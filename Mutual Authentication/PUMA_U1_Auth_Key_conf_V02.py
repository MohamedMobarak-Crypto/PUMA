"""Pi 1: automatic local user/avatar creation and PUMA authentication.

AuthReq signs
both the first avatar's IdAv and the intended second avatar's IdAv. AuthRes
contains the second avatar's HMAC key-confirmation tag; Pi 1 verifies it and
returns its own tag in AuthConf. HKDF-SHA-256 derives distinct session and
confirmation keys from each ML-KEM shared secret.

Run this file first, then run the matching Pi 2 file.
No biometric mechanism is used in this local benchmark.
"""
import argparse
import base64
import hashlib
import hmac
import json
import socket
import statistics
import struct
import time

import oqs

SIG = "ML-DSA-44"  # NIST category 2: authority, registration, and avatar signatures.
KEM = "ML-KEM-512"  # NIST category 1: per-session key encapsulation.
VERSION = "PUMA-auto-stats-v2"
PORT = 5300
WINDOW_SECONDS = 30  # Timestamp freshness interval; both device clocks must agree.
PK_SIZE = 1312  # ML-DSA-44 public-key length used to extract pk^a from IdAv.
clock = time.perf_counter_ns  # Duration timer; timestamps use time.time_ns().


# Convert binary data to canonical Base64 for the JSON transport.
def encode(data):
    """Represent bytes in JSON without changing their contents."""
    return base64.b64encode(data).decode("ascii")


# Decode a canonical Base64 field and reject invalid or alternative encodings.
def decode(text):
    """Recover bytes, rejecting alternative encodings of the same key."""
    data = base64.b64decode(text, validate=True)
    if encode(data) != text:
        raise ValueError("Noncanonical Base64")
    return data


# Prefix each binary field with its length so signed tuples are unambiguous.
def pack(*fields):
    """Encode signed tuples in a fixed, unambiguous order."""
    return b"".join(struct.pack("!I", len(field)) + field for field in fields)


# Encode a nanosecond timestamp as an eight-byte unsigned integer.
def timestamp_bytes(ts):
    """Encode a timestamp identically on both Pis."""
    if type(ts) is not int or not 0 <= ts < 2**64:
        raise ValueError("Invalid timestamp")
    return struct.pack("!Q", ts)


# Serialize the AuthReq signature message exactly as in Section V-D.
def request_bytes(req):
    """AuthReq signs the first IdAv, intended second IdAv, ek, and ts1."""
    return pack(decode(req["idav"]), decode(req["peer_idav"]),
                decode(req["ek"]), timestamp_bytes(req["ts1"]))


# Serialize the AuthRes signature message exactly as in Section V-D.
def response_bytes(req, res):
    """AuthRes signs both avatar IDs, ciphertext, and ts2, as in the paper."""
    # Signed tuple: (IdAv_{k,ell}, IdAv_{i,j}, c_{k,ell}, ts_2).
    # Keep the original req argument for call compatibility; it is not signed here.
    return pack(decode(res["idav"]), decode(res["peer_idav"]),
                decode(res["c"]), timestamp_bytes(res["ts2"]))


# Combine both signed messages and signatures for key derivation and confirmation.
def transcript_bytes(req, res):
    """Bind both signed messages into the key schedule and confirmation tags."""
    return pack(request_bytes(req), decode(req["sigma"]),
                response_bytes(req, res), decode(res["sigma"]))


# Perform HKDF-SHA-256 extraction and expansion to the requested byte length.
def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 HKDF-SHA-256, using Python's standard-library HMAC."""
    hash_len = hashlib.sha256().digest_size
    if not 0 <= length <= 255 * hash_len:
        raise ValueError("Invalid HKDF output length")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    for counter in range(1, (length + hash_len - 1) // hash_len + 1):
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output.extend(previous)
    return bytes(output[:length])


# Derive separate 32-byte session and confirmation keys from the shared secret.
def derive_session_and_confirmation_keys(shared_secret, transcript):
    """Use HKDF to derive separate 32-byte session and confirmation keys."""
    transcript_hash = hashlib.sha256(transcript).digest()
    salt = hashlib.sha256(b"PUMA-HKDF-SHA256-salt-v1" + transcript_hash).digest()
    # K^sess = HKDF(K, info_sess); info_sess includes a label and transcript hash.
    session_key = hkdf_sha256(
        shared_secret, salt, b"PUMA-session-key-v1" + transcript_hash, 32
    )
    # K^conf = HKDF(K, info_conf); a distinct purpose label separates the keys.
    confirmation_key = hkdf_sha256(
        shared_secret, salt, b"PUMA-key-confirmation-key-v1" + transcript_hash, 32
    )
    return session_key, confirmation_key


# Compute an HMAC tag bound to this transcript and the sender's direction.
def confirmation_tag(confirmation_key, direction, transcript):
    """Compute a direction-specific HMAC over the authenticated transcript."""
    # tau = HMAC(K^conf, info_conf); this context includes the direction and H(T).
    message = pack(b"PUMA-key-confirmation-v1", direction,
                   hashlib.sha256(transcript).digest())
    return hmac.new(confirmation_key, message, hashlib.sha256).digest()


# Generate a local key pair using the selected ML-DSA parameter set.
def keygen():
    """Generate a local ML-DSA public/secret key pair."""
    with oqs.Signature(SIG) as signer:
        return signer.generate_keypair(), signer.export_secret_key()


# Sign a binary protocol message with its owner's ML-DSA secret key.
def sign(secret, message):
    """Sign bytes using a local secret key."""
    with oqs.Signature(SIG, secret) as signer:
        return signer.sign(message)


# Verify an ML-DSA signature and stop processing if it is invalid.
def verify(public, message, signature):
    """Stop on any invalid ML-DSA signature."""
    with oqs.Signature(SIG) as verifier:
        if not verifier.verify(message, signature, public):
            raise ValueError("ML-DSA signature verification failed")


# Read exactly the requested number of bytes despite TCP fragmentation.
def receive_exactly(conn, size):
    """Receive a full TCP field even when it arrives in several pieces."""
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("The other Pi closed the connection")
        data.extend(chunk)
    return bytes(data)


# Send one JSON message with a four-byte length prefix.
def send(conn, message):
    """Send one JSON object with a four-byte length prefix."""
    data = json.dumps(message, separators=(",", ":")).encode()
    if len(data) > 1_000_000:
        raise ValueError("Message too large")
    conn.sendall(struct.pack("!I", len(data)) + data)


# Read and validate one length-prefixed JSON message.
def receive(conn):
    """Read one bounded JSON object."""
    size = struct.unpack("!I", receive_exactly(conn, 4))[0]
    if not 0 < size <= 1_000_000:
        raise ValueError("Invalid frame size")
    message = json.loads(receive_exactly(conn, size))
    if not isinstance(message, dict):
        raise ValueError("Expected JSON object")
    return message


# Configure connection timeouts and disable Nagle buffering for the benchmark.
def configure(conn):
    """Set a connection timeout and avoid Nagle buffering in the experiment."""
    conn.settimeout(60)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


# Check that liboqs enables the signature and KEM parameter sets selected above.
def check_algorithms():
    """Check that the existing liboqs installation supports both algorithms."""
    if SIG not in oqs.get_enabled_sig_mechanisms() or KEM not in oqs.get_enabled_kem_mechanisms():
        raise ValueError(f"Enable {SIG} and {KEM} in liboqs")


# Reject a timestamp outside the configured freshness window.
def fresh(ts):
    """Check timestamp freshness; both Pi clocks should be synchronized."""
    timestamp_bytes(ts)
    if abs(time.time_ns() - ts) > WINDOW_SECONDS * 1e9:
        raise ValueError("Timestamp outside 30-second window; check both Pi clocks")


# Verify the ACA certificate, then extract the certified avatar public key.
def verify_avatar(aca_pk, message):
    """Verify an ACA certificate and extract the certified avatar public key."""
    identity = decode(message["idav"])
    if len(identity) <= PK_SIZE:
        raise ValueError("Invalid avatar identity")
    verify(aca_pk, identity, decode(message["ac"]))
    return identity[:PK_SIZE]


# Emulate registration and avatar certification for Pi 1 before timing starts.
def create_first_avatar(ra_sk, ra_pk, aca_sk, aca_pk):
    """Simulate registration and creation of Pi 1's local avatar."""
    reg_pk, reg_sk = keygen()
    rc = sign(ra_sk, reg_pk)  # RC = ML-DSA.Sign(sk_RA, pk^reg).
    verify(ra_pk, reg_pk, rc)

    avatar_pk, avatar_sk = keygen()
    idav = avatar_pk + b"D_i,j"  # IdAv_{i,j} = pk^a_{i,j} || D_{i,j}.
    proof = sign(reg_sk, idav)  # sigma^req_{i,j} = Sign(sk^reg_{i,j}, IdAv_{i,j}).
    verify(reg_pk, idav, proof)
    ac = sign(aca_sk, idav)  # AC = ML-DSA.Sign(sk_ACA, IdAv).
    verify(aca_pk, idav, ac)
    del reg_sk
    return dict(idav=encode(idav), ac=encode(ac), sk=avatar_sk)


# Emulate MSP/ACA processing for Pi 2's registration and avatar certification.
def create_second_avatar(conn, ra_sk, aca_pk, aca_sk):
    """Register Pi 2's user and issue an avatar certificate for its avatar."""
    registration = receive(conn)
    if registration.get("uid") != "user_k":
        raise ValueError("Unexpected Pi 2 user identifier")
    reg_pk = decode(registration["pk_reg"])
    if len(reg_pk) != PK_SIZE:
        raise ValueError("Invalid registration public key")
    rc = sign(ra_sk, reg_pk)  # RC = ML-DSA.Sign(sk_RA, pk^reg).
    send(conn, {"rc": encode(rc)})

    avatar_request = receive(conn)
    idav = decode(avatar_request["idav"])
    if len(idav) <= PK_SIZE:
        raise ValueError("Invalid Pi 2 avatar identity")
    verify(reg_pk, idav, decode(avatar_request["proof"]))
    ac = sign(aca_sk, idav)  # AC = ML-DSA.Sign(sk_ACA, IdAv).
    verify(aca_pk, idav, ac)
    send(conn, {"ac": encode(ac)})
    if receive(conn).get("ready") is not True:
        raise ValueError("Pi 2 did not complete local avatar setup")
    return dict(idav=encode(idav), ac=encode(ac))


# Compute population timing statistics for one measured benchmark stage.
def summarize(stage, values):
    """Calculate mean, variance, average, median, standard deviation, min, max."""
    mean = statistics.fmean(values)
    return dict(
        stage=stage,
        mean=mean,
        variance=statistics.pvariance(values),
        average=mean,
        median=statistics.median(values),
        std_dev=statistics.pstdev(values),
        min=min(values),
        max=max(values),
    )


# Print the timing statistics and explain their measurement scope.
def print_results(summary):
    """Print timing summary with all requested statistics."""
    print("\nMutual-authentication benchmark (milliseconds)")
    print(f"{'Stage':48s} {'Mean':>12s} {'Variance':>12s} {'Average':>12s} "
          f"{'Median':>12s} {'Std dev':>12s} {'Min':>12s} {'Max':>12s}")
    print("-" * 142)
    for row in summary["rows"]:
        print(f"{row['stage']:48s} {row['mean']:12.6f} {row['variance']:12.6f} "
              f"{row['average']:12.6f} {row['median']:12.6f} "
              f"{row['std_dev']:12.6f} {row['min']:12.6f} {row['max']:12.6f}")
    print(f"\nTotal measured mutual-authentication time for {summary['runs']} iterations: "
          f"{summary['total_ms']:.6f} ms")
    print(f"Average mutual-authentication time: {summary['rows'][-1]['mean']:.6f} ms")
    print("All certificates/signatures and both key-confirmation tags verified.")
    print("Total includes the authentication exchange, Pi 2's confirmation check, and its timing reply.")


# Execute U1's AuthReq/AuthRes/AuthConf exchange and collect per-stage timings.
def run_authentication(conn, aca_pk, first_avatar, second_avatar, runs):
    """Run AuthReq, AuthRes, and bilateral key confirmation for each session."""
    samples = {
        "Pi 1 AuthReq generation": [],
        "Pi 2 AuthReq verification": [],
        "Pi 2 AuthRes creation": [],
        "Pi 1 AuthRes verification": [],
        "Pi 1 decaps, HKDF, KC, AuthConf": [],
        "Pi 2 AuthConf verification": [],
        "End-to-end exchange": [],
    }
    total_samples = []

    # Setup is excluded; each timed iteration uses a new ML-KEM key pair.
    for _ in range(runs):
        total_start = clock()
        start_create = clock()
        with oqs.KeyEncapsulation(KEM) as kem:
            # (ek^e_{i,j}, dk^e_{i,j}) = ML-KEM.KeyGen(); dk remains in kem.
            ek = kem.generate_keypair()
            # AuthReq_{i,j} = (AC_{i,j}, IdAv_{i,j}, IdAv_{k,ell},
            #                  ek^e_{i,j}, ts_1, sigma^auth_{i,j}).
            # Build public fields here; the authentication signature is added below.
            req = dict(idav=first_avatar["idav"],
                       peer_idav=second_avatar["idav"],
                       ac=first_avatar["ac"], ek=encode(ek), ts1=time.time_ns())
            # sigma^auth_{i,j} = Sign(sk^a_{i,j},
            #                        (IdAv_{i,j}, IdAv_{k,ell}, ek^e_{i,j}, ts_1)).
            req["sigma"] = encode(sign(first_avatar["sk"], request_bytes(req)))
            create_req_ms = (clock() - start_create) / 1e6
            send(conn, req)

            # Receive AuthRes_{k,ell}, including sigma^res_{k,ell} and tau_{k,ell}.
            res = receive(conn)
            start_verify = clock()
            fresh(res["ts2"])
            if decode(res["idav"]) != decode(second_avatar["idav"]):
                raise ValueError("AuthRes came from an unexpected avatar")
            if decode(res["peer_idav"]) != decode(first_avatar["idav"]):
                raise ValueError("AuthRes is addressed to an unexpected avatar")
            second_pk = verify_avatar(aca_pk, res)
            # Verify sigma^res_{k,ell} over (IdAv_{k,ell}, IdAv_{i,j}, c_{k,ell}, ts_2).
            verify(second_pk, response_bytes(req, res), decode(res["sigma"]))
            verify_res_ms = (clock() - start_verify) / 1e6

            start_confirmation = clock()
            # K = ML-KEM.Decaps(dk^e_{i,j}, c_{k,ell}).
            shared_secret = kem.decap_secret(decode(res["c"]))
            transcript = transcript_bytes(req, res)
            session_key, confirmation_key = derive_session_and_confirmation_keys(
                shared_secret, transcript
            )
            # Verify the responder tag tau_{k,ell} with the local K^conf_{i,j}.
            expected_tag = confirmation_tag(
                confirmation_key, b"second-avatar-to-first-avatar", transcript
            )
            if not hmac.compare_digest(decode(res["kc"]), expected_tag):
                raise ValueError("Second avatar's key-confirmation tag is invalid")

            # AuthConf proves to the second avatar that Pi 1 derived the key.
            # tau_{i,j} = HMAC(K^conf_{i,j}, info_conf for the initiator direction).
            auth_conf_tag = confirmation_tag(
                confirmation_key, b"first-avatar-to-second-avatar", transcript
            )
            send(conn, {"type": "AuthConf", "kc": encode(auth_conf_tag)})  # AuthConf_{i,j} = tau_{i,j}.
            key_confirmation_ms = (clock() - start_confirmation) / 1e6
            # This benchmark ends the session here; del removes Python bindings.
            del session_key, confirmation_key, shared_secret

        # Pi 2 sends these benchmark measurements only after verifying AuthConf.
        pi2_metrics = receive(conn)
        pi2_verify_ms = float(pi2_metrics["verify_ms"])
        pi2_create_ms = float(pi2_metrics["create_ms"])
        pi2_confirmation_ms = float(pi2_metrics["confirmation_ms"])
        if min(pi2_verify_ms, pi2_create_ms, pi2_confirmation_ms) < 0:
            raise ValueError("Pi 2 returned a negative timing measurement")
        # End the iteration timer after U2 confirms the key and returns timing data.
        total_ms = (clock() - total_start) / 1e6

        samples["Pi 1 AuthReq generation"].append(create_req_ms)
        samples["Pi 2 AuthReq verification"].append(pi2_verify_ms)
        samples["Pi 2 AuthRes creation"].append(pi2_create_ms)
        samples["Pi 1 AuthRes verification"].append(verify_res_ms)
        samples["Pi 1 decaps, HKDF, KC, AuthConf"].append(key_confirmation_ms)
        samples["Pi 2 AuthConf verification"].append(pi2_confirmation_ms)
        samples["End-to-end exchange"].append(total_ms)
        total_samples.append(total_ms)

    if receive(conn).get("completed") != runs:
        raise ValueError("Pi 2 did not complete the requested number of sessions")

    summary = dict(
        kind="statistics",
        runs=runs,
        rows=[summarize(stage, values) for stage, values in samples.items()],
        total_ms=sum(total_samples),
    )
    send(conn, summary)
    if receive(conn).get("statistics_received") is not True:
        raise ValueError("Pi 2 did not acknowledge the timing summary")
    print_results(summary)


# Parse command-line options, perform setup, and start this device's protocol role.
def main():
    """Create local authorities/avatar, then serve one Pi 2 connection."""
    parser = argparse.ArgumentParser(
        description="PUMA Pi 1: automatic setup and first-avatar processing"
    )
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--runs", type=int, default=10000)
    args = parser.parse_args()
    if not 1 <= args.runs <= 10_000_000:
        parser.error("--runs must be between 1 and 10000000")
    check_algorithms()

    ra_pk, ra_sk = keygen()
    aca_pk, aca_sk = keygen()
    first_avatar = create_first_avatar(ra_sk, ra_pk, aca_sk, aca_pk)
    print("Local Pi 1 avatar created. Waiting for Pi 2 ...", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.bind, args.port))
        server.listen(1)
        conn, address = server.accept()
        with conn:
            configure(conn)
            send(conn, dict(version=VERSION, signature=SIG, kem=KEM,
                            ra_pk=encode(ra_pk), aca_pk=encode(aca_pk),
                            runs=args.runs))
            second_avatar = create_second_avatar(conn, ra_sk, aca_pk, aca_sk)
            del ra_sk, aca_sk
            print(f"Pi 2 connected from {address}; avatars are certified.", flush=True)
            run_authentication(conn, aca_pk, first_avatar, second_avatar, args.runs)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as exc:
        raise SystemExit(f"PUMA error: {exc}")
