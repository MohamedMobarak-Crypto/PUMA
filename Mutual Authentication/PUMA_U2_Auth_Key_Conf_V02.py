"""Pi 2: automatic local user/avatar creation and PUMA authentication.

AuthReq carries the first avatar's IdAv and the intended second avatar's IdAv.
The second avatar places its key-confirmation tag in AuthRes; the first avatar
returns its tag in AuthConf. Each tag is an HMAC under an HKDF-derived
confirmation key. 

Start PUMA_U1_Key_conf_V02.py on Pi 1, then run this file on Pi 2.
Pi 1 controls --runs and sends the iteration count during untimed setup.
For this trusted-lab experiment, authority public keys received directly over
TCP are trusted. No authority secret key is received. All user/avatar secrets
are generated locally and kept in RAM. No biometric mechanism is implemented.
Registration and creation are not timed. The replay cache exists only for this
connection/process lifetime.
"""
import argparse
import base64
import hashlib
import hmac
import json
import socket
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
    """Verify the ACA certificate and extract the certified avatar public key."""
    identity = decode(message["idav"])
    if len(identity) <= PK_SIZE:
        raise ValueError("Invalid avatar identity")
    verify(aca_pk, identity, decode(message["ac"]))
    return identity[:PK_SIZE]


# Compute an HMAC tag bound to this transcript and the sender's direction.
def confirmation_tag(confirmation_key, direction, transcript):
    """Compute a direction-specific HMAC over the authenticated transcript."""
    # tau = HMAC(K^conf, info_conf); this context includes the direction and H(T).
    message = pack(b"PUMA-key-confirmation-v1", direction,
                   hashlib.sha256(transcript).digest())
    return hmac.new(confirmation_key, message, hashlib.sha256).digest()


# Print the timing statistics and explain their measurement scope.
def print_results(summary):
    """Print the same complete statistics table on both Pis."""
    print("\nMutual-authentication benchmark (milliseconds)")
    print(f"{'Stage':36s} {'Mean':>12s} {'Variance':>12s} {'Average':>12s} "
          f"{'Median':>12s} {'Std dev':>12s} {'Min':>12s} {'Max':>12s}")
    print("-" * 130)
    for row in summary["rows"]:
        # Preserve compatibility with summaries that send population std dev
        # but omit variance; variance is std_dev squared (ddof=0).
        variance = row["variance"] if "variance" in row else row["std_dev"] ** 2
        print(f"{row['stage']:36s} {row['mean']:12.6f} {variance:12.6f} "
              f"{row['average']:12.6f} {row['median']:12.6f} "
              f"{row['std_dev']:12.6f} {row['min']:12.6f} {row['max']:12.6f}")
    print(f"\nTotal measured mutual-authentication time for {summary['runs']} iterations: "
          f"{summary['total_ms']:.6f} ms")
    print(f"Average mutual-authentication time: {summary['rows'][-1]['mean']:.6f} ms")
    print("All certificates/signatures and both 32-byte key-confirmation tags verified.")


PI1_IP = "192.168.2.2"


# Obtain authority public keys and create Pi 2's certified avatar before timing.
def setup(conn):
    """Receive public parameters, register user_k and create Avatar A_k,ell."""
    parameters = receive(conn)
    if (parameters["version"], parameters["signature"], parameters["kem"]) != (VERSION, SIG, KEM):
        raise ValueError("The Pis are using different protocol/algorithm settings")
    ra_pk, aca_pk = decode(parameters["ra_pk"]), decode(parameters["aca_pk"])
    if len(ra_pk) != PK_SIZE or len(aca_pk) != PK_SIZE:
        raise ValueError("Invalid authority public keys")
    runs = parameters["runs"]
    if type(runs) is not int or not 1 <= runs <= 10_000_000:
        raise ValueError("Invalid iteration count")
    print("Received MSP and ACA public keys directly from Pi 1.", flush=True)

    reg_pk, reg_sk = keygen()
    send(conn, dict(uid="user_k", pk_reg=encode(reg_pk)))
    rc = decode(receive(conn)["rc"])
    # Check the MSP-issued registration certificate RC_{k,ell} on pk^reg_{k,ell}.
    verify(ra_pk, reg_pk, rc)

    avatar_pk, avatar_sk = keygen()
    idav = avatar_pk + b"D_k,ell"  # IdAv_{k,ell} = pk^a_{k,ell} || D_{k,ell}.
    proof = sign(reg_sk, idav)  # sigma^req_{k,ell} = Sign(sk^reg_{k,ell}, IdAv_{k,ell}).
    send(conn, dict(idav=encode(idav), proof=encode(proof)))
    ac = decode(receive(conn)["ac"])
    # Check the ACA-issued avatar certificate AC_{k,ell} on IdAv_{k,ell}.
    verify(aca_pk, idav, ac)
    del reg_sk
    avatar = dict(idav=encode(idav), ac=encode(ac), sk=avatar_sk)
    send(conn, {"ready": True})
    print("Local avatar created; RC and AC verified. Setup is not timed.", flush=True)
    return aca_pk, avatar, runs


# Execute U2's request checks, response creation, and AuthConf verification.
def respond(conn, aca_pk, avatar, runs):
    """Verify each AuthReq, encapsulate, send AuthRes, and verify AuthConf."""
    seen = {}
    for _ in range(runs):
        # Receive AuthReq_{i,j} and verify its timestamp, recipient, certificate,
        # and signature over (IdAv_{i,j}, IdAv_{k,ell}, ek^e_{i,j}, ts_1).
        req = receive(conn)
        start_verify = clock()
        fresh(req["ts1"])
        if decode(req["peer_idav"]) != decode(avatar["idav"]):
            raise ValueError("AuthReq is addressed to a different avatar")
        pk = verify_avatar(aca_pk, req)
        payload = request_bytes(req)
        verify(pk, payload, decode(req["sigma"]))

        # Reject repeated signed requests, even if the signature bytes differ.
        now = time.time_ns()
        while seen and next(iter(seen.values())) < now:
            del seen[next(iter(seen))]
        token = hashlib.sha256(payload).digest()
        if token in seen:
            raise ValueError("Replayed authentication request")
        seen[token] = now + int(2 * WINDOW_SECONDS * 1e9)
        verify_ms = (clock() - start_verify) / 1e6

        start_create = clock()
        with oqs.KeyEncapsulation(KEM) as kem:
            # Paper: (K, c_{k,ell}) = ML-KEM.Encaps(ek^e_{i,j}).
            # liboqs returns these as (ciphertext, shared_secret), i.e. (c, K).
            ciphertext, shared_secret = kem.encap_secret(decode(req["ek"]))
        # AuthRes_{k,ell} = (AC_{k,ell}, tau_{k,ell}, IdAv_{k,ell},
        #                    IdAv_{i,j}, c_{k,ell}, ts_2, sigma^res_{k,ell}).
        # Build public fields here; sigma^res and tau are added below before sending.
        res = dict(idav=avatar["idav"], peer_idav=req["idav"], ac=avatar["ac"],
                   c=encode(ciphertext), ts2=time.time_ns())
        # sigma^res_{k,ell} = Sign(sk^a_{k,ell},
        #                        (IdAv_{k,ell}, IdAv_{i,j}, c_{k,ell}, ts_2)).
        res["sigma"] = encode(sign(avatar["sk"], response_bytes(req, res)))
        transcript = transcript_bytes(req, res)
        session_key, confirmation_key = derive_session_and_confirmation_keys(
            shared_secret, transcript
        )
        # Sign the AuthRes fields first; its HMAC tag is then computed over the
        # request and this signed response, excluding the tag itself.
        # tau_{k,ell} = HMAC(K^conf_{k,ell}, info_conf for the responder direction).
        res["kc"] = encode(confirmation_tag(
            confirmation_key, b"second-avatar-to-first-avatar", transcript
        ))
        create_ms = (clock() - start_create) / 1e6
        send(conn, res)

        # AuthConf is the first avatar's key-confirmation message.
        auth_conf = receive(conn)  # AuthConf_{i,j} = tau_{i,j}.
        start_confirmation = clock()
        if auth_conf.get("type") != "AuthConf":
            raise ValueError("Expected the first avatar's AuthConf message")
        # Check the initiator tag tau_{i,j} using the local K^conf_{k,ell}.
        expected_tag = confirmation_tag(
            confirmation_key, b"first-avatar-to-second-avatar", transcript
        )
        if not hmac.compare_digest(decode(auth_conf["kc"]), expected_tag):
            raise ValueError("First avatar's key-confirmation tag is invalid")
        confirmation_ms = (clock() - start_confirmation) / 1e6
        # This benchmark ends the session here; del removes Python bindings.
        del session_key, confirmation_key, shared_secret

        # Timing data is benchmark instrumentation, not an authentication message.
        send(conn, dict(verify_ms=verify_ms, create_ms=create_ms,
                        confirmation_ms=confirmation_ms))
    send(conn, {"completed": runs})
    print(f"Completed {runs} mutual-authentication sessions.", flush=True)
    print("All request certificates/signatures verified; every session key confirmed.")
    # The summary is computed only after all sessions, outside every timer.
    # Allow extra time for median/std-dev calculations for millions of samples.
    conn.settimeout(300)
    summary = receive(conn)
    if summary.get("kind") != "statistics" or summary.get("runs") != runs:
        raise ValueError("Invalid statistics report from Pi 1")
    send(conn, {"statistics_received": True})
    print_results(summary)


# Parse command-line options, perform setup, and start this device's protocol role.
def main():
    """Connect to Pi 1, complete automatic setup, then respond."""
    parser = argparse.ArgumentParser(
        description="PUMA Pi 2: automatic setup and second-avatar processing"
    )
    parser.add_argument("--peer", default=PI1_IP)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    check_algorithms()
    print(f"Connecting to Pi 1 at {args.peer}:{args.port} ...", flush=True)
    with socket.create_connection((args.peer, args.port), timeout=10) as conn:
        configure(conn)
        aca_pk, avatar, runs = setup(conn)
        print(f"Waiting for {runs} authentication requests ...", flush=True)
        respond(conn, aca_pk, avatar, runs)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as exc:
        raise SystemExit(f"PUMA error: {exc}")
