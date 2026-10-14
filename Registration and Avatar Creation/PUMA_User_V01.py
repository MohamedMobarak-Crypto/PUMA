"""PUMA registration/avatar-creation benchmark; standalone file.
User role: run PUMA_User_V03.py on the Pi after starting the Mac authority.
Python wrapper over liboqs C, ML-DSA-44. Same signature and TCP framing helpers
as PUMA_stats_pi1/pi2. No mutual-authentication loop in this separate experiment.

One persistent TCP connection; authority keygen and public-key bootstrap excluded.
All elapsed intervals use ONLY the Pi's perf_counter_ns; no clock sync needed.
Registration: before local registration keygen -> received RC decoded.
Creation: before local avatar keygen -> received AC decoded.
Pi-side RC/AC verification and local storage occur after each timer stops.
ACA verification of RC and creation proof remains inside creation timing.
Fresh keys each trial; same simulated UID and descriptor; no warm-up.
RA/ACA keys last for the run. Per-trial authority records are reset outside timers
so repeated enrollment trials do not accumulate gigabytes of evidence in RAM.
This measures independent enrollment latency, not growth of a user database.

MSPsigns raw registration pk (RC); ACA verifies RC and registration-key signature
on IdAv = avatar pk || descriptor, checks single use, signs IdAv (AC), stores proof.
Authority secrets remain on Mac; user secrets remain on Pi. Trusted-lab public-key
bootstrap, simulated identity vetting, random avatar keys instead of biometrics.
Both authority roles on Mac are a simulation, not actual split-trust isolation.
All state is in RAM; deleting Python references does not guarantee secure erasure.
"""
import argparse
from array import array
import base64
import json
import math
import socket
import statistics
import struct
import time
import oqs

SIG = "ML-DSA-44"  # NIST category 2: registration and avatar certificates/proofs.
PK_SIZE = 1312  # ML-DSA-44 public-key length in bytes.
VERSION = "PUMA-enrollment-stats-v2"
PORT = 5500
MAC_IP = "192.168.2.1"
clock = time.perf_counter_ns  # Local monotonic timer; only Pi durations are reported.

# Convert binary protocol fields to canonical Base64 for JSON transmission.
def encode(data):
    """Represent bytes in JSON without changing their contents."""
    return base64.b64encode(data).decode("ascii")

# Decode Base64 fields and reject invalid or noncanonical representations.
def decode(text):
    """Recover bytes, rejecting alternative encodings of the same key."""
    data = base64.b64decode(text, validate=True)
    if encode(data) != text:
        raise ValueError("Noncanonical Base64")
    return data

# Generate a local ML-DSA public/secret key pair with the selected parameters.
def keygen():
    """Generate a local ML-DSA public/secret key pair."""
    with oqs.Signature(SIG) as signer:
        return signer.generate_keypair(), signer.export_secret_key()

# Sign the given binary message with a local ML-DSA secret key.
def sign(secret, message):
    """Sign bytes using a local secret key."""
    with oqs.Signature(SIG, secret) as signer:
        return signer.sign(message)

# Verify an ML-DSA signature and reject invalid certificates or authorization proofs.
def verify(public, message, signature):
    """Stop on any invalid ML-DSA signature."""
    with oqs.Signature(SIG) as verifier:
        if not verifier.verify(message, signature, public):
            raise ValueError("ML-DSA signature verification failed")

# Read the required bytes even when TCP splits them across packets.
def receive_exactly(conn, size):
    """Receive a full TCP field even when it arrives in several pieces."""
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("The other Pi closed the connection")
        data.extend(chunk)
    return bytes(data)

# Serialize and transmit one JSON message with a four-byte length prefix.
def send(conn, message):
    """Send one JSON object with a four-byte length prefix."""
    data = json.dumps(message, separators=(",", ":")).encode()
    if len(data) > 1_000_000:
        raise ValueError("Message too large")
    conn.sendall(struct.pack("!I", len(data)) + data)

# Read and validate one bounded, length-prefixed JSON message.
def receive(conn):
    """Read one bounded JSON object."""
    size = struct.unpack("!I", receive_exactly(conn, 4))[0]
    if not 0 < size <= 1_000_000:
        raise ValueError("Invalid frame size")
    message = json.loads(receive_exactly(conn, size))
    if not isinstance(message, dict):
        raise ValueError("Expected JSON object")
    return message

# Set the timeout and disable Nagle buffering for latency measurements.
def configure(conn):
    """Set a connection timeout and avoid Nagle buffering in the experiment."""
    conn.settimeout(60)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

# Shared ACA helper, retained from the original file but unused on the Pi.
# Check RC/proof, enforce single use, issue AC, and retain authorization evidence.
def certify_avatar(ra_pk, aca_sk, reg_pk, rc, idav, proof, used, table):
    """ACA checks RC/Areq, enforces one-use credentials, and issues AC."""
    # ML-DSA.Verify(pk_RA, pk^reg_{i,j}, RC_{i,j}) = 1.
    verify(ra_pk, reg_pk, rc)
    # ML-DSA.Verify(pk^reg_{i,j}, IdAv_{i,j}, sigma^req_{i,j}) = 1.
    verify(reg_pk, idav, proof)
    if reg_pk in used:
        raise ValueError("Registration credential already used")
    if len(reg_pk) != PK_SIZE or len(idav) <= PK_SIZE or idav in table:
        raise ValueError("Invalid or duplicate avatar identity")
    ac = sign(aca_sk, idav)  # AC_{i,j} = ML-DSA.Sign(sk_ACA, IdAv_{i,j}).
    used.add(reg_pk)  # Consume pk^reg_{i,j}: S <- S union {pk^reg_{i,j}}.
    # Record IdAv_{i,j} -> (pk^reg_{i,j}, sigma^req_{i,j}); also retain AC.
    table[idav] = dict(pk_reg=reg_pk, proof=proof, ac=ac)
    return ac


# Require the next message to belong to the expected phase and benchmark trial.
def expect(conn, kind, iteration=None):
    """Check the next frame belongs to the expected phase and trial."""
    msg = receive(conn)
    if msg.get("type") != kind:
        raise ValueError(f"Expected {kind}, received {msg.get('type')}")
    if iteration is not None and msg.get("iteration") != iteration:
        raise ValueError("Unexpected iteration")
    return msg


# Print identical phase statistics and measurement boundaries on the Mac and Pi.
def print_results(summary):
    """Print identical statistics on the Mac and Pi, after all trials."""
    print("\nRegistration and avatar-creation benchmark (milliseconds)")
    print(f"{'Stage':28s} {'Mean':>12s} {'Median':>12s} {'Average':>12s} "
          f"{'Std dev':>12s} {'Min':>12s} {'Max':>12s}")
    print("-" * 106)
    for row in summary["rows"]:
        print(f"{row['stage']:28s} " + " ".join(
            f"{row[field]:12.6f}" for field in
            ("mean", "median", "average", "std_dev", "min", "max")))
    for row in summary["rows"]:
        print(f"\nTotal measured {row['stage'].lower()} time for {summary['runs']} "
              f"iterations: {row['total_ms']:.6f} ms")
        print(f"Average: {row['mean']:.6f} ms")
    print("\nMean = arithmetic average; std dev = population standard deviation (ddof=0).")
    print("All issued certificates verified on the Pi.")
    print("Timers stop after certificate reception/decoding; Pi-side verification/storage excluded.")


# Check that native liboqs supports the selected ML-DSA parameter set.
def check_algorithm():
    """Fail early if the installed C library does not enable the selected ML-DSA."""
    if SIG not in oqs.get_enabled_sig_mechanisms():
        raise ValueError(f"{SIG} is not enabled in liboqs")

# Change this or pass --runs. Only the Pi controls the number of trials.
RUNS = 100000


# Compute timing statistics after all enrollment trials have completed.
def summarize(samples, runs):
    """Compute statistics from every recorded duration after the benchmark."""
    rows = []
    for name, values in zip(("Registration", "Avatar creation"), samples):
        if len(values) != runs:
            raise ValueError("Incomplete samples")
        mean = statistics.fmean(values)
        rows.append(dict(stage=name, mean=mean, average=mean,
                         median=statistics.median(values),
                         std_dev=statistics.pstdev(values),
                         min=min(values), max=max(values), total_ms=math.fsum(values)))
    return dict(runs=runs, rows=rows)


# Run both enrollment phases on the Pi with the original phase timer boundaries.
def benchmark(conn, runs, uid, descriptor):
    """Enroll fresh credentials and avatars, recording both end-to-end intervals."""
    params = expect(conn, "parameters")
    if params.get("version") != VERSION or params.get("signature") != SIG:
        raise ValueError("Protocol/algorithm mismatch; use matching files")
    ra_pk, aca_pk = decode(params["ra_pk"]), decode(params["aca_pk"])
    if len(ra_pk) != PK_SIZE or len(aca_pk) != PK_SIZE:
        raise ValueError("Invalid authority public key")
    # Start/reset/ready/report frames coordinate trials; they are not paper payloads.
    send(conn, dict(type="start", runs=runs))
    samples = (array("d"), array("d"))
    print(f"Running {runs} registration and avatar-creation trials; no warm-up.", flush=True)
    for i in range(runs):
        # Prepare independent trial state BEFORE either phase timer starts.
        send(conn, dict(type="reset", iteration=i))
        expect(conn, "ready", i)

        registration_start = clock()                 # REGISTRATION TIMER START
        reg_pk, reg_sk = keygen()  # (pk^reg_{i,j}, sk^reg_{i,j}) = ML-DSA.KeyGen(pp_DSA).
        # Registration request for one credential: (UID_i, pk^reg_{i,j}).
        send(conn, dict(type="register", iteration=i, uid=uid, pk_reg=encode(reg_pk)))
        response = expect(conn, "registered", i)
        rc = decode(response["rc"])  # RC_{i,j}: the MSP signature on pk^reg_{i,j}.
        registration_end = clock()                   # REGISTRATION TIMER STOP

        # Extra client-side check and storage, outside BOTH phase timers.
        # ML-DSA.Verify(pk_RA, pk^reg_{i,j}, RC_{i,j}) = 1; outside both timers.
        verify(ra_pk, reg_pk, rc)
        credential = dict(pk=reg_pk, sk=reg_sk, rc=rc)  # Local (pk^reg, sk^reg, RC).

        creation_start = clock()                     # CREATION TIMER START
        # Random key generation is benchmarked; biometric regeneration is not simulated.
        avatar_pk, avatar_sk = keygen()  # (pk^a_{i,j}, sk^a_{i,j}) = ML-DSA.KeyGen(pp_DSA).
        idav = avatar_pk + descriptor.encode("utf-8")  # IdAv_{i,j} = pk^a_{i,j} || D_{i,j}.
        proof = sign(credential["sk"], idav)  # sigma^req_{i,j} = Sign(sk^reg_{i,j}, IdAv_{i,j}).
        # AReq_{i,j} = (pk^reg_{i,j}, RC_{i,j}, IdAv_{i,j}, sigma^req_{i,j}).
        # "proof" is sigma^req; type/iteration fields are benchmark metadata.
        send(conn, dict(type="create", iteration=i, pk_reg=encode(credential["pk"]),
                        rc=encode(credential["rc"]), idav=encode(idav), proof=encode(proof)))
        response = expect(conn, "created", i)
        ac = decode(response["ac"])  # AC_{i,j}: the ACA signature on IdAv_{i,j}.
        creation_end = clock()                       # CREATION TIMER STOP

        # Extra client-side check, storage and cleanup, outside timing.
        # ML-DSA.Verify(pk_ACA, IdAv_{i,j}, AC_{i,j}) = 1; outside the phase timer.
        verify(aca_pk, idav, ac)
        avatar = dict(idav=idav, sk=avatar_sk, ac=ac)  # Local certified avatar record.
        del credential, reg_sk

        samples[0].append((registration_end - registration_start) / 1e6)
        samples[1].append((creation_end - creation_start) / 1e6)
        del avatar, avatar_sk
    # Let the Mac wait for statistics without affecting any timed phase.
    send(conn, dict(type="finished"))
    expect(conn, "finished_ack")
    summary = summarize(samples, runs)
    send(conn, dict(type="report", summary=summary))
    expect(conn, "report_ack")
    print_results(summary)


# Connect the Pi to the Mac once, then run both enrollment-phase benchmarks.
def main():
    """Connect to Mac once, then execute the benchmark on the Pi."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", default=MAC_IP)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--runs", type=int, default=RUNS)
    parser.add_argument("--uid", default="user_i")
    parser.add_argument("--descriptor", default="D_i,j")
    args = parser.parse_args()
    if args.runs < 1 or not args.uid or not args.descriptor:
        parser.error("runs must be positive; UID and descriptor must be nonempty")
    check_algorithm()
    with socket.create_connection((args.peer, args.port), timeout=60) as conn:
        configure(conn)
        benchmark(conn, args.runs, args.uid, args.descriptor)


if __name__ == "__main__":
    main()
