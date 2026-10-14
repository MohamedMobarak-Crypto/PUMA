"""PUMA registration/avatar-creation benchmark; standalone file.
Authority role: run PUMA_Authority_V01.py on the Mac first.
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

MSP signs raw registration pk (RC); ACA verifies RC and registration-key signature
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
    print("All issued certificates verified on the Pi.")
    print("Timers stop after certificate reception/decoding; Pi-side verification/storage excluded.")


# Check that native liboqs supports the selected ML-DSA parameter set.
def check_algorithm():
    """Fail early if the installed C library does not enable the selected ML-DSA."""
    if SIG not in oqs.get_enabled_sig_mechanisms():
        raise ValueError(f"{SIG} is not enabled in liboqs")


# Process enrollment requests on the Mac and return registration/avatar certificates.
def serve(conn, ra_pk, ra_sk, aca_pk, aca_sk):
    """Issue RC and AC to the Pi; only public authority keys are shared."""
    # Bootstrap public authority keys only; sk_RA and sk_ACA remain on the Mac.
    send(conn, dict(type="parameters", version=VERSION, signature=SIG,
                    ra_pk=encode(ra_pk), aca_pk=encode(aca_pk)))
    runs = expect(conn, "start")["runs"]
    if type(runs) is not int or runs < 1:
        raise ValueError("Invalid run count")
    print(f"Serving {runs} independent enrollment trials.", flush=True)
    ra_table, aca_table, used = {}, {}, set()
    for i in range(runs):
        expect(conn, "reset", i)
        # Reset the simulated database OUTSIDE the Pi's timers.
        ra_table.clear()
        aca_table.clear()
        used.clear()
        send(conn, dict(type="ready", iteration=i))

        # Registration request for one credential: (UID_i, pk^reg_{i,j}).
        request = expect(conn, "register", i)
        uid, reg_pk = request["uid"], decode(request["pk_reg"])
        # Real-world UID vetting is simulated, not measured.
        if not isinstance(uid, str) or not uid or len(reg_pk) != PK_SIZE or reg_pk in ra_table:
            raise ValueError("Invalid registration request")
        rc = sign(ra_sk, reg_pk)  # RC_{i,j} = ML-DSA.Sign(sk_RA, pk^reg_{i,j}).
        ra_table[reg_pk] = uid  # T_RA stores pk^reg_{i,j} -> UID_i.
        send(conn, dict(type="registered", iteration=i, rc=encode(rc)))  # Return RC_{i,j}.

        # AReq_{i,j} = (pk^reg_{i,j}, RC_{i,j}, IdAv_{i,j}, sigma^req_{i,j}).
        # "proof" is sigma^req; type/iteration fields are benchmark metadata.
        request = expect(conn, "create", i)
        creation_pk = decode(request["pk_reg"])
        if creation_pk != reg_pk:
            raise ValueError("Creation credential differs from this trial's registration")
        # ACA verifies the certificate and authorization before issuing AC.
        ac = certify_avatar(ra_pk, aca_sk, creation_pk, decode(request["rc"]),
                            decode(request["idav"]), decode(request["proof"]), used, aca_table)
        send(conn, dict(type="created", iteration=i, ac=encode(ac)))  # Return AC_{i,j}.

    expect(conn, "finished")
    conn.settimeout(600)  # Exact median/std-dev calculations happen after all trials.
    send(conn, dict(type="finished_ack"))
    report = expect(conn, "report")
    if report["summary"]["runs"] != runs:
        raise ValueError("Report run count mismatch")
    send(conn, dict(type="report_ack"))
    print_results(report["summary"])


# Generate MSP/ACA keys on the Mac, accept the Pi connection, and serve requests.
def main():
    """Generate authority keys once and listen for the Pi. Run Mac first."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=MAC_IP)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    check_algorithm()
    ra_pk, ra_sk = keygen()  # (pk_RA, sk_RA) = ML-DSA.KeyGen(pp_DSA).
    aca_pk, aca_sk = keygen()  # (pk_ACA, sk_ACA) = ML-DSA.KeyGen(pp_DSA).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen(1)
        print(f"Mac RA/ACA waiting for Pi on {args.host}:{args.port} ...", flush=True)
        conn, address = listener.accept()
        with conn:
            configure(conn)
            print(f"Pi connected: {address[0]}", flush=True)
            serve(conn, ra_pk, ra_sk, aca_pk, aca_sk)


if __name__ == "__main__":
    main()
