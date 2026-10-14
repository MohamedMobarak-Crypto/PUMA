# PUMA: Mutual Authentication and Key Establishment

This folder contains the socket-based PUMA mutual-authentication benchmark for two Raspberry Pi 5 devices. The avatars exchange signed authentication messages, establish a fresh shared secret with ML-KEM, derive separate session and confirmation keys, and perform bilateral key confirmation.

The source filenames retain the earlier project name, VISTA.

## Files

| File | Device and role |
| --- | --- |
| [VISTA_U1_Key_conf_V02.py](VISTA_U1_Key_conf_V02.py) | Pi 1: initiator, setup coordination, and statistics collection |
| [VISTA_U2_Key_Conf_V02.py](VISTA_U2_Key_Conf_V02.py) | Pi 2: responder and final confirmation verification |

Use these matching V02 files together.

## Cryptographic configuration

| Component | Setting |
| --- | --- |
| Signatures and certificates | ML-DSA-44, NIST category 2 |
| Session key encapsulation | ML-KEM-512, NIST category 1 |
| Key derivation | HKDF-SHA-256; separate 32-byte session and confirmation keys |
| Key confirmation | HMAC-SHA-256; 32-byte direction-specific tags |

## Requirements

Both devices require Python 3 and compatible installations of `liboqs` and `liboqs-python`. Follow the [official installation guide](https://github.com/open-quantum-safe/liboqs-python#installation) for the native library and platform prerequisites. A native build requires Git, CMake, and a C compiler.

To install the Python wrapper in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install liboqs-python
```

Connect the devices over Ethernet and synchronize their clocks. The scripts check received timestamps against a 30-second freshness window.

## Run

Run commands from this folder on each device. The example uses `192.168.2.2` as Pi 1's address; replace it with your actual address.

Start Pi 1 first:

```bash
python3 VISTA_U1_Key_conf_V02.py --bind 192.168.2.2 --port 5300 --runs 10000
```

Then start Pi 2:

```bash
python3 VISTA_U2_Key_Conf_V02.py --peer 192.168.2.2 --port 5300
```

Pi 1 controls the iteration count and communicates it during setup. Its default is 10,000 iterations. Use `--runs 100` for a short initial run.

## Authentication exchange

| Message | Direction | Purpose |
| --- | --- | --- |
| AuthReq | Pi 1 to Pi 2 | Send the initiator certificate, both identities, ephemeral encapsulation key, timestamp, and signature |
| AuthRes | Pi 2 to Pi 1 | Send the responder certificate, both identities, ciphertext, timestamp, signature, and responder confirmation tag |
| AuthConf | Pi 1 to Pi 2 | Send the initiator confirmation tag |

The signed fields are:

```text
AuthReq: (IdAv_A, IdAv_B, ek, ts1)
AuthRes: (IdAv_B, IdAv_A, c, ts2)
```

A fresh ML-KEM key pair is generated in every iteration. HKDF and HMAC use the authenticated transcript and distinct purpose/direction labels.

## Timing and output

Both devices print per-stage statistics. Durations are in milliseconds; population variances are in milliseconds squared. All iterations are included, with no warm-up or outlier removal.

The end-to-end timer starts before Pi 1 generates the ephemeral ML-KEM key pair. It stops after Pi 2 verifies AuthConf and Pi 1 receives and validates Pi 2's timing report. The total therefore includes the authentication exchange and the extra per-session timing-report message.

Authority setup and avatar certification, and the final statistics exchange, are excluded from per-session timing. Record hardware, software versions, iteration count, and source revision alongside measured results.

## Prototype scope

Pi 1 emulates authority setup, and public authority keys received during setup are trusted within the laboratory experiment. Synthetic identities and random avatar keys are used. Biometric regeneration, complete tracing registries, Judge-authorized tracing, and encrypted application traffic are outside this benchmark.

