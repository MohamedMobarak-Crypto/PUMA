# PUMA: User Registration and Avatar Creation

This folder contains the socket-based benchmark for PUMA's user-registration and avatar-creation phases. A Raspberry Pi 5 represents the user, while a Mac emulates the Metaverse Service Provider (MSP/RA) and Avatar Creation Authority (ACA).

The source filenames retain the earlier project name, VISTA.

## Files

| File | Device and role |
| --- | --- |
| [VISTA_Authority_V03.py](VISTA_Authority_V03.py) | Mac: issue registration certificates, validate creation requests, and issue avatar certificates |
| [VISTA_User_V03.py](VISTA_User_V03.py) | Pi 5: generate user/avatar keys, submit requests, and measure both phases |

Use these matching V03 files together.

## Cryptographic configuration

Registration keys, avatar keys, authorization signatures, and authority certificates use ML-DSA-44, NIST category 2. Its public-key length is 1,312 bytes.

## Requirements

Both devices require Python 3 and compatible installations of `liboqs` and `liboqs-python`. Follow the [official installation guide](https://github.com/open-quantum-safe/liboqs-python#installation) for the native library and platform prerequisites. A native build requires Git, CMake, and a C compiler.

To install the Python wrapper in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install liboqs-python
```

Connect the Mac and Pi over Ethernet. All measured durations use the Pi's local performance counter, so these measurements do not require synchronized device clocks.

## Run

Run commands from this folder on the appropriate device. The example uses `192.168.2.1` as the Mac's address; replace it with your actual address.

Start the Mac authority first:

```bash
python3 VISTA_Authority_V03.py --host 192.168.2.1 --port 5500
```

Then start the Pi user:

```bash
python3 VISTA_User_V03.py --peer 192.168.2.1 --port 5500 --runs 1000
```

Only the Pi controls the iteration count. Omitting `--runs` uses the default of 100,000 trials. The Pi also accepts `--uid` and `--descriptor` to replace the demonstration values.

## Protocol phases

### User registration

The Pi generates a registration key pair and sends `(UID_i, pk_reg)` to the MSP. The MSP issues:

```text
RC = ML-DSA.Sign(sk_RA, pk_reg)
```

The MSP records the registration-public-key-to-user-identity association. The Pi verifies the received registration certificate.

### Avatar creation

The Pi generates an avatar authentication key pair and constructs:

```text
IdAv = pk_avatar || D
proof = ML-DSA.Sign(sk_reg, IdAv)
AReq = (pk_reg, RC, IdAv, proof)
```

The ACA verifies RC and the authorization proof, checks that the registration credential has not been consumed and the identity has not been recorded, then issues:

```text
AC = ML-DSA.Sign(sk_ACA, IdAv)
```

It marks the credential as used and retains the avatar's registration key and authorization proof. The Pi verifies AC. Message-type and iteration fields coordinate the benchmark.

## Timing and output

One persistent TCP connection serves the entire run. Fresh registration and avatar keys are generated in every trial.

| Phase | Timer starts | Timer stops |
| --- | --- | --- |
| Registration | Before Pi-side registration key generation | After the received RC is decoded |
| Avatar creation | Before Pi-side avatar key generation | After the received AC is decoded |

Network communication and authority processing are included. Pi-side certificate verification and local storage occur after each timer stops. TCP setup, authority key generation, trial resets, and final reporting are excluded.

Both devices print mean, median, population standard deviation, minimum, maximum, and total measured time. No warm-up iterations or outliers are removed. Authority records are reset between trials outside timing, so results measure independent enrollment latency.

## Prototype scope

Identity vetting is simulated, avatar keys are generated randomly, and both authority roles run on the Mac. The experiment does not implement biometric regeneration or independently deployed split-trust authorities. Keys and records remain in RAM for the experiment.

