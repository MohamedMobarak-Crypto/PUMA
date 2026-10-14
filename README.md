# PUMA: Post-Quantum Unlinkable Metaverse Authentication with Accountability

This repository contains the experimental implementations and formal verification model for PUMA, a post-quantum framework for privacy-preserving avatar authentication with conditional accountability.

The work covers user registration, avatar creation, and mutual authentication with session-key establishment and bilateral key confirmation.

## Repository contents

| Folder | Contents |
| --- | --- |
| [Mutual authentication](Mutual_Authentication/) | Socket-based mutual authentication between two Raspberry Pi 5 devices, including session-key establishment, bilateral key confirmation, and timing measurements. |
| [Registration and avatar creation](Registration_Avatar_Creation/) | Socket-based registration and avatar creation between a Raspberry Pi 5 and a Mac. The Mac emulates the registration and avatar-certification authorities, with timing measurements for both phases. |
| [AVISPA](AVISPA/) | HLPSL model and recorded OFMC and CL-AtSe results for authentication, key confirmation, and secrecy in bounded sessions. |

## Cryptographic configuration

The socket implementations use **ML-DSA-44 (security category 2)** for signatures and certificates. Mutual authentication also uses **ML-KEM-512 (security category 1)**, **HKDF-SHA-256** for key derivation, and **HMAC-SHA-256** for key confirmation.

## Experimental results

| Phase | Execution time |
| --- | --- |
| User registration | 0.82 ms |
| Avatar creation | 1.38 ms |
| Mutual authentication | 2.57 ms |

## Getting started

Open the README in each folder for dependencies, configuration, execution commands, and details of the timing measurements or formal verification results.
