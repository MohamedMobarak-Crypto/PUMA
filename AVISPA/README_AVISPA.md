# PUMA: AVISPA Formal Verification

This folder contains the annotated HLPSL model of PUMA's mutual-authentication and key-confirmation exchange, together with the recorded OFMC and CL-AtSe results. The model uses Dolev-Yao channels, allowing an adversary to intercept, modify, and replay messages.

## Files

Keep these files in the same folder:

| File | Purpose |
| --- | --- |
| [VISTA_mutual_auth_mlkem_fo_keyconfirm.hlpsl](VISTA_mutual_auth_mlkem_fo_keyconfirm.hlpsl) | Latest annotated model; reviewer comments added on October 14, 2026 |
| [OFMC.png](OFMC.png) | Recorded OFMC result from SPAN |
| [CL-AtSe.png](CL-AtSe.png) | Recorded CL-AtSe result from SPAN |

The source filenames retain the earlier project name, VISTA. The reviewer annotations change comments only; protocol statements, goals, and session configuration are preserved.

## Modeled exchange

| Message | Direction | Contents |
| --- | --- | --- |
| AuthReq | A to B | Initiator certificate, both avatar identities, ephemeral encapsulation key, timestamp, and request signature |
| AuthRes | B to A | Responder certificate and confirmation tag, both identities, ciphertext, timestamp, and response signature |
| AuthConf | A to B | Initiator confirmation tag |

The signed request contains `(IdAv_A, IdAv_B, E, T1)`. The signed response contains `(IdAv_B, IdAv_A, C, T2)`.

Certificates are pre-issued. ML-DSA signatures are represented as ideal symbolic signatures. ML-KEM uses an FO-inspired encryption and consistency-check abstraction with an implicit-rejection branch. HKDF and HMAC are represented by public symbolic constructors.

## Key derivation and confirmation

The model uses an initiator-first context and distinct key-purpose and confirmation-direction labels:

```text
Ctx  = IdAv_A.IdAv_B.E.C.T1.T2
Ks   = Kdf(K.Ls.Ctx)
Kc   = Kdf(K.Lc.Ctx)
TagB = Mac(Kc.Lb.Ctx)
TagA = Mac(Kc.La.Ctx)
```

`K` is the raw shared secret, `Ks` is the derived session key, and `Kc` is the confirmation key. A verifies TagB before sending AuthConf. B accepts only after verifying TagA. Direction separation prevents B's tag from being reused as A's tag.

## Security goals

| Goal | Meaning |
| --- | --- |
| `secrecy_of kem_secret` | Secrecy of the raw KEM shared secret K |
| `secrecy_of session_key` | Secrecy of the derived session key Ks |
| `secrecy_of confirmation_key` | Secrecy of the derived confirmation key Kc |
| `authentication_on req_agree` | B authenticates A's signed request |
| `authentication_on res_agree` | A authenticates B's response after verifying TagB |
| `authentication_on kc_b_to_a` | A verifies B's agreement on the context and derived keys |
| `authentication_on kc_a_to_b` | B verifies A's agreement through AuthConf |

The environment contains two honest A-B sessions, one A-intruder session, and one intruder-B session. Responders played by B share a replay cache. The intruder is an authorized peer for secrets established in its own sessions.

## Run the analysis

Use an AVISPA installation with HLPSL2IF and the OFMC/CL-AtSe backends available. Run from this folder:

```bash
avispa VISTA_mutual_auth_mlkem_fo_keyconfirm.hlpsl --ofmc
avispa VISTA_mutual_auth_mlkem_fo_keyconfirm.hlpsl --cl-atse
```

The supplied screenshots were produced with SPAN 1.6; the OFMC screenshot identifies version 2006/02/13. Use compatible tool versions and retain the generated IF and backend output when reproducing results. See the [AVISPA team's HLPSL tutorial](https://edu.info.uaic.ro/protocoale-de-securitate/HLPSL%20Tutorial.pdf) for tool usage.

## Recorded results

| Backend | Saved result | Analysis scope |
| --- | --- | --- |
| OFMC | SAFE | Bounded number of sessions |
| CL-AtSe | SAFE | Bounded number of sessions; typed model |

Both screenshots display `VISTA_Session_key_tag.if` as the analyzed input. Retain that tested IF and its corresponding HLPSL alongside the screenshots to make the source-to-result mapping explicit. The model comments also describe separate diagnostic runs, distinct from these SPAN screenshots.

### OFMC

![Recorded OFMC SAFE result](OFMC.png)

### CL-AtSe

![Recorded CL-AtSe SAFE result](CL-AtSe.png)

## Verification scope

SAFE applies to the specified symbolic model, goals, and session configuration. Real clock arithmetic, cache expiry, secret compromise/erasure, and concrete cryptographic implementations are outside this model. The model does not establish forward secrecy, anonymity, avatar unlinkability, tracing, non-frameability, or computational post-quantum security.

