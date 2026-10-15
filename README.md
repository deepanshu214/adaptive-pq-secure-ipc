# Adaptive Post-Quantum Secure IPC Framework

**with Dynamic Security Policy Selection** - group project of Aditya and Deepanshu.

Not every message between two processes needs the same protection. A status update and an emergency
alert should not cost the same CPU time, and the alert should not be protected as weakly as the status
update either. This framework decides, for every IPC message, how much security it needs and then
actually applies that security while the message travels from Process A to Process B.

```
  IPC message + context                                 Process B
        |                                                   ^
        v                                                   |
  +----------------------------+   profile    +-------------+--------------+
  | Policy engine  (Aditya)    |  --------->  | Secure IPC engine          |
  | C++, policy_engine/        |   L1 .. L5   | (Deepanshu)  secure_ipc/   |
  | risk model, policy choice, |              | authentication, key        |
  | resource-aware adaptation  |  <---------  | exchange, encryption,      |
  +----------------------------+   attacks    | integrity, anti-replay     |
                                   detected   +----------------------------+
```

| Part | Who | Language | What it does |
|---|---|---|---|
| `policy_engine/` | Aditya | C++14 | Classifies each message (sensitivity, criticality, sender trust, threat, CPU / memory) and selects a security level L1-L5 and its parameters. Includes its own dataset, calibration, evaluation and simulation. |
| `secure_ipc/` | Deepanshu | Python 3 | Carries the decision out between two real processes: mutual authentication, classical / hybrid / post-quantum key exchange, AES-256-GCM, replay protection, re-keying, per-message signatures. Also contains the integration (`policy.py`, `framework.py`), attack tests and benchmarks. |

## Security levels

The levels are defined once, by the policy engine (`policy_engine/src/crypto_suite.cpp`), and the
secure IPC engine implements exactly those suites (`secure_ipc/crypto.py`).

| Level | Key establishment | Authentication | Payload | Re-key | Per-message signature |
|---|---|---|---|---|---|
| L1 BASIC | pre-provisioned channel key | HMAC-SHA-256 | integrity only | - | no |
| L2 CLASSICAL | X25519 | Ed25519 | AES-256-GCM | 64 msgs | no |
| L3 HYBRID | X25519 + ML-KEM-512 | Ed25519 | AES-256-GCM | 32 msgs | no |
| L4 POST_QUANTUM | ML-KEM-768 | ML-DSA-65 | AES-256-GCM | 16 msgs | no |
| L5 STRONG_PQ | ML-KEM-1024 | ML-DSA-87 | AES-256-GCM | 4 msgs | yes (ML-DSA-87) |

In **OPTIMIZED** mode (chosen by the engine under CPU or memory pressure) the algorithms stay the same,
the re-key interval is multiplied by 4 and per-message signatures are switched off.

## Setup

Needs a C++14 compiler (clang or g++), GNU make and Python 3. Tested on macOS with Apple clang 21
and Python 3.12.4.

```bash
git clone <this repository>
cd adaptive-pq-secure-ipc
make setup      # pip install cryptography==50.0.2 kyber-py==1.2.0 dilithium-py==1.4.0
make            # builds policy_engine/build/aspe and aspe_tests
```

## Running it

| Command | What you see |
|---|---|
| `make run` | **The complete framework.** The five specification messages (Status, Gaze, Profile, Emergency, Alert) are decided by the policy engine and sent through the secure IPC engine to a separate Process B. Then a stream of Gaze messages is attacked by a simulated man in the middle: Process B detects it, the feedback lowers trust and raises the threat level, and the engine moves Gaze from L2 to L3 for the next messages. |
| `make test` | The policy engine's 29 unit tests, then 7 attacks against all 5 levels. |
| `make demo` | The secure IPC engine alone: every level over a pipe and over a Unix socket. |
| `make bench` | Timing of every algorithm, handshake / latency / throughput / CPU / memory per level, and the measured numbers next to the policy engine's cost model. |
| `policy_engine/build/aspe all` | Aditya's full pipeline (analysis, calibration, evaluation, simulation), run from inside `policy_engine/`. See `policy_engine/README.md`. |

## How the two parts are connected

1. **Decision.** `secure_ipc/policy.py` calls the engine's documented JSON interface:
   `aspe decide --json --type Gaze --sensitivity MEDIUM ... --trust 0.85 --threat LOW --cpu 40`.
   The answer contains `selected_level`, `mode`, `rekey_interval` and `per_message_signature`.
2. **Profile.** `crypto.Profile.from_decision()` turns that answer into the profile the channel uses.
3. **Transmission.** `framework.SecureIpcFramework.send()` reuses the open session if the profile is
   unchanged, or opens a new authenticated session at the new level. The profile is part of the signed
   handshake, so nobody in between can lower it.
4. **Feedback.** Process B answers every message. If it detects tampering or a replay it reports an
   attack; the framework then halves the sender's trust and raises the threat level by one step, and
   the next decision is made with that context.

This is the same loop as the engine's own `SecureIpcFramework` (`policy_engine/include/aspe/integration.h`),
with the real secure channel in place of the `ModelledSecureChannel` stand-in.

## Results (from the runs above)

- All five specification messages get the level the specification asks for: Status L1, Gaze L2,
  Profile L3, Emergency L4, Alert L5 (OPTIMIZED, because CPU is at 80 %).
- After one detected attack, Gaze is raised from L2 CLASSICAL to L3 HYBRID automatically.
- All 7 attacks (unauthorized process, fake process, modified message, replayed message, invalid
  authentication, corrupted ciphertext, invalid signature) are detected at all 5 levels.
- Handshake: about 0.5 ms (L1), 3-5 ms (L2), 7 ms (L3), 60-85 ms (L4) and 90-120 ms (L5).
  After the handshake L1-L4 all reach roughly 0.02 ms per 1 KB round trip.
- L5 in STANDARD mode signs every message with ML-DSA-87 and drops to about 90 ms per round trip.
  This is the measured reason why the engine switches L5 to OPTIMIZED under load.
- Per-message overhead: 40 B at L1 (same as the engine's model), 24 B at L2-L4, 4651 B at L5 STANDARD.

## Changes made while integrating

Policy engine (`policy_engine/`): no code changes. It is used through its JSON interface, and its
29 tests pass unchanged.

Secure IPC engine (`secure_ipc/`):
- extended from three hand-picked modes to the engine's five levels, including L1 BASIC (HMAC with the
  pre-provisioned channel key) and L5 STRONG_PQ (ML-KEM-1024, ML-DSA-87);
- the hybrid level now follows the engine's definition (X25519 + ML-KEM-512, Ed25519);
- added re-keying, OPTIMIZED mode and per-message signatures, as described by the profile;
- one session key per direction instead of one shared key;
- the profile is carried in the signed handshake and Process B can enforce a minimum level;
- new `policy.py` (bridge to the engine) and `framework.py` (complete framework + demo);
- attacks and benchmarks now cover all five levels and compare measurements with the engine's model.

## Project layout

```
policy_engine/        Aditya - Adaptive Security Policy Engine (C++), see its own README
  include/aspe/       headers, one per module
  src/                implementation
  apps/aspe_main.cpp  command-line tool (aspe)
  tests/              29 unit and property tests
  data/, results/     dataset and generated results
secure_ipc/           Deepanshu - Secure IPC & PQC engine (Python) + integration
  crypto.py           the five suites: keys, signatures, key exchange, key derivation
  channel.py          handshake and protected channel (encryption, integrity, anti-replay, re-key)
  transport.py        pipe and Unix domain socket
  policy.py           bridge to the policy engine (aspe decide --json)
  framework.py        the complete framework and its demo
  demo.py             secure IPC engine alone, every level
  attacks.py          7 attacks x 5 levels
  benchmark.py        measurements per level, compared with the cost model
docs/                 demo and viva guide for both team members
Makefile              build / test / run for the whole project
requirements.txt      Python libraries (pinned)
```

## Limitations

- ML-KEM and ML-DSA come from pure-Python libraries (kyber-py, dilithium-py). They implement the NIST
  standards but are slow and not constant-time, so post-quantum timings are much higher than the
  engine's model, which assumes optimised C code.
- Re-keying derives the next key from the current one with HKDF. The engine's cost model counts a
  re-key as a fresh key exchange, which is stronger but more expensive.
- The framework's trust and threat feedback is a simple version (halve trust, raise threat one step,
  no decay). The engine's full monitors (EWMA threat monitor, Beta-reputation trust) are used in its
  own simulation (`aspe simulate`).
- Each decision starts the `aspe` program (about 3 ms). Inside one process the engine needs well
  under a microsecond per decision.
- Identity is possession of a registered private key (or, at L1, the shared channel key). There is no
  key revocation, and everything runs on one machine.
