# Adaptive Security Policy Engine (ASPE)

**Adaptive Post-Quantum Secure Inter-Process Communication Framework with Dynamic Security Policy Selection**
Part 1 of 2: *Adaptive IPC Security Policy & Threat Intelligence* (Aditya)

ASPE is the decision-making layer of the framework. For every IPC message it decides **how much
protection the message needs**: BASIC, CLASSICAL, HYBRID, POST-QUANTUM or STRONG POST-QUANTUM. The
decision depends on the message's sensitivity, the trust of the sending process, the current threat
level, how critical the communication is, and the CPU/memory available. The partner project (Secure IPC
& PQC Engine, Deepanshu) carries out the selected policy through a small, documented interface (`ISecureChannel`).

```
                 IPC MESSAGE
                      |
          +-----------v-----------+   Phase 2
          |  Context extraction   |   S, C, H, trust, CPU, memory, size, lifetime -> [0,1]
          +-----------+-----------+
          +-----------v-----------+   Phase 1 + 3
          | Requirement analysis  |   which services are needed (confidentiality, PQ, ...)
          | Risk assessment       |   R = wI*I + wL*L + wX*I*L  -> risk band L1..L5
          +-----------+-----------+
          +-----------v-----------+   Phase 4
          | Policy selection      |   required = max(risk band, requirement floor)
          +-----------+-----------+
          +-----------v-----------+   Phase 5
          | Resource adaptation   |   harden / keep / optimize / lightweight, never below floor
          +-----------+-----------+
                      v
     SecurityProfile -> ISecureChannel (partner: authentication, encryption, PQC)
                      ^
     ThreatMonitor / TrustManager / ResourceMonitor  <- security events fed back
```

## Results at a glance

All numbers below are reproduced by `aspe all` (deterministic seeds). Figures are in `results/figures/`.

| | Result |
|---|---|
| Specification scenarios (Status, Gaze, Profile, Emergency, Alert) | **5/5** classified as specified |
| Agreement with the independent reference policy (5000 messages) | **98.0 %**, under-protection **0.2 %**, always within one level |
| Calibration, held-out test split | 74.1 % → **97.6 %** accuracy after calibration |
| Dataset: security failures (below mandatory floor) | Adaptive **0.1 %** vs Static CLASSICAL 43.0 %, Static PQ 1.8 % |
| Dataset: mean crypto CPU per message (embedded device) | Adaptive **107 µs** vs Static PQ 195 µs, Static STRONG-PQ 4,410 µs |
| Simulation under load + intrusion: delivered within deadline | Adaptive (full) **100 %**, adaptive without Phase 5 96.5 %, Static STRONG-PQ 24.6 % |
| Simulation: p95 latency | Adaptive (full) **0.40 ms** vs 50.5 ms without Phase 5 and 2.49 ms for Static PQ |
| Policy decision overhead (measured) | ~0.2–0.3 µs per decision, ~1 % of the protection it selects |
| Unit and property tests | **29/29** pass |

## Quick start

Requirements: a C++14 compiler (GCC ≥ 5, Clang ≥ 3.4 or MSVC 2017+). Optional: GNU make or
CMake ≥ 3.10, and Python ≥ 3.8 for the figures.

```bash
# Windows (MinGW g++), no make needed
build.bat run                 # builds, runs the tests, runs every phase

# Any platform with GNU make (mingw32-make on Windows)
make            # build/aspe and build/aspe_tests
make test       # 29 unit and property tests
make run        # every phase -> data/ and results/

# CMake (Visual Studio, Ninja, Makefiles, ...)
cmake -S . -B build && cmake --build build --config Release
ctest --test-dir build

# Figures (optional)
python -m pip install -r requirements.txt
python scripts/plot_results.py           # -> results/figures/*.png
```

Run the commands from the project root. `aspe all` writes the dataset to `data/`, all CSV and text
results to `results/`, and the whole console report to `results/report.txt`.

## Command reference

| Command | Phase | What it does |
|---|---|---|
| `aspe analyze` | 1 | IPC threat catalogue, quantum threat model, requirement analysis |
| `aspe params` | 2 | Parameter specification, normalised context vectors, crypto suites |
| `aspe generate [--count 5000] [--seed 42]` | – | Synthetic dataset with reference labels |
| `aspe classify` | 3 | Classification of the scenarios + confusion matrix on the dataset |
| `aspe calibrate [--samples 6000]` | 4 | Experimental determination of weights and thresholds |
| `aspe decide --sensitivity HIGH --criticality CRITICAL --threat HIGH --trust 0.3 --cpu 80` | 4/5 | One decision with a full explanation (`--json` for machine output) |
| `aspe adapt` | 5 | Policy selected as CPU load rises |
| `aspe evaluate [--rate 500]` | 6 | Static vs adaptive on the dataset |
| `aspe simulate [--seed 2024]` | 6 | Closed-loop simulation: load peaks and an intrusion |
| `aspe bench` | – | Measured decision overhead |
| `aspe demo` | – | Integration demo through `ISecureChannel` |
| `aspe all` | 1–6 | Everything above, in order |

`--platform embedded|reference` selects the cost model (embedded ARM-class device or x86-64 desktop).

Example:

```text
$ aspe decide --type Alert --sensitivity CRITICAL --criticality CRITICAL --threat HIGH --trust LOW --cpu 80 --lifetime 12
    Requirements           : integrity, origin-auth, anti-replay, confidentiality, strong-auth, PQ-confidentiality, PQ-authentication -> floor L4-PQ
    Risk model             : I=1.000 L=0.731 R=0.858 -> band L5-STRONG-PQ
    Required level         : L5-STRONG-PQ
    Mandatory floor        : L5-STRONG-PQ (no downgrade: critical asset or critical threat)
    Resource state         : ELEVATED (P=0.80)
    Adaptation             : OPTIMIZED - Elevated resource pressure: level kept, parameters optimized
    Selected policy        : L5-STRONG-PQ / OPTIMIZED  [ML-KEM-1024 | ML-DSA-87 | AES-256-GCM]
```

## How each phase is implemented

| Phase | Module | Key idea |
|---|---|---|
| 1 IPC security analysis | `threat_analysis.h` | Six IPC threats (impersonation, unauthorized access, tampering, replay, eavesdropping, harvest-now-decrypt-later) mapped to security properties. The requirement analysis gives the lowest level that provides every needed service. |
| 2 Security parameters | `parameters.h` | Seven measurable parameters plus confidentiality lifetime, each normalised to [0, 1]. Mosca's inequality (x + y > z) decides quantum exposure. |
| 3 Classification engine | `risk_model.h`, `classifier.h` | Impact I = a·max(S,C) + (1−a)·mean(S,C); likelihood L = b·H + (1−b)·(1−T); risk R = wI·I + wL·L + wX·I·L, mapped to 5 bands. The final level is the higher of the risk band and the requirement floor. |
| 4 Adaptive policy engine | `policy_engine.h`, `evaluation.h` | Weights and thresholds calibrated by random search with local refinement on a train/test split. The cost is asymmetric (under-protection ×4) and the specification scenarios are hard constraints. |
| 5 Performance-aware adaptation | `policy_engine.h` | IDLE → harden, NORMAL → as required, ELEVATED → optimize parameters, CONSTRAINED → one level down *only if cheaper*, never below the mandatory floor. Critical assets and CRITICAL threat are never downgraded. |
| Adaptive decision mechanism | `runtime_monitor.h` | Threat monitor (EWMA + hysteresis), Beta-reputation trust with forgetting, smoothed resource monitor. |
| 6 Evaluation | `evaluation.h`, `simulation.h` | Static L1..L5 vs adaptive (with and without Phase 5), on the dataset and in a closed-loop 300 s simulation with a fluid queue model. |

### Security levels

| Level | Key establishment | Authentication | Payload | Quantum-safe | Re-key |
|---|---|---|---|---|---|
| L1 BASIC | pre-provisioned key | HMAC-SHA-256 | integrity only | – | – |
| L2 CLASSICAL | X25519 | Ed25519 | AES-256-GCM | no | 64 msgs |
| L3 HYBRID | X25519 + ML-KEM-512 | Ed25519 | AES-256-GCM | confidentiality | 32 msgs |
| L4 POST-QUANTUM | ML-KEM-768 | ML-DSA-65 | AES-256-GCM | conf. + auth. | 16 msgs |
| L5 STRONG PQ | ML-KEM-1024 | ML-DSA-87 per message | AES-256-GCM | conf. + auth. | 4 msgs |

*Optimized* mode keeps the algorithms. It multiplies the re-key interval by 4 and replaces per-message
signatures with session-level authentication.

## Integration with the Secure IPC & PQC engine

The partner project implements one interface:

```cpp
class ISecureChannel {
public:
    virtual ~ISecureChannel() = default;
    virtual std::string name() const = 0;
    virtual TransmissionReport transmit(const IpcMessage& message,
                                        const SecurityProfile& profile) = 0;
};
```

`SecurityProfile` carries the level, mode, algorithms, re-key interval, per-message-signature flag and
replay protection. `TransmissionReport` returns latency, wire bytes, whether the peer authenticated, and
any detected attacks (replay, tampering, ...). `SecureIpcFramework` connects the two sides: it selects the
policy, calls `transmit`, and feeds the outcome back into the trust and threat monitors.
`ModelledSecureChannel` stands in for the partner engine until integration, and `aspe demo` shows the
full loop. Decisions can also be exported as JSON (`aspe decide --json`) for a non-C++ engine.

Link against the `aspe_core` CMake target, or compile `src/*.cpp` with `-Iinclude`.

## Project layout

```
include/aspe/      public headers (one per module, documented)
src/               implementation
apps/aspe_main.cpp command-line tool
tests/test_main.cpp unit + property tests (no external framework)
scripts/plot_results.py figures from results/*.csv
docs/              Review 2 implementation report (PDF + HTML source)
data/              generated dataset
results/           generated results, report.txt, figures/
legacy_prototype/  earlier prototype, kept for reference (not built)
```

## Assumptions and limitations

- The cryptographic **costs are an analytical model**. Object sizes are exact (FIPS 203/204,
  RFC 7748/8032). Timings are order-of-magnitude estimates for reference implementations, ×6 for
  the embedded platform. They are replaced by measurements once the partner engine is integrated.
- The **reference policy** (risk matrix + Mosca rule) is the ground truth for a synthetic dataset. It
  plays the role of an expert's security policy; the engine never uses it directly.
- In the simulation, the remaining policy violations come from **detection lag**: the monitors need
  1–3 s to notice an attack, which accounts for about 95 % of violations. The rest is residual
  calibration error (0.2 %).
- No message content is inspected. Sensitivity and criticality are declared by the sending
  application or by system policy.

## References

NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), 2024 · NIST SP 800-30 Rev. 1 · NIST IR 8547 (draft) ·
M. Mosca, *IEEE Security & Privacy* 16(5), 2018 · A. Jøsang & R. Ismail, *The Beta Reputation System*,
2002 · D. Stebila et al., *Hybrid key exchange in TLS 1.3* (IETF draft) · Open Quantum Safe, liboqs.
