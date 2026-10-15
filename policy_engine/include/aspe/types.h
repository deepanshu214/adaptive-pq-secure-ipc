// ---------------------------------------------------------------------------
// Adaptive Security Policy Engine (ASPE)
// Core domain types shared by every module of the framework.
// ---------------------------------------------------------------------------
#ifndef ASPE_TYPES_H
#define ASPE_TYPES_H

#include <cstdint>
#include <string>

namespace aspe {

// ----- Qualitative input scales ---------------------------------------------

/// How damaging disclosure of the message content would be.
enum class Sensitivity { Low = 0, Medium = 1, High = 2, Critical = 3 };

/// How important timely, correct delivery of the message is to the system.
enum class Criticality { Low = 0, Medium = 1, High = 2, Critical = 3 };

/// Current threat level observed on the host / IPC channel.
enum class ThreatLevel { Low = 0, Medium = 1, High = 2, Critical = 3 };

/// Discretised trust of the sending process (the engine itself uses the
/// continuous trust score in [0, 1]; the level is used for reporting).
enum class TrustLevel { Low = 0, Medium = 1, High = 2 };

// ----- Output scale ------------------------------------------------------------

/// Security level selected for an IPC message. Each level maps to a concrete
/// cryptographic suite (see crypto_suite.h).
enum class SecurityLevel {
    Basic = 1,             ///< L1  integrity + origin authentication only (MAC)
    Classical = 2,         ///< L2  classical ECDHE + AEAD (quantum-vulnerable)
    Hybrid = 3,            ///< L3  classical + ML-KEM key exchange
    PostQuantum = 4,       ///< L4  ML-KEM-768 + ML-DSA-65
    StrongPostQuantum = 5  ///< L5  ML-KEM-1024 + ML-DSA-87, per-message signatures
};

constexpr int kMinLevel = 1;
constexpr int kMaxLevel = 5;
constexpr int kLevelCount = 5;

// ----- Message and runtime context -----------------------------------------

/// Static attributes of an IPC message (known when the message is created).
struct IpcMessage {
    std::uint64_t id = 0;
    std::string type;                 ///< Application message type, e.g. "Alert"
    int senderPid = 0;
    int receiverPid = 0;
    std::uint32_t sizeBytes = 0;      ///< Payload size
    Sensitivity sensitivity = Sensitivity::Low;
    Criticality criticality = Criticality::Low;
    double lifetimeYears = 0.0;       ///< How long the content must stay confidential
};

/// Dynamic state of the system at the moment the message is sent.
struct RuntimeContext {
    double processTrust = 0.5;        ///< Trust score of the sender in [0, 1]
    ThreatLevel threat = ThreatLevel::Low;
    double cpuPercent = 0.0;          ///< CPU utilisation in [0, 100]
    double memoryPercent = 0.0;       ///< Memory utilisation in [0, 100]
};

// ----- Helpers ---------------------------------------------------------------------

template <typename Enum>
constexpr int ordinal(Enum value) {
    return static_cast<int>(value);
}

inline int toInt(SecurityLevel level) { return static_cast<int>(level); }

/// Converts an integer to a security level, clamping to [1, 5].
SecurityLevel levelFromInt(int value);
SecurityLevel stepUp(SecurityLevel level);
SecurityLevel stepDown(SecurityLevel level);
SecurityLevel maxLevel(SecurityLevel a, SecurityLevel b);

TrustLevel trustLevelFromScore(double trustScore);
double representativeTrustScore(TrustLevel level);

std::string toString(Sensitivity value);
std::string toString(Criticality value);
std::string toString(ThreatLevel value);
std::string toString(TrustLevel value);
std::string toString(SecurityLevel value);
/// Compact label such as "L3-HYBRID".
std::string shortName(SecurityLevel value);

/// Case-insensitive parsers. Accept names ("HIGH") or ordinals ("2").
bool parse(const std::string& text, Sensitivity& out);
bool parse(const std::string& text, Criticality& out);
bool parse(const std::string& text, ThreatLevel& out);
bool parse(const std::string& text, TrustLevel& out);
/// Accepts "BASIC", "CLASSICAL", "HYBRID", "PQ", "POST_QUANTUM", "STRONG_PQ",
/// "L1".."L5" or "1".."5".
bool parse(const std::string& text, SecurityLevel& out);

}  // namespace aspe

#endif  // ASPE_TYPES_H
