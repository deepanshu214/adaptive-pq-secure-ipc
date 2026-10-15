// ---------------------------------------------------------------------------
// Phase 1 - IPC security analysis.
//
// Catalogue of IPC threats, the security property each one violates, and a
// requirement analyser that derives the security services a message needs.
// The derived requirements give a hard lower bound ("requirement floor") on
// the security level that the policy engine may select.
// ---------------------------------------------------------------------------
#ifndef ASPE_THREAT_ANALYSIS_H
#define ASPE_THREAT_ANALYSIS_H

#include <string>
#include <vector>

#include "aspe/parameters.h"
#include "aspe/types.h"

namespace aspe {

enum class IpcThreat {
    ProcessImpersonation,
    UnauthorizedAccess,
    MessageTampering,
    ReplayAttack,
    Eavesdropping,
    HarvestNowDecryptLater
};

enum class SecurityProperty {
    Authentication,
    AccessControl,
    Integrity,
    Freshness,
    Confidentiality,
    QuantumResistance
};

std::string toString(IpcThreat threat);
std::string toString(SecurityProperty property);

struct ThreatProfile {
    IpcThreat threat;
    std::string description;
    std::string ipcAttackVector;
    SecurityProperty violatedProperty;
    std::string countermeasure;
};

/// Security services required by a message.
struct SecurityRequirements {
    bool integrity = true;                 ///< Always: no silent modification
    bool originAuthentication = true;      ///< Always: know who sent it
    bool replayProtection = false;         ///< Freshness / anti-replay window
    bool confidentiality = false;          ///< Encryption of the payload
    bool strongAuthentication = false;     ///< Asymmetric, per-session authentication
    bool quantumSafeConfidentiality = false;
    bool quantumSafeAuthentication = false;
};

/// Likelihood x impact estimate of one threat for one message.
struct ThreatExposure {
    IpcThreat threat;
    double likelihood = 0.0;
    double impact = 0.0;
    double risk() const { return likelihood * impact; }
};

const std::vector<ThreatProfile>& threatCatalogue();

class SecurityAnalyzer {
public:
    /// Derives the security services required by the message.
    SecurityRequirements analyze(const ContextVector& context) const;

    /// Estimates exposure to every catalogued threat, sorted by risk (desc).
    std::vector<ThreatExposure> assessThreats(const ContextVector& context) const;
};

/// Lowest security level whose suite provides all required services.
SecurityLevel minimumLevelFor(const SecurityRequirements& requirements);

/// Human-readable list such as "confidentiality, strong-auth, PQ-confidentiality".
std::string describe(const SecurityRequirements& requirements);

}  // namespace aspe

#endif  // ASPE_THREAT_ANALYSIS_H
