#include "aspe/threat_analysis.h"

#include <algorithm>

namespace aspe {

std::string toString(IpcThreat threat) {
    switch (threat) {
        case IpcThreat::ProcessImpersonation: return "Process impersonation";
        case IpcThreat::UnauthorizedAccess: return "Unauthorized access";
        case IpcThreat::MessageTampering: return "Message tampering";
        case IpcThreat::ReplayAttack: return "Replay attack";
        case IpcThreat::Eavesdropping: return "Eavesdropping";
        case IpcThreat::HarvestNowDecryptLater: return "Harvest-now-decrypt-later";
    }
    return "Unknown";
}

std::string toString(SecurityProperty property) {
    switch (property) {
        case SecurityProperty::Authentication: return "Authentication";
        case SecurityProperty::AccessControl: return "Access control";
        case SecurityProperty::Integrity: return "Integrity";
        case SecurityProperty::Freshness: return "Freshness";
        case SecurityProperty::Confidentiality: return "Confidentiality";
        case SecurityProperty::QuantumResistance: return "Quantum resistance";
    }
    return "Unknown";
}

const std::vector<ThreatProfile>& threatCatalogue() {
    static const std::vector<ThreatProfile> catalogue = {
        {IpcThreat::ProcessImpersonation,
         "A malicious process poses as a trusted peer and sends forged messages.",
         "Squatting on a socket path / pipe name / bus name, PID reuse, spoofed endpoint",
         SecurityProperty::Authentication,
         "Peer authentication: HMAC (L1), Ed25519 (L2-L3), ML-DSA (L4-L5)"},
        {IpcThreat::UnauthorizedAccess,
         "A process without the required privilege reads or injects IPC data.",
         "World-readable shared memory, permissive message-queue ACLs, leaked handles",
         SecurityProperty::AccessControl,
         "Per-session keys: only authenticated peers hold the traffic key"},
        {IpcThreat::MessageTampering,
         "Message content is modified in transit or in a shared buffer.",
         "Writable shared-memory ring buffer, compromised broker, ptrace injection",
         SecurityProperty::Integrity,
         "MAC / AEAD authentication tag on every message"},
        {IpcThreat::ReplayAttack,
         "A previously valid message is re-injected (e.g. a repeated command).",
         "Recorded socket traffic replayed by a local attacker",
         SecurityProperty::Freshness,
         "Monotonic sequence numbers, sliding replay window, periodic re-keying"},
        {IpcThreat::Eavesdropping,
         "A passive attacker observes message content.",
         "Debug interfaces, /proc inspection, broker logs, side channels",
         SecurityProperty::Confidentiality,
         "AEAD encryption (AES-256-GCM) with ephemeral session keys"},
        {IpcThreat::HarvestNowDecryptLater,
         "Recorded ciphertext is decrypted once a quantum computer can run Shor's algorithm.",
         "Exfiltrated captures of long-lived sensitive IPC traffic",
         SecurityProperty::QuantumResistance,
         "ML-KEM (FIPS 203) key establishment, ML-DSA (FIPS 204) signatures, AES-256"},
    };
    return catalogue;
}

SecurityRequirements SecurityAnalyzer::analyze(const ContextVector& c) const {
    SecurityRequirements r;
    const bool criticalAsset = c.sensitivityLevel == Sensitivity::Critical ||
                               c.criticalityLevel == Criticality::Critical;

    r.integrity = true;
    r.originAuthentication = true;
    r.replayProtection = ordinal(c.criticalityLevel) >= ordinal(Criticality::Medium) ||
                         ordinal(c.threatLevel) >= ordinal(ThreatLevel::High);
    r.confidentiality = ordinal(c.sensitivityLevel) >= ordinal(Sensitivity::Medium);
    r.strongAuthentication = c.trustLevel == TrustLevel::Low ||
                             ordinal(c.threatLevel) >= ordinal(ThreatLevel::High) ||
                             ordinal(c.criticalityLevel) >= ordinal(Criticality::High);
    r.quantumSafeConfidentiality = r.confidentiality && (c.quantumExposed || criticalAsset);
    r.quantumSafeAuthentication = criticalAsset;
    return r;
}

std::vector<ThreatExposure> SecurityAnalyzer::assessThreats(const ContextVector& c) const {
    const double assetImpact = std::max(c.sensitivity, c.criticality);
    const double hndl = c.quantumExposure;

    std::vector<ThreatExposure> result = {
        {IpcThreat::ProcessImpersonation, 0.5 * c.distrust + 0.5 * c.threat, assetImpact},
        {IpcThreat::UnauthorizedAccess, 0.7 * c.threat + 0.3 * c.distrust, c.sensitivity},
        {IpcThreat::MessageTampering, 0.5 * c.threat + 0.5 * c.distrust, c.criticality},
        {IpcThreat::ReplayAttack, c.threat, c.criticality},
        {IpcThreat::Eavesdropping, c.threat, c.sensitivity},
        {IpcThreat::HarvestNowDecryptLater, hndl, c.sensitivity},
    };
    std::stable_sort(result.begin(), result.end(),
                     [](const ThreatExposure& a, const ThreatExposure& b) {
                         return a.risk() > b.risk();
                     });
    return result;
}

SecurityLevel minimumLevelFor(const SecurityRequirements& r) {
    if (r.quantumSafeAuthentication) return SecurityLevel::PostQuantum;
    if (r.quantumSafeConfidentiality) return SecurityLevel::Hybrid;
    if (r.confidentiality || r.strongAuthentication) return SecurityLevel::Classical;
    return SecurityLevel::Basic;
}

std::string describe(const SecurityRequirements& r) {
    std::vector<std::string> parts;
    if (r.integrity) parts.push_back("integrity");
    if (r.originAuthentication) parts.push_back("origin-auth");
    if (r.replayProtection) parts.push_back("anti-replay");
    if (r.confidentiality) parts.push_back("confidentiality");
    if (r.strongAuthentication) parts.push_back("strong-auth");
    if (r.quantumSafeConfidentiality) parts.push_back("PQ-confidentiality");
    if (r.quantumSafeAuthentication) parts.push_back("PQ-authentication");
    std::string text;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) text += ", ";
        text += parts[i];
    }
    return text;
}

}  // namespace aspe
