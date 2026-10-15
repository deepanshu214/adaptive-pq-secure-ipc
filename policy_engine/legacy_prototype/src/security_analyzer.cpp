#include "security_analyzer.h"

SecurityRequirements SecurityAnalyzer::analyze(const IPCMessage& msg) {

    SecurityRequirements requirements;

    requirements.confidentiality = false;
    requirements.integrity = false;
    requirements.authentication = false;
    requirements.replayProtection = false;

    if (msg.sensitivity == Sensitivity::HIGH ||
        msg.sensitivity == Sensitivity::CRITICAL) {
        requirements.confidentiality = true;
    }

    if (msg.criticality == Criticality::HIGH ||
        msg.criticality == Criticality::CRITICAL) {
        requirements.integrity = true;
    }

    if (msg.processTrust == TrustLevel::LOW ||
        msg.threat == ThreatLevel::HIGH ||
        msg.threat == ThreatLevel::CRITICAL) {
        requirements.authentication = true;
    }

    if (msg.criticality == Criticality::HIGH ||
        msg.criticality == Criticality::CRITICAL ||
        msg.threat == ThreatLevel::HIGH ||
        msg.threat == ThreatLevel::CRITICAL) {
        requirements.replayProtection = true;
    }

    return requirements;
}