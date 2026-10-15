#include "risk_engine.h"

int RiskEngine::sensitivityScore(Sensitivity value) {

    switch (value) {
        case Sensitivity::LOW:
            return 1;

        case Sensitivity::MEDIUM:
            return 2;

        case Sensitivity::HIGH:
            return 3;

        case Sensitivity::CRITICAL:
            return 4;
    }

    return 0;
}

int RiskEngine::trustScore(TrustLevel value) {

    switch (value) {
        case TrustLevel::HIGH:
            return 1;

        case TrustLevel::MEDIUM:
            return 2;

        case TrustLevel::LOW:
            return 4;
    }

    return 0;
}

int RiskEngine::threatScore(ThreatLevel value) {

    switch (value) {
        case ThreatLevel::LOW:
            return 1;

        case ThreatLevel::MEDIUM:
            return 2;

        case ThreatLevel::HIGH:
            return 3;

        case ThreatLevel::CRITICAL:
            return 4;
    }

    return 0;
}

int RiskEngine::criticalityScore(Criticality value) {

    switch (value) {
        case Criticality::LOW:
            return 1;

        case Criticality::MEDIUM:
            return 2;

        case Criticality::HIGH:
            return 3;

        case Criticality::CRITICAL:
            return 4;
    }

    return 0;
}

RiskResult RiskEngine::calculateRisk(const IPCMessage& msg) {

    int score = 0;

    score += sensitivityScore(msg.sensitivity);
    score += trustScore(msg.processTrust);
    score += threatScore(msg.threat);
    score += criticalityScore(msg.criticality);

    RiskLevel level;

    if (score <= 4) {
        level = RiskLevel::LOW;
    }
    else if (score <= 8) {
        level = RiskLevel::MEDIUM;
    }
    else if (score <= 12) {
        level = RiskLevel::HIGH;
    }
    else {
        level = RiskLevel::CRITICAL;
    }

    return {score, level};
}