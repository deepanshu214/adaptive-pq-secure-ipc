#ifndef RISK_ENGINE_H
#define RISK_ENGINE_H

#include "ipc_message.h"

enum class RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct RiskResult {
    int score;
    RiskLevel level;
};

class RiskEngine {
public:
    RiskResult calculateRisk(const IPCMessage& msg);

private:
    int sensitivityScore(Sensitivity value);
    int trustScore(TrustLevel value);
    int threatScore(ThreatLevel value);
    int criticalityScore(Criticality value);
};

#endif