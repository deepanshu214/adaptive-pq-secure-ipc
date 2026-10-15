#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include <string>

#include "ipc_message.h"
#include "risk_engine.h"

using namespace std;

enum class SecurityPolicy {

    BASIC,
    CLASSICAL,
    HYBRID,
    POST_QUANTUM
};

struct PolicyDecision {

    SecurityPolicy basePolicy;
    SecurityPolicy policy;

    bool adapted;
    bool securityEscalated;
    bool resourceAdapted;

    string reason;
};

class PolicyEngine {

public:

    PolicyDecision selectPolicy(
        const IPCMessage& message,
        const RiskResult& risk
    );
};

#endif