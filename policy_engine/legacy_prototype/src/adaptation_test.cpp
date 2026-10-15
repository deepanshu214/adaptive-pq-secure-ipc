#include <iostream>
#include "ipc_message.h"
#include "risk_engine.h"
#include "policy_engine.h"

using namespace std;

string policyToString(SecurityPolicy policy) {

    switch (policy) {

        case SecurityPolicy::BASIC:
            return "BASIC";

        case SecurityPolicy::CLASSICAL:
            return "CLASSICAL";

        case SecurityPolicy::HYBRID:
            return "HYBRID";

        case SecurityPolicy::POST_QUANTUM:
            return "POST_QUANTUM";
    }

    return "UNKNOWN";
}

string riskToString(RiskLevel level) {

    switch (level) {

        case RiskLevel::LOW:
            return "LOW";

        case RiskLevel::MEDIUM:
            return "MEDIUM";

        case RiskLevel::HIGH:
            return "HIGH";

        case RiskLevel::CRITICAL:
            return "CRITICAL";
    }

    return "UNKNOWN";
}

int main() {

    RiskEngine riskEngine;
    PolicyEngine policyEngine;

    IPCMessage msg;

    msg.id = 1;
    msg.message = "High Risk Transaction";

    msg.sensitivity = Sensitivity::HIGH;
    msg.processTrust = TrustLevel::MEDIUM;
    msg.threat = ThreatLevel::HIGH;
    msg.criticality = Criticality::HIGH;

    msg.messageSize = 1024;

    int cpuValues[] = {30, 50, 70, 85, 95};

    int memoryValues[] = {40, 50, 70, 85, 95};

    cout << "===== ADAPTATION EXPERIMENT =====\n\n";

    cout << "Scenario: High Risk IPC\n\n";

    cout << "CPU\tMemory\tRisk\tRisk Level\tPolicy\n";
    cout << "---------------------------------------------------\n";

    for (int i = 0; i < 5; i++) {

        msg.cpuUsage = cpuValues[i];
        msg.memoryUsage = memoryValues[i];

        RiskResult risk =
            riskEngine.calculateRisk(msg);

        PolicyDecision decision =
            policyEngine.selectPolicy(msg, risk);

        cout << msg.cpuUsage << "%\t"
             << msg.memoryUsage << "%\t"
             << risk.score << "\t"
             << riskToString(risk.level) << "\t\t"
             << policyToString(decision.policy)
             << endl;
    }

    return 0;
}