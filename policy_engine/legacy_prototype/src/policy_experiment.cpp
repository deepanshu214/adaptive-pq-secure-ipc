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

void runScenario(
    string name,
    IPCMessage msg,
    RiskEngine& riskEngine,
    PolicyEngine& policyEngine
) {

    RiskResult risk =
        riskEngine.calculateRisk(msg);

    PolicyDecision decision =
        policyEngine.selectPolicy(msg, risk);

    cout << name << "\n";

    cout << "Risk Score : "
         << risk.score << "/16\n";

    cout << "Risk Level : "
         << riskToString(risk.level) << "\n";

    cout << "CPU        : "
         << msg.cpuUsage << "%\n";

    cout << "Memory     : "
         << msg.memoryUsage << "%\n";

    cout << "Policy     : "
         << policyToString(decision.policy) << "\n";

    cout << "Reason     : "
         << decision.reason << "\n";

    cout << "----------------------------------------\n";
}

int main() {

    RiskEngine riskEngine;
    PolicyEngine policyEngine;

    cout << "===== ADAPTIVE SECURITY POLICY EXPERIMENT =====\n\n";

    IPCMessage msg;

    msg.id = 1;
    msg.messageSize = 1024;

   

    msg.sensitivity = Sensitivity::LOW;
    msg.processTrust = TrustLevel::HIGH;
    msg.threat = ThreatLevel::LOW;
    msg.criticality = Criticality::LOW;

    msg.cpuUsage = 30;
    msg.memoryUsage = 40;

    runScenario(
        "SCENARIO 1: LOW RISK",
        msg,
        riskEngine,
        policyEngine
    );

   
    msg.sensitivity = Sensitivity::MEDIUM;
    msg.processTrust = TrustLevel::HIGH;
    msg.threat = ThreatLevel::MEDIUM;
    msg.criticality = Criticality::MEDIUM;

    msg.cpuUsage = 40;
    msg.memoryUsage = 50;

    runScenario(
        "SCENARIO 2: MEDIUM RISK",
        msg,
        riskEngine,
        policyEngine
    );

 

    msg.sensitivity = Sensitivity::HIGH;
    msg.processTrust = TrustLevel::MEDIUM;
    msg.threat = ThreatLevel::HIGH;
    msg.criticality = Criticality::HIGH;

    msg.cpuUsage = 40;
    msg.memoryUsage = 50;

    runScenario(
        "SCENARIO 3: HIGH RISK",
        msg,
        riskEngine,
        policyEngine
    );

    msg.sensitivity = Sensitivity::CRITICAL;
    msg.processTrust = TrustLevel::LOW;
    msg.threat = ThreatLevel::CRITICAL;
    msg.criticality = Criticality::CRITICAL;

    msg.cpuUsage = 90;
    msg.memoryUsage = 90;

    runScenario(
        "SCENARIO 4: CRITICAL RISK",
        msg,
        riskEngine,
        policyEngine
    );

    return 0;
}