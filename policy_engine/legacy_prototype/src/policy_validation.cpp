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

void runTest(
    string name,
    Sensitivity sensitivity,
    TrustLevel trust,
    ThreatLevel threat,
    Criticality criticality,
    double cpu,
    double memory
) {

    IPCMessage msg;

    msg.sensitivity = sensitivity;
    msg.processTrust = trust;
    msg.threat = threat;
    msg.criticality = criticality;

    msg.cpuUsage = cpu;
    msg.memoryUsage = memory;

    RiskEngine riskEngine;
    PolicyEngine policyEngine;

    RiskResult risk =
        riskEngine.calculateRisk(msg);

    PolicyDecision decision =
        policyEngine.selectPolicy(msg, risk);

    cout << "\n" << name << "\n";
    cout << "----------------------------------------\n";

    cout << "Risk Score    : "
         << risk.score << "/16\n";

    cout << "Risk Level    : "
         << riskToString(risk.level) << "\n";

    cout << "Base Policy   : "
         << policyToString(decision.basePolicy) << "\n";

    cout << "Final Policy  : "
         << policyToString(decision.policy) << "\n";

    cout << "Adapted       : "
         << (decision.adapted ? "YES" : "NO") << "\n";

    cout << "Reason        : "
         << decision.reason << "\n";
}

int main() {

    cout << "========================================\n";
    cout << "       POLICY ENGINE VALIDATION\n";
    cout << "========================================\n";

    runTest(
        "TEST 1: LOW RISK",
        Sensitivity::LOW,
        TrustLevel::HIGH,
        ThreatLevel::LOW,
        Criticality::LOW,
        30,
        40
    );

    runTest(
        "TEST 2: MEDIUM RISK",
        Sensitivity::MEDIUM,
        TrustLevel::HIGH,
        ThreatLevel::MEDIUM,
        Criticality::MEDIUM,
        40,
        50
    );

    runTest(
        "TEST 3: HIGH RISK",
        Sensitivity::HIGH,
        TrustLevel::HIGH,
        ThreatLevel::MEDIUM,
        Criticality::CRITICAL,
        40,
        50
    );

    runTest(
        "TEST 4: HIGH RISK + RESOURCE CONSTRAINT",
        Sensitivity::HIGH,
        TrustLevel::HIGH,
        ThreatLevel::MEDIUM,
        Criticality::CRITICAL,
        90,
        90
    );

    runTest(
        "TEST 5: CRITICAL THREAT",
        Sensitivity::HIGH,
        TrustLevel::LOW,
        ThreatLevel::CRITICAL,
        Criticality::MEDIUM,
        40,
        50
    );

    runTest(
        "TEST 6: CRITICAL + RESOURCE CONSTRAINT",
        Sensitivity::CRITICAL,
        TrustLevel::LOW,
        ThreatLevel::CRITICAL,
        Criticality::CRITICAL,
        95,
        95
    );

    return 0;
}