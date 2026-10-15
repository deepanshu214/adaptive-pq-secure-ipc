#include <iostream>
#include "security_analyzer.h"
#include "risk_engine.h"
#include "policy_engine.h"

using namespace std;

string status(bool value) {
    return value ? "REQUIRED" : "NOT REQUIRED";
}

int main() {

    IPCMessage msg;

    msg.id = 1;
    msg.message = "User profile";

   msg.sensitivity = Sensitivity::HIGH;
msg.processTrust = TrustLevel::MEDIUM;
msg.threat = ThreatLevel::HIGH;
msg.criticality = Criticality::HIGH;

msg.cpuUsage = 90;
msg.memoryUsage = 90;
    SecurityAnalyzer analyzer;

    SecurityRequirements result =
        analyzer.analyze(msg);

    RiskEngine riskEngine;

    RiskResult risk =
        riskEngine.calculateRisk(msg);

    PolicyEngine policyEngine;

    PolicyDecision decision =
        policyEngine.selectPolicy(msg, risk);

    cout << "===== IPC SECURITY ANALYSIS =====\n\n";

    cout << "Message: "
         << msg.message << endl;

    cout << "CPU Usage: "
         << msg.cpuUsage << "%\n";

    cout << "Memory Usage: "
         << msg.memoryUsage << "%\n";

    cout << "Message Size: "
         << msg.messageSize << " bytes\n\n";

    cout << "Security Requirements:\n";

    cout << "Confidentiality: "
         << status(result.confidentiality)
         << endl;

    cout << "Integrity: "
         << status(result.integrity)
         << endl;

    cout << "Authentication: "
         << status(result.authentication)
         << endl;

    cout << "Replay Protection: "
         << status(result.replayProtection)
         << endl;

    cout << "\nRisk Score: "
         << risk.score << "/16"
         << endl;

    cout << "Risk Level: ";

    switch (risk.level) {

        case RiskLevel::LOW:
            cout << "LOW";
            break;

        case RiskLevel::MEDIUM:
            cout << "MEDIUM";
            break;

        case RiskLevel::HIGH:
            cout << "HIGH";
            break;

        case RiskLevel::CRITICAL:
            cout << "CRITICAL";
            break;
    }

   cout << "Base Policy: ";

switch (decision.basePolicy) {

case SecurityPolicy::BASIC:
    cout << "BASIC";
    break;

case SecurityPolicy::CLASSICAL:
    cout << "CLASSICAL";
    break;

case SecurityPolicy::HYBRID:
    cout << "HYBRID";
    break;

case SecurityPolicy::POST_QUANTUM:
    cout << "POST-QUANTUM";
    break;
}

cout << endl;

cout << "Adapted: "
     << (decision.adapted ? "YES" : "NO")
     << endl;
    return 0;
}