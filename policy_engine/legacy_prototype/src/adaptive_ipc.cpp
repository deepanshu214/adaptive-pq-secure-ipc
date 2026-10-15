#include <iostream>

#include "risk_engine.h"
#include "policy_engine.h"

using namespace std;

int main()
{
    IPCMessage msg;

    msg.id = 1;

    msg.sensitivity = Sensitivity::HIGH;
    msg.processTrust = TrustLevel::LOW;
    msg.threat = ThreatLevel::HIGH;
    msg.criticality = Criticality::HIGH;

    msg.cpuUsage = 40;
    msg.memoryUsage = 50;
    msg.messageSize = 512;

    RiskEngine riskEngine;
    PolicyEngine policyEngine;

    RiskResult risk =
        riskEngine.calculateRisk(msg);

    PolicyDecision decision =
        policyEngine.selectPolicy(msg, risk);

    cout << "====================================\n";
    cout << "       ADAPTIVE IPC ANALYSIS\n";
    cout << "====================================\n\n";

    cout << "IPC MESSAGE\n";
    cout << "-----------\n";
    cout << "Message ID : " << msg.id << "\n";
    cout << "CPU Usage  : " << msg.cpuUsage << "%\n";
    cout << "Memory     : " << msg.memoryUsage << "%\n";
    cout << "Message Size : " << msg.messageSize << " bytes\n\n";

    cout << "RISK ANALYSIS\n";
    cout << "-------------\n";
    cout << "Risk Score : " << risk.score << "/16\n";

    cout << "Risk Level : ";

    switch (risk.level)
    {
        case RiskLevel::LOW:
            cout << "LOW\n";
            break;

        case RiskLevel::MEDIUM:
            cout << "MEDIUM\n";
            break;

        case RiskLevel::HIGH:
            cout << "HIGH\n";
            break;

        case RiskLevel::CRITICAL:
            cout << "CRITICAL\n";
            break;
    }

    cout << "\nPOLICY DECISION\n";
    cout << "---------------\n";

    cout << "Base Policy  : ";

    switch (decision.basePolicy)
    {
        case SecurityPolicy::BASIC:
            cout << "BASIC\n";
            break;

        case SecurityPolicy::CLASSICAL:
            cout << "CLASSICAL\n";
            break;

        case SecurityPolicy::HYBRID:
            cout << "HYBRID\n";
            break;

        case SecurityPolicy::POST_QUANTUM:
            cout << "POST-QUANTUM\n";
            break;
    }

    cout << "Final Policy : ";

    switch (decision.policy)
    {
        case SecurityPolicy::BASIC:
            cout << "BASIC\n";
            break;

        case SecurityPolicy::CLASSICAL:
            cout << "CLASSICAL\n";
            break;

        case SecurityPolicy::HYBRID:
            cout << "HYBRID\n";
            break;

        case SecurityPolicy::POST_QUANTUM:
            cout << "POST-QUANTUM\n";
            break;
    }

    cout << "Adapted      : "
         << (decision.adapted ? "YES" : "NO")
         << "\n";

    cout << "Reason       : "
         << decision.reason
         << "\n";

    cout << "\n====================================\n";

    return 0;
}