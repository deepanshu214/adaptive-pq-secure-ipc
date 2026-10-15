#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "ipc_message.h"
#include "risk_engine.h"
#include "policy_engine.h"

using namespace std;

Sensitivity parseSensitivity(const string& value) {

    if (value == "LOW")
        return Sensitivity::LOW;

    if (value == "MEDIUM")
        return Sensitivity::MEDIUM;

    if (value == "HIGH")
        return Sensitivity::HIGH;

    return Sensitivity::CRITICAL;
}

TrustLevel parseTrust(const string& value) {

    if (value == "LOW")
        return TrustLevel::LOW;

    if (value == "MEDIUM")
        return TrustLevel::MEDIUM;

    return TrustLevel::HIGH;
}

ThreatLevel parseThreat(const string& value) {

    if (value == "LOW")
        return ThreatLevel::LOW;

    if (value == "MEDIUM")
        return ThreatLevel::MEDIUM;

    if (value == "HIGH")
        return ThreatLevel::HIGH;

    return ThreatLevel::CRITICAL;
}

Criticality parseCriticality(const string& value) {

    if (value == "LOW")
        return Criticality::LOW;

    if (value == "MEDIUM")
        return Criticality::MEDIUM;

    if (value == "HIGH")
        return Criticality::HIGH;

    return Criticality::CRITICAL;
}

string riskToString(RiskLevel value) {

    switch (value) {

        case RiskLevel::LOW:
            return "LOW";

        case RiskLevel::MEDIUM:
            return "MEDIUM";

        case RiskLevel::HIGH:
            return "HIGH";

        case RiskLevel::CRITICAL:
            return "CRITICAL";
    }

    return "";
}

string policyToString(SecurityPolicy value) {

    switch (value) {

        case SecurityPolicy::BASIC:
            return "BASIC";

        case SecurityPolicy::CLASSICAL:
            return "CLASSICAL";

        case SecurityPolicy::HYBRID:
            return "HYBRID";

        case SecurityPolicy::POST_QUANTUM:
            return "POST_QUANTUM";
    }

    return "";
}

int main() {

    ifstream input("data/ipc_dataset.csv");

    if (!input.is_open()) {

        cout << "Error: Could not open ipc_dataset.csv\n";

        return 1;
    }

    ofstream output("data/ipc_policy_results.csv");

    if (!output.is_open()) {

        cout << "Error: Could not create output file\n";

        return 1;
    }

    string line;

    getline(input, line);

    output << "ID,Sensitivity,ProcessTrust,Threat,Criticality,"
           << "CPU,Memory,MessageSize,RiskScore,RiskLevel,Policy\n";

    RiskEngine riskEngine;
    PolicyEngine policyEngine;

    int basicCount = 0;
    int classicalCount = 0;
    int hybridCount = 0;
    int postQuantumCount = 0;

    int processed = 0;

    while (getline(input, line)) {

        stringstream ss(line);

        string id;
        string sensitivity;
        string trust;
        string threat;
        string criticality;
        string cpu;
        string memory;
        string messageSize;
        string oldRiskScore;
        string oldRiskLevel;

        getline(ss, id, ',');
        getline(ss, sensitivity, ',');
        getline(ss, trust, ',');
        getline(ss, threat, ',');
        getline(ss, criticality, ',');
        getline(ss, cpu, ',');
        getline(ss, memory, ',');
        getline(ss, messageSize, ',');
        getline(ss, oldRiskScore, ',');
        getline(ss, oldRiskLevel, ',');

        IPCMessage message;

        message.id = stoi(id);

        message.message = "Synthetic IPC Message";

        message.sensitivity =
            parseSensitivity(sensitivity);

        message.processTrust =
            parseTrust(trust);

        message.threat =
            parseThreat(threat);

        message.criticality =
            parseCriticality(criticality);

        message.cpuUsage =
            stod(cpu);

        message.memoryUsage =
            stod(memory);

        message.messageSize =
            stoi(messageSize);

        RiskResult risk =
            riskEngine.calculateRisk(message);

        PolicyDecision decision =
            policyEngine.selectPolicy(message, risk);

        output << message.id << ","
               << sensitivity << ","
               << trust << ","
               << threat << ","
               << criticality << ","
               << message.cpuUsage << ","
               << message.memoryUsage << ","
               << message.messageSize << ","
               << risk.score << ","
               << riskToString(risk.level) << ","
               << policyToString(decision.policy)
               << "\n";

        switch (decision.policy) {

            case SecurityPolicy::BASIC:
                basicCount++;
                break;

            case SecurityPolicy::CLASSICAL:
                classicalCount++;
                break;

            case SecurityPolicy::HYBRID:
                hybridCount++;
                break;

            case SecurityPolicy::POST_QUANTUM:
                postQuantumCount++;
                break;
        }

        processed++;
    }

    input.close();
    output.close();

    cout << "\n===== POLICY EVALUATION =====\n\n";

    cout << "Records processed: "
         << processed
         << "\n\n";

    cout << "BASIC: "
         << basicCount
         << "\n";

    cout << "CLASSICAL: "
         << classicalCount
         << "\n";

    cout << "HYBRID: "
         << hybridCount
         << "\n";

    cout << "POST-QUANTUM: "
         << postQuantumCount
         << "\n\n";

    cout << "Results saved to:\n";
    cout << "data/ipc_policy_results.csv\n";

    return 0;
}