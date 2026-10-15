#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cctype>

#include "ipc_message.h"
#include "risk_engine.h"
#include "policy_engine.h"

using namespace std;

string cleanValue(string value) {

    value.erase(
        remove(value.begin(), value.end(), '\r'),
        value.end()
    );

    while (!value.empty() && isspace(value.front()))
        value.erase(value.begin());

    while (!value.empty() && isspace(value.back()))
        value.pop_back();

    while (value.size() >= 2 &&
           value[0] == '*' &&
           value[1] == '*') {

        value.erase(0, 2);
    }

    while (!value.empty() && value.back() == '*')
        value.pop_back();

    return value;
}

bool parseSensitivity(
    const string& value,
    Sensitivity& result
) {

    string v = cleanValue(value);

    if (v == "LOW") {
        result = Sensitivity::LOW;
        return true;
    }

    if (v == "MEDIUM") {
        result = Sensitivity::MEDIUM;
        return true;
    }

    if (v == "HIGH") {
        result = Sensitivity::HIGH;
        return true;
    }

    if (v == "CRITICAL") {
        result = Sensitivity::CRITICAL;
        return true;
    }

    return false;
}

bool parseTrust(
    const string& value,
    TrustLevel& result
) {

    string v = cleanValue(value);

    if (v == "HIGH") {
        result = TrustLevel::HIGH;
        return true;
    }

    if (v == "MEDIUM") {
        result = TrustLevel::MEDIUM;
        return true;
    }

    if (v == "LOW") {
        result = TrustLevel::LOW;
        return true;
    }

    return false;
}

bool parseThreat(
    const string& value,
    ThreatLevel& result
) {

    string v = cleanValue(value);

    if (v == "LOW") {
        result = ThreatLevel::LOW;
        return true;
    }

    if (v == "MEDIUM") {
        result = ThreatLevel::MEDIUM;
        return true;
    }

    if (v == "HIGH") {
        result = ThreatLevel::HIGH;
        return true;
    }

    if (v == "CRITICAL") {
        result = ThreatLevel::CRITICAL;
        return true;
    }

    return false;
}

bool parseCriticality(
    const string& value,
    Criticality& result
) {

    string v = cleanValue(value);

    if (v == "LOW") {
        result = Criticality::LOW;
        return true;
    }

    if (v == "MEDIUM") {
        result = Criticality::MEDIUM;
        return true;
    }

    if (v == "HIGH") {
        result = Criticality::HIGH;
        return true;
    }

    if (v == "CRITICAL") {
        result = Criticality::CRITICAL;
        return true;
    }

    return false;
}

int main() {

    ifstream input("data/ipc_dataset.csv");

    if (!input.is_open()) {

        cout << "Error opening dataset.\n";
        return 1;
    }

    string line;

    // Skip header
    getline(input, line);

    RiskEngine riskEngine;
    PolicyEngine policyEngine;

    int total = 0;
    int skipped = 0;

    int basic = 0;
    int classical = 0;
    int hybrid = 0;
    int postQuantum = 0;

    int lowRisk = 0;
    int mediumRisk = 0;
    int highRisk = 0;
    int criticalRisk = 0;

    int resourceConstrained = 0;
    int totalAdaptations = 0;

    int criticalCases = 0;
    int criticalProtected = 0;

    // Policy transition counters

    int basicToClassical = 0;
    int basicToHybrid = 0;
    int basicToPostQuantum = 0;

    int classicalToBasic = 0;
    int classicalToHybrid = 0;
    int classicalToPostQuantum = 0;

    int hybridToBasic = 0;
    int hybridToClassical = 0;
    int hybridToPostQuantum = 0;

    int postQuantumToBasic = 0;
    int postQuantumToClassical = 0;
    int postQuantumToHybrid = 0;

    while (getline(input, line)) {

        if (line.empty())
            continue;

        stringstream ss(line);

        string id;
        string sensitivity;
        string trust;
        string threat;
        string criticality;
        string cpu;
        string memory;
        string messageSize;

        // These may exist in the CSV but are not required
        // because we calculate them ourselves.
        string csvRiskScore;
        string csvRiskLevel;
        string csvPolicy;

        getline(ss, id, ',');
        getline(ss, sensitivity, ',');
        getline(ss, trust, ',');
        getline(ss, threat, ',');
        getline(ss, criticality, ',');
        getline(ss, cpu, ',');
        getline(ss, memory, ',');
        getline(ss, messageSize, ',');

        // Read optional remaining columns
        getline(ss, csvRiskScore, ',');
        getline(ss, csvRiskLevel, ',');
        getline(ss, csvPolicy, ',');

        id = cleanValue(id);
        sensitivity = cleanValue(sensitivity);
        trust = cleanValue(trust);
        threat = cleanValue(threat);
        criticality = cleanValue(criticality);
        cpu = cleanValue(cpu);
        memory = cleanValue(memory);
        messageSize = cleanValue(messageSize);

        IPCMessage msg;

        try {

            msg.id = stoi(id);

            msg.cpuUsage = stod(cpu);

            msg.memoryUsage = stod(memory);

            msg.messageSize = stoi(messageSize);

        }
        catch (...) {

            skipped++;
            continue;
        }

        /*
            Convert CSV security parameters
        */

        if (!parseSensitivity(
                sensitivity,
                msg.sensitivity)) {

            skipped++;
            continue;
        }

        if (!parseTrust(
                trust,
                msg.processTrust)) {

            skipped++;
            continue;
        }

        if (!parseThreat(
                threat,
                msg.threat)) {

            skipped++;
            continue;
        }

        if (!parseCriticality(
                criticality,
                msg.criticality)) {

            skipped++;
            continue;
        }

        /*
            Calculate risk
        */

        RiskResult risk =
            riskEngine.calculateRisk(msg);

        /*
            Select adaptive policy
        */

        PolicyDecision decision =
            policyEngine.selectPolicy(
                msg,
                risk
            );

        total++;

        /*
            FINAL POLICY DISTRIBUTION
        */

        switch (decision.policy) {

            case SecurityPolicy::BASIC:
                basic++;
                break;

            case SecurityPolicy::CLASSICAL:
                classical++;
                break;

            case SecurityPolicy::HYBRID:
                hybrid++;
                break;

            case SecurityPolicy::POST_QUANTUM:
                postQuantum++;
                break;
        }

        /*
            RISK DISTRIBUTION
        */

        if (risk.level == RiskLevel::LOW) {

            lowRisk++;
        }

        else if (risk.level == RiskLevel::MEDIUM) {

            mediumRisk++;
        }

        else if (risk.level == RiskLevel::HIGH) {

            highRisk++;
        }

        else {

            criticalRisk++;
        }

        /*
            RESOURCE PRESSURE
        */

        bool constrained =
            msg.cpuUsage >= 80 ||
            msg.memoryUsage >= 80;

        if (constrained)
            resourceConstrained++;

        /*
            POLICY ADAPTATION
        */

        if (decision.adapted) {

            totalAdaptations++;

            /*
                BASIC transitions
            */

            if (decision.basePolicy ==
                    SecurityPolicy::BASIC &&
                decision.policy ==
                    SecurityPolicy::CLASSICAL) {

                basicToClassical++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::BASIC &&
                decision.policy ==
                    SecurityPolicy::HYBRID) {

                basicToHybrid++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::BASIC &&
                decision.policy ==
                    SecurityPolicy::POST_QUANTUM) {

                basicToPostQuantum++;
            }

            /*
                CLASSICAL transitions
            */

            else if (
                decision.basePolicy ==
                    SecurityPolicy::CLASSICAL &&
                decision.policy ==
                    SecurityPolicy::BASIC) {

                classicalToBasic++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::CLASSICAL &&
                decision.policy ==
                    SecurityPolicy::HYBRID) {

                classicalToHybrid++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::CLASSICAL &&
                decision.policy ==
                    SecurityPolicy::POST_QUANTUM) {

                classicalToPostQuantum++;
            }

            /*
                HYBRID transitions
            */

            else if (
                decision.basePolicy ==
                    SecurityPolicy::HYBRID &&
                decision.policy ==
                    SecurityPolicy::BASIC) {

                hybridToBasic++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::HYBRID &&
                decision.policy ==
                    SecurityPolicy::CLASSICAL) {

                hybridToClassical++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::HYBRID &&
                decision.policy ==
                    SecurityPolicy::POST_QUANTUM) {

                hybridToPostQuantum++;
            }

            /*
                POST-QUANTUM transitions
            */

            else if (
                decision.basePolicy ==
                    SecurityPolicy::POST_QUANTUM &&
                decision.policy ==
                    SecurityPolicy::BASIC) {

                postQuantumToBasic++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::POST_QUANTUM &&
                decision.policy ==
                    SecurityPolicy::CLASSICAL) {

                postQuantumToClassical++;
            }

            else if (
                decision.basePolicy ==
                    SecurityPolicy::POST_QUANTUM &&
                decision.policy ==
                    SecurityPolicy::HYBRID) {

                postQuantumToHybrid++;
            }
        }

        /*
            CRITICAL SECURITY PRESERVATION
        */

        if (risk.level == RiskLevel::CRITICAL) {

            criticalCases++;

            if (decision.policy ==
                SecurityPolicy::POST_QUANTUM) {

                criticalProtected++;
            }
        }
    }

    input.close();

    /*
        Calculate adaptation rate
    */

    double adaptationRate = 0;

    if (total > 0) {

        adaptationRate =
            (double)totalAdaptations /
            total * 100;
    }

    /*
        Calculate critical preservation
    */

    double criticalPreservation = 0;

    if (criticalCases > 0) {

        criticalPreservation =
            (double)criticalProtected /
            criticalCases * 100;
    }

    /*
        Calculate transition total
    */

    int transitionTotal =
        basicToClassical +
        basicToHybrid +
        basicToPostQuantum +

        classicalToBasic +
        classicalToHybrid +
        classicalToPostQuantum +

        hybridToBasic +
        hybridToClassical +
        hybridToPostQuantum +

        postQuantumToBasic +
        postQuantumToClassical +
        postQuantumToHybrid;

    /*
        OUTPUT
    */

    cout << "\n";
    cout << "============================================\n";
    cout << "       ADAPTIVE IPC METRICS\n";
    cout << "============================================\n\n";

    cout << "DATASET VALIDATION\n";
    cout << "------------------\n";

    cout << "Valid records   : "
         << total << "\n";

    cout << "Skipped records : "
         << skipped << "\n\n";

    cout << "FINAL POLICY DISTRIBUTION\n";
    cout << "-------------------------\n";

    cout << "BASIC        : "
         << basic << "\n";

    cout << "CLASSICAL    : "
         << classical << "\n";

    cout << "HYBRID       : "
         << hybrid << "\n";

    cout << "POST-QUANTUM : "
         << postQuantum << "\n\n";

    cout << "RISK DISTRIBUTION\n";
    cout << "-----------------\n";

    cout << "LOW          : "
         << lowRisk << "\n";

    cout << "MEDIUM       : "
         << mediumRisk << "\n";

    cout << "HIGH         : "
         << highRisk << "\n";

    cout << "CRITICAL     : "
         << criticalRisk << "\n\n";

    cout << "RESOURCE ANALYSIS\n";
    cout << "-----------------\n";

    cout << "Resource constrained cases : "
         << resourceConstrained << "\n";

    cout << "Total policy adaptations   : "
         << totalAdaptations << "\n";

    cout << "Overall adaptation rate    : "
         << adaptationRate
         << "%\n\n";

    cout << "POLICY TRANSITIONS\n";
    cout << "------------------\n";

    cout << "BASIC -> CLASSICAL        : "
         << basicToClassical << "\n";

    cout << "BASIC -> HYBRID           : "
         << basicToHybrid << "\n";

    cout << "BASIC -> POST-QUANTUM     : "
         << basicToPostQuantum << "\n";

    cout << "CLASSICAL -> BASIC        : "
         << classicalToBasic << "\n";

    cout << "CLASSICAL -> HYBRID       : "
         << classicalToHybrid << "\n";

    cout << "CLASSICAL -> POST-QUANTUM : "
         << classicalToPostQuantum << "\n";

    cout << "HYBRID -> BASIC           : "
         << hybridToBasic << "\n";

    cout << "HYBRID -> CLASSICAL       : "
         << hybridToClassical << "\n";

    cout << "HYBRID -> POST-QUANTUM    : "
         << hybridToPostQuantum << "\n";

    cout << "POST-QUANTUM -> BASIC     : "
         << postQuantumToBasic << "\n";

    cout << "POST-QUANTUM -> CLASSICAL : "
         << postQuantumToClassical << "\n";

    cout << "POST-QUANTUM -> HYBRID    : "
         << postQuantumToHybrid << "\n";

    cout << "\nTransition total          : "
         << transitionTotal << "\n";

    cout << "Adaptation count          : "
         << totalAdaptations << "\n\n";

    cout << "CRITICAL SECURITY\n";
    cout << "-----------------\n";

    cout << "Critical cases             : "
         << criticalCases << "\n";

    cout << "Critical cases protected   : "
         << criticalProtected << "\n";

    cout << "Security preservation      : "
         << criticalPreservation
         << "%\n\n";

    cout << "============================================\n";

    return 0;
}