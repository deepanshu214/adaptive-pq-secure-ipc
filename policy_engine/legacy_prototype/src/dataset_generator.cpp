#include <iostream>
#include <fstream>
#include <random>
#include "risk_engine.h"

using namespace std;

string sensitivityToString(Sensitivity value) {

    switch (value) {
        case Sensitivity::LOW:
            return "LOW";

        case Sensitivity::MEDIUM:
            return "MEDIUM";

        case Sensitivity::HIGH:
            return "HIGH";

        case Sensitivity::CRITICAL:
            return "CRITICAL";
    }

    return "";
}

string trustToString(TrustLevel value) {

    switch (value) {
        case TrustLevel::LOW:
            return "LOW";

        case TrustLevel::MEDIUM:
            return "MEDIUM";

        case TrustLevel::HIGH:
            return "HIGH";
    }

    return "";
}

string threatToString(ThreatLevel value) {

    switch (value) {
        case ThreatLevel::LOW:
            return "LOW";

        case ThreatLevel::MEDIUM:
            return "MEDIUM";

        case ThreatLevel::HIGH:
            return "HIGH";

        case ThreatLevel::CRITICAL:
            return "CRITICAL";
    }

    return "";
}

string criticalityToString(Criticality value) {

    switch (value) {
        case Criticality::LOW:
            return "LOW";

        case Criticality::MEDIUM:
            return "MEDIUM";

        case Criticality::HIGH:
            return "HIGH";

        case Criticality::CRITICAL:
            return "CRITICAL";
    }

    return "";
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

int main() {

    ofstream file("data/ipc_dataset.csv");

    if (!file.is_open()) {
        cout << "Error opening dataset file.\n";
        return 1;
    }

    file << "ID,Sensitivity,ProcessTrust,Threat,Criticality,"
         << "CPU,Memory,MessageSize,RiskScore,RiskLevel\n";

    random_device rd;
    mt19937 generator(rd());

    uniform_int_distribution<int> sensitivityDist(1, 4);
    uniform_int_distribution<int> trustDist(1, 3);
    uniform_int_distribution<int> threatDist(1, 4);
    uniform_int_distribution<int> criticalityDist(1, 4);

    uniform_int_distribution<int> cpuDist(10, 95);
    uniform_int_distribution<int> memoryDist(10, 95);
    uniform_int_distribution<int> messageSizeDist(64, 4096);

    RiskEngine riskEngine;

    for (int i = 1; i <= 1000; i++) {

        int sensitivityValue = sensitivityDist(generator);
        int trustValue = trustDist(generator);
        int threatValue = threatDist(generator);
        int criticalityValue = criticalityDist(generator);

        int cpu = cpuDist(generator);
        int memory = memoryDist(generator);
        int messageSize = messageSizeDist(generator);

        Sensitivity sensitivity =
            static_cast<Sensitivity>(sensitivityValue - 1);

        TrustLevel trust =
            static_cast<TrustLevel>(trustValue - 1);

        ThreatLevel threat =
            static_cast<ThreatLevel>(threatValue - 1);

        Criticality criticality =
            static_cast<Criticality>(criticalityValue - 1);

        IPCMessage message;

        message.id = i;
        message.message = "Synthetic IPC Message";
        message.sensitivity = sensitivity;
        message.processTrust = trust;
        message.threat = threat;
        message.criticality = criticality;
        message.cpuUsage = cpu;
        message.memoryUsage = memory;
        message.messageSize = messageSize;

        RiskResult result =
            riskEngine.calculateRisk(message);

        file << i << ","
             << sensitivityToString(sensitivity) << ","
             << trustToString(trust) << ","
             << threatToString(threat) << ","
             << criticalityToString(criticality) << ","
             << cpu << ","
             << memory << ","
             << messageSize << ","
             << result.score << ","
             << riskToString(result.level)
             << "\n";
    }

    file.close();

    cout << "Dataset generated successfully.\n";
    cout << "1000 IPC scenarios written to data/ipc_dataset.csv\n";

    return 0;
}