#ifndef IPC_MESSAGE_H
#define IPC_MESSAGE_H

#include <string>

enum class Sensitivity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class TrustLevel {
    LOW,
    MEDIUM,
    HIGH
};

enum class ThreatLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class Criticality {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct IPCMessage {
    int id;
    std::string message;
    Sensitivity sensitivity;
    TrustLevel processTrust;
    ThreatLevel threat;
    Criticality criticality;
    double cpuUsage;
    double memoryUsage;
    int messageSize;
};

#endif