#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H

#include "ipc_message.h"

struct SecurityRequirements {
    bool confidentiality;
    bool integrity;
    bool authentication;
    bool replayProtection;
};

class SecurityAnalyzer {
public:
    SecurityRequirements analyze(const IPCMessage& msg);
};

#endif