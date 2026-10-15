#include "aspe/integration.h"

namespace aspe {

TransmissionReport ModelledSecureChannel::transmit(const IpcMessage& message,
                                                   const SecurityProfile& profile) {
    const CostEstimate cost = estimateCost(profile, message.sizeBytes, platform_);
    TransmissionReport report;
    report.delivered = true;
    report.peerAuthenticated = true;
    report.latencyMicros = cost.latencyMicros;
    report.wireBytes = message.sizeBytes + cost.overheadBytes;
    return report;
}

SecureIpcFramework::SecureIpcFramework(AdaptivePolicyEngine engine, ISecureChannel& channel)
    : engine_(engine), channel_(channel) {}

void SecureIpcFramework::registerProcess(int pid, double priorTrust) {
    trustManager_.registerProcess(pid, priorTrust);
}

void SecureIpcFramework::observeResources(double cpuPercent, double memoryPercent) {
    resourceMonitor_.observe(cpuPercent, memoryPercent);
}

void SecureIpcFramework::reportSecurityEvent(const SecurityEvent& event) {
    threatMonitor_.record(event);
    if (event.processId != 0) trustManager_.recordOutcome(event.processId, false);
}

void SecureIpcFramework::endPeriod() { threatMonitor_.endPeriod(); }

RuntimeContext SecureIpcFramework::currentContext(int senderPid) const {
    RuntimeContext context;
    context.processTrust = trustManager_.trust(senderPid);
    context.threat = threatMonitor_.level();
    context.cpuPercent = resourceMonitor_.cpuPercent();
    context.memoryPercent = resourceMonitor_.memoryPercent();
    return context;
}

SecureIpcFramework::SendResult SecureIpcFramework::send(const IpcMessage& message) {
    SendResult result;
    result.decision = engine_.decide(message, currentContext(message.senderPid));
    result.report = channel_.transmit(message, result.decision.profile);

    trustManager_.recordOutcome(message.senderPid, result.report.peerAuthenticated);
    for (const SecurityEvent& event : result.report.events) reportSecurityEvent(event);
    return result;
}

}  // namespace aspe
