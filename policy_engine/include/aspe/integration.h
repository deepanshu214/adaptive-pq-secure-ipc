// ---------------------------------------------------------------------------
// Integration contract with the Secure IPC & PQC engine (partner project).
//
//   +------------------------ this project ------------------------+
//   | IpcMessage --> AdaptivePolicyEngine --> SecurityProfile       |
//   |                     ^                        |                |
//   |  ThreatMonitor / TrustManager / ResourceMonitor                |
//   +---------------------^--------------------------+---------------+
//                         | SecurityEvents           v
//   +---------------------- partner project -------------------------+
//   | ISecureChannel::transmit(message, profile)                     |
//   |   authentication, encryption, integrity, replay protection,    |
//   |   classical / hybrid / post-quantum suites                     |
//   +----------------------------------------------------------------+
//
// The partner implements ISecureChannel. Until then ModelledSecureChannel
// stands in for it, using the analytical cost model of crypto_suite.h.
// ---------------------------------------------------------------------------
#ifndef ASPE_INTEGRATION_H
#define ASPE_INTEGRATION_H

#include <cstdint>
#include <string>
#include <vector>

#include "aspe/crypto_suite.h"
#include "aspe/policy_engine.h"
#include "aspe/runtime_monitor.h"
#include "aspe/types.h"

namespace aspe {

/// What the secure channel reports back after sending one message.
struct TransmissionReport {
    bool delivered = true;
    bool peerAuthenticated = true;     ///< false -> sender's trust is reduced
    double latencyMicros = 0.0;
    std::uint32_t wireBytes = 0;
    std::vector<SecurityEvent> events; ///< detected attacks (replay, tampering, ...)
};

/// Interface implemented by the Secure IPC & PQC engine.
class ISecureChannel {
public:
    virtual ~ISecureChannel() = default;
    virtual std::string name() const = 0;
    virtual TransmissionReport transmit(const IpcMessage& message,
                                        const SecurityProfile& profile) = 0;
};

/// Stand-in channel based on the analytical cost model.
class ModelledSecureChannel : public ISecureChannel {
public:
    explicit ModelledSecureChannel(Platform platform = embeddedPlatform())
        : platform_(platform) {}

    std::string name() const override { return "modelled channel (" + platform_.name + ")"; }
    TransmissionReport transmit(const IpcMessage& message,
                                const SecurityProfile& profile) override;

private:
    Platform platform_;
};

/// Facade that wires the policy engine, the runtime monitors and a secure
/// channel together. This is the single entry point used after integration.
class SecureIpcFramework {
public:
    SecureIpcFramework(AdaptivePolicyEngine engine, ISecureChannel& channel);

    void registerProcess(int pid, double priorTrust);
    /// Feeds the latest system utilisation (smoothed internally).
    void observeResources(double cpuPercent, double memoryPercent);
    /// Security event from an external detector (IDS, kernel audit, ...).
    void reportSecurityEvent(const SecurityEvent& event);
    /// Closes an observation period of the threat monitor (e.g. every second).
    void endPeriod();

    struct SendResult {
        PolicyDecision decision;
        TransmissionReport report;
    };

    /// Selects a policy for the message from the current runtime state, sends
    /// it through the channel and feeds the outcome back into the monitors.
    SendResult send(const IpcMessage& message);

    RuntimeContext currentContext(int senderPid) const;
    const ThreatMonitor& threatMonitor() const { return threatMonitor_; }
    const TrustManager& trustManager() const { return trustManager_; }
    const AdaptivePolicyEngine& engine() const { return engine_; }

private:
    AdaptivePolicyEngine engine_;
    ISecureChannel& channel_;
    ThreatMonitor threatMonitor_;
    TrustManager trustManager_;
    ResourceMonitor resourceMonitor_;
};

}  // namespace aspe

#endif  // ASPE_INTEGRATION_H
