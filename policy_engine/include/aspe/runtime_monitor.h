// ---------------------------------------------------------------------------
// Adaptive decision mechanism - runtime estimation of the dynamic inputs.
//
//  * ThreatMonitor   : turns security events reported by the secure IPC
//                      layer into a threat level (EWMA + hysteresis, so the
//                      policy does not oscillate).
//  * TrustManager    : per-process trust = static prior (code signing,
//                      privilege, origin) x Beta reputation with forgetting
//                      (Josang & Ismail, 2002); failures weigh more than
//                      successes, so trust is lost faster than it is regained.
//  * ResourceMonitor : exponentially smoothed CPU / memory utilisation.
// ---------------------------------------------------------------------------
#ifndef ASPE_RUNTIME_MONITOR_H
#define ASPE_RUNTIME_MONITOR_H

#include <array>
#include <map>
#include <string>

#include "aspe/types.h"

namespace aspe {

enum class SecurityEventType {
    AuthenticationFailure,
    IntegrityViolation,
    ReplayDetected,
    AccessDenied,
    AnomalousTraffic
};

std::string toString(SecurityEventType type);

struct SecurityEvent {
    SecurityEventType type = SecurityEventType::AuthenticationFailure;
    int processId = 0;
};

class ThreatMonitor {
public:
    struct Config {
        double smoothing = 0.30;            ///< EWMA weight of the newest period
        double saturationScore = 100.0;     ///< weighted events / period mapped to 1.0
        /// Score needed to enter MEDIUM, HIGH, CRITICAL.
        std::array<double, 3> raiseThresholds = {{0.15, 0.40, 0.70}};
        /// Score below which the level drops back from MEDIUM, HIGH, CRITICAL.
        std::array<double, 3> lowerThresholds = {{0.08, 0.30, 0.55}};
    };

    ThreatMonitor();
    explicit ThreatMonitor(Config config);

    void record(const SecurityEvent& event);
    void record(SecurityEventType type, int count);
    /// Closes the current observation period and updates score and level.
    void endPeriod();

    ThreatLevel level() const { return level_; }
    double score() const { return score_; }

    static double weightOf(SecurityEventType type);

private:
    Config config_;
    double pendingWeight_ = 0.0;
    double score_ = 0.0;
    ThreatLevel level_ = ThreatLevel::Low;
};

class TrustManager {
public:
    struct Config {
        double failurePenalty = 4.0;   ///< one failure counts as this many observations
        double forgetting = 0.98;      ///< decay of old evidence per observation
    };

    TrustManager();
    explicit TrustManager(Config config);

    /// Registers a process with its static prior trust (resets its evidence).
    void registerProcess(int pid, double priorTrust);
    void recordOutcome(int pid, bool success);
    /// Trust in [0, 1]; unknown processes have prior 0.5.
    double trust(int pid) const;
    /// Beta reputation (a + 1) / (a + b + 2) of a process in (0, 1).
    double reputation(int pid) const;

private:
    struct Evidence {
        double prior = 0.5;
        double positive = 0.0;
        double negative = 0.0;
    };
    Config config_;
    std::map<int, Evidence> evidence_;
};

class ResourceMonitor {
public:
    explicit ResourceMonitor(double smoothing = 0.5) : smoothing_(smoothing) {}

    void observe(double cpuPercent, double memoryPercent);
    double cpuPercent() const { return cpu_; }
    double memoryPercent() const { return memory_; }

private:
    double smoothing_;
    bool initialised_ = false;
    double cpu_ = 0.0;
    double memory_ = 0.0;
};

}  // namespace aspe

#endif  // ASPE_RUNTIME_MONITOR_H
