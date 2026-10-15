#include "aspe/runtime_monitor.h"

#include <algorithm>

#include "aspe/util.h"

namespace aspe {

std::string toString(SecurityEventType type) {
    switch (type) {
        case SecurityEventType::AuthenticationFailure: return "AUTH_FAILURE";
        case SecurityEventType::IntegrityViolation: return "INTEGRITY_VIOLATION";
        case SecurityEventType::ReplayDetected: return "REPLAY_DETECTED";
        case SecurityEventType::AccessDenied: return "ACCESS_DENIED";
        case SecurityEventType::AnomalousTraffic: return "ANOMALOUS_TRAFFIC";
    }
    return "UNKNOWN";
}

// ----- ThreatMonitor ---------------------------------------------------------------

ThreatMonitor::ThreatMonitor() : ThreatMonitor(Config()) {}

ThreatMonitor::ThreatMonitor(Config config) : config_(config) {}

double ThreatMonitor::weightOf(SecurityEventType type) {
    switch (type) {
        case SecurityEventType::AuthenticationFailure: return 1.0;
        case SecurityEventType::IntegrityViolation: return 1.5;
        case SecurityEventType::ReplayDetected: return 1.5;
        case SecurityEventType::AccessDenied: return 0.5;
        case SecurityEventType::AnomalousTraffic: return 0.75;
    }
    return 1.0;
}

void ThreatMonitor::record(const SecurityEvent& event) { pendingWeight_ += weightOf(event.type); }

void ThreatMonitor::record(SecurityEventType type, int count) {
    if (count > 0) pendingWeight_ += weightOf(type) * count;
}

void ThreatMonitor::endPeriod() {
    const double intensity = util::clamp01(pendingWeight_ / config_.saturationScore);
    pendingWeight_ = 0.0;
    score_ = (1.0 - config_.smoothing) * score_ + config_.smoothing * intensity;

    // Hysteresis: raise as far as the score allows, lower one step at a time
    // only when the score falls below the (lower) release threshold.
    int level = ordinal(level_);
    while (level < 3 && score_ >= config_.raiseThresholds[level]) ++level;
    while (level > 0 && score_ < config_.lowerThresholds[level - 1]) --level;
    level_ = static_cast<ThreatLevel>(level);
}

// ----- TrustManager -------------------------------------------------------------------

TrustManager::TrustManager() : TrustManager(Config()) {}

TrustManager::TrustManager(Config config) : config_(config) {}

void TrustManager::registerProcess(int pid, double priorTrust) {
    Evidence evidence;
    evidence.prior = util::clamp01(priorTrust);
    evidence_[pid] = evidence;
}

void TrustManager::recordOutcome(int pid, bool success) {
    auto it = evidence_.find(pid);
    if (it == evidence_.end()) it = evidence_.insert(std::make_pair(pid, Evidence())).first;
    Evidence& e = it->second;
    e.positive = config_.forgetting * e.positive + (success ? 1.0 : 0.0);
    e.negative = config_.forgetting * e.negative + (success ? 0.0 : config_.failurePenalty);
}

double TrustManager::reputation(int pid) const {
    const auto it = evidence_.find(pid);
    if (it == evidence_.end()) return 0.5;
    const Evidence& e = it->second;
    return (e.positive + 1.0) / (e.positive + e.negative + 2.0);
}

double TrustManager::trust(int pid) const {
    const auto it = evidence_.find(pid);
    const double prior = it == evidence_.end() ? 0.5 : it->second.prior;
    if (it == evidence_.end()) return prior;
    // Without negative evidence the trust converges to the prior; the
    // reputation can only lower it (a process cannot earn more trust than its
    // static attributes justify).
    const double r = reputation(pid);
    const double cleanReputation = (it->second.positive + 1.0) / (it->second.positive + 2.0);
    return util::clamp01(prior * r / cleanReputation);
}

// ----- ResourceMonitor -----------------------------------------------------------------

void ResourceMonitor::observe(double cpuPercent, double memoryPercent) {
    if (!initialised_) {
        cpu_ = cpuPercent;
        memory_ = memoryPercent;
        initialised_ = true;
        return;
    }
    cpu_ = (1.0 - smoothing_) * cpu_ + smoothing_ * cpuPercent;
    memory_ = (1.0 - smoothing_) * memory_ + smoothing_ * memoryPercent;
}

}  // namespace aspe
