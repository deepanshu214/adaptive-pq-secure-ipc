#include "aspe/simulation.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

#include "aspe/dataset.h"
#include "aspe/runtime_monitor.h"
#include "aspe/util.h"

namespace aspe {

SimulationConfig SimulationConfig::standardScenario() {
    SimulationConfig c;
    c.phases = {
        {"Baseline", 0, 60, 30, 45, ThreatLevel::Low, 0.0, 0.0},
        {"Peak load", 60, 120, 78, 70, ThreatLevel::Low, 0.0, 0.0},
        {"Intrusion", 120, 180, 40, 50, ThreatLevel::High, 10.0, 0.15},
        {"Intrusion + overload", 180, 240, 88, 80, ThreatLevel::Critical, 30.0, 0.30},
        {"Recovery", 240, 300, 30, 45, ThreatLevel::Low, 0.0, 0.0},
    };
    c.channels = {
        {"Status", 1, 20, 200, 0.90},      {"Heartbeat", 2, 20, 100, 0.90},
        {"Telemetry", 3, 21, 300, 0.85},   {"Gaze", 4, 22, 150, 0.80},
        {"Configuration", 5, 23, 10, 0.75}, {"Profile", 6, 24, 40, 0.60},
        {"Credential", 7, 25, 15, 0.70},   {"Payment", 8, 26, 10, 0.65},
        {"Emergency", 9, 27, 8, 0.60},     {"Alert", 10, 27, 30, 0.55},
        {"KeyMaterial", 11, 28, 2, 0.90},
    };
    c.compromisedPid = 3;  // the telemetry agent is taken over during the intrusion
    return c;
}

const ScenarioPhase& SimulationConfig::phaseAt(double second) const {
    for (const ScenarioPhase& p : phases) {
        if (second >= p.startSecond && second < p.endSecond) return p;
    }
    return phases.back();
}

Simulator::Simulator(SimulationConfig config) : config_(std::move(config)) {
    if (config_.phases.empty() || config_.channels.empty() || config_.durationSeconds <= 0) {
        throw std::invalid_argument("simulation needs phases, channels and a positive duration");
    }
    for (const ChannelSpec& ch : config_.channels) {
        MessageArchetype unused;
        if (!findArchetype(ch.archetype, unused)) {
            throw std::invalid_argument("unknown message archetype: " + ch.archetype);
        }
    }
}

std::vector<PeriodRecord> Simulator::run(const PolicyStrategy& strategy,
                                         SimulationSummary& summary) const {
    // Common random numbers: every strategy sees exactly the same workload.
    util::Random random(config_.seed);
    ThreatMonitor threatMonitor;
    TrustManager trustManager;
    ResourceMonitor resourceMonitor;
    for (const ChannelSpec& ch : config_.channels) {
        trustManager.registerProcess(ch.senderPid, ch.priorTrust);
    }

    std::vector<MessageArchetype> archetypes;
    for (const ChannelSpec& ch : config_.channels) {
        MessageArchetype a;
        findArchetype(ch.archetype, a);
        archetypes.push_back(a);
    }

    const Platform& platform = config_.platform;
    const double deadlineMicros = config_.deadlineMs * 1000.0;
    double backlogMicros = 0.0;
    double lastTotalCpu = config_.phases.front().backgroundCpuPercent;
    std::uint64_t nextId = 1;

    std::vector<PeriodRecord> periods;
    std::vector<double> latencies;
    summary = SimulationSummary();
    summary.strategy = strategy.name();
    double levelSum = 0.0, overheadSum = 0.0, stateSum = 0.0, cpuSum = 0.0;
    long long metCount = 0, violationCount = 0;

    for (int second = 0; second < config_.durationSeconds; ++second) {
        const ScenarioPhase& phase = config_.phaseAt(second);
        const bool underAttack = phase.forgedFraction > 0.0 || phase.externalEventsPerSecond > 0.0;
        resourceMonitor.observe(lastTotalCpu, phase.backgroundMemoryPercent);

        struct Pending {
            double cpuMicros;
            int level;
        };
        std::vector<Pending> work;
        PeriodRecord rec;
        rec.second = second;
        rec.phase = phase.name;
        int optimized = 0, met = 0;

        for (std::size_t c = 0; c < config_.channels.size(); ++c) {
            const ChannelSpec& ch = config_.channels[c];
            const int count = random.stochasticRound(ch.messagesPerSecond);
            const bool compromised = underAttack && ch.senderPid == config_.compromisedPid;

            for (int i = 0; i < count; ++i) {
                const IpcMessage msg = sampleMessage(archetypes[c], nextId++, ch.senderPid,
                                                     ch.receiverPid, 0.25, random);
                // What the engine can observe.
                RuntimeContext observed;
                observed.processTrust = trustManager.trust(ch.senderPid);
                observed.threat = threatMonitor.level();
                observed.cpuPercent = resourceMonitor.cpuPercent();
                observed.memoryPercent = resourceMonitor.memoryPercent();
                // Ground truth used by the reference policy.
                RuntimeContext truth = observed;
                truth.processTrust = compromised ? config_.compromisedTrust : ch.priorTrust;
                truth.threat = phase.trueThreat;

                const SecurityProfile profile = strategy.select(msg, observed);
                const CostEstimate cost = estimateCost(profile, msg.sizeBytes, platform);
                const SecurityLevel required = referenceRequiredLevel(msg, truth);
                const SecurityLevel floor = referenceFloor(msg, truth, required);
                const bool criticalAsset = msg.sensitivity == Sensitivity::Critical ||
                                           msg.criticality == Criticality::Critical;

                if (toInt(profile.level) >= toInt(required)) ++met;
                if (toInt(profile.level) < toInt(floor)) {
                    ++rec.floorViolations;
                    if (criticalAsset) ++summary.criticalFloorViolations;
                }
                if (profile.mode == ProtectionMode::Optimized) ++optimized;

                work.push_back({cost.cpuMicros, toInt(profile.level)});
                levelSum += toInt(profile.level);
                overheadSum += cost.overheadBytes;
                stateSum += cost.memoryBytes;

                // Outcome reported by the secure channel: forged messages from
                // the compromised process fail authentication.
                const bool forged = compromised && random.bernoulli(phase.forgedFraction);
                trustManager.recordOutcome(ch.senderPid, !forged);
                if (forged) threatMonitor.record(SecurityEventType::AuthenticationFailure, 1);
            }
        }

        // External detector events (attack) and benign noise.
        const int attackEvents = random.stochasticRound(phase.externalEventsPerSecond);
        for (int e = 0; e < attackEvents; ++e) {
            SecurityEvent event;
            event.type = random.bernoulli(0.5) ? SecurityEventType::ReplayDetected
                                               : SecurityEventType::IntegrityViolation;
            event.processId = config_.compromisedPid;
            threatMonitor.record(event);
            trustManager.recordOutcome(event.processId, false);
        }
        threatMonitor.record(SecurityEventType::AccessDenied,
                             random.stochasticRound(config_.baselineEventsPerSecond));
        threatMonitor.endPeriod();

        // ----- Fluid queue model for this period --------------------------------
        const double background = phase.backgroundCpuPercent / 100.0;
        const double serviceRate = platform.cryptoCores * (1.0 - background);  // core-us per us
        const double capacity = serviceRate * 1e6;
        double demand = 0.0;
        for (const Pending& p : work) demand += p.cpuMicros;
        const double total = backlogMicros + demand;
        const int n = static_cast<int>(work.size());

        double served = 0.0, waitMicros = 0.0, droppedWork = 0.0;
        if (total <= capacity) {
            served = total;
            const double rho = std::min(0.999, total / capacity);
            const double meanService = n > 0 ? demand / n / serviceRate : 0.0;
            waitMicros = backlogMicros / serviceRate + rho * meanService / (2.0 * (1.0 - rho));
            backlogMicros = 0.0;
        } else {
            served = capacity;
            const double excess = total - capacity;
            const double maxBacklog = serviceRate * deadlineMicros;
            droppedWork = std::max(0.0, excess - maxBacklog);
            backlogMicros = excess - droppedWork;
            waitMicros = backlogMicros / serviceRate;
        }
        waitMicros = std::min(waitMicros, deadlineMicros);

        const double dropShare = demand > 0.0 ? std::min(1.0, droppedWork / demand) : 0.0;
        rec.offered = n;
        rec.dropped = static_cast<int>(std::lround(dropShare * n));
        rec.delivered = n - rec.dropped;

        double latencySum = 0.0;
        const int deliveredSamples = rec.delivered;
        for (int i = 0; i < deliveredSamples && i < n; ++i) {
            const double latency = work[i].cpuMicros / (1.0 - background) + waitMicros;
            latencies.push_back(latency / 1000.0);
            latencySum += latency / 1000.0;
        }
        double levels = 0.0;
        for (const Pending& p : work) levels += p.level;

        rec.cryptoCpuPercent = 100.0 * served / (platform.cryptoCores * 1e6);
        rec.totalCpuPercent = std::min(100.0, phase.backgroundCpuPercent + rec.cryptoCpuPercent);
        rec.meanLatencyMs = deliveredSamples > 0 ? latencySum / deliveredSamples : 0.0;
        rec.meanLevel = n > 0 ? levels / n : 0.0;
        rec.requirementMet = n > 0 ? static_cast<double>(met) / n : 1.0;
        rec.estimatedThreat = threatMonitor.level();
        rec.compromisedTrustEstimate = trustManager.trust(config_.compromisedPid);
        rec.optimizedShare = n > 0 ? static_cast<double>(optimized) / n : 0.0;
        periods.push_back(rec);

        lastTotalCpu = rec.totalCpuPercent;
        summary.offered += rec.offered;
        summary.delivered += rec.delivered;
        summary.dropped += rec.dropped;
        summary.peakCpuPercent = std::max(summary.peakCpuPercent, rec.totalCpuPercent);
        cpuSum += rec.totalCpuPercent;
        metCount += met;
        violationCount += rec.floorViolations;
    }

    const double offered = static_cast<double>(std::max<long long>(1, summary.offered));
    summary.deliveryRatio = static_cast<double>(summary.delivered) / offered;
    summary.meanLatencyMs = util::mean(latencies);
    summary.p95LatencyMs = util::percentile(latencies, 95.0);
    summary.p99LatencyMs = util::percentile(latencies, 99.0);
    summary.meanCpuPercent = cpuSum / config_.durationSeconds;
    summary.meanLevel = levelSum / offered;
    summary.requirementMet = static_cast<double>(metCount) / offered;
    summary.floorViolationRate = static_cast<double>(violationCount) / offered;
    summary.meanOverheadBytes = overheadSum / offered;
    summary.meanStateBytes = stateSum / offered;
    return periods;
}

}  // namespace aspe
