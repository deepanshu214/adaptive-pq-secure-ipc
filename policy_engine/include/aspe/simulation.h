// ---------------------------------------------------------------------------
// Phase 6 - Time-series simulation of an IPC workload.
//
// A set of IPC channels sends messages for a number of one-second periods
// while the scenario changes background load and launches an intrusion
// (a compromised process injecting forged messages). Each strategy runs on
// identical random input. The adaptive strategies see the system only
// through the runtime monitors (threat, trust, smoothed utilisation), i.e.
// with detection lag, while the reference policy uses the ground truth.
//
// Crypto work is served by a fluid queue: capacity per period is
// cores * (1 - background load); queueing delay follows the M/D/1
// approximation below saturation and is bounded by the IPC deadline above
// it, where work that cannot meet the deadline is dropped.
// ---------------------------------------------------------------------------
#ifndef ASPE_SIMULATION_H
#define ASPE_SIMULATION_H

#include <cstdint>
#include <string>
#include <vector>

#include "aspe/crypto_suite.h"
#include "aspe/evaluation.h"
#include "aspe/types.h"

namespace aspe {

struct ScenarioPhase {
    std::string name;
    double startSecond = 0.0;
    double endSecond = 0.0;
    double backgroundCpuPercent = 30.0;
    double backgroundMemoryPercent = 40.0;
    ThreatLevel trueThreat = ThreatLevel::Low;
    double externalEventsPerSecond = 0.0;  ///< attack events seen by detectors
    double forgedFraction = 0.0;           ///< share of the compromised channel's traffic forged
};

struct ChannelSpec {
    std::string archetype;
    int senderPid = 0;
    int receiverPid = 0;
    double messagesPerSecond = 0.0;
    double priorTrust = 0.8;
};

struct SimulationConfig {
    std::uint32_t seed = 2024;
    int durationSeconds = 300;
    double deadlineMs = 50.0;
    double baselineEventsPerSecond = 0.5;  ///< benign noise (e.g. access denials)
    double compromisedTrust = 0.15;        ///< true trust of the compromised process
    int compromisedPid = 3;
    Platform platform = embeddedPlatform();
    std::vector<ScenarioPhase> phases;
    std::vector<ChannelSpec> channels;

    /// Baseline -> peak load -> intrusion -> intrusion under overload -> recovery.
    static SimulationConfig standardScenario();
    const ScenarioPhase& phaseAt(double second) const;
};

struct PeriodRecord {
    int second = 0;
    std::string phase;
    int offered = 0;
    int delivered = 0;
    int dropped = 0;
    double totalCpuPercent = 0.0;
    double cryptoCpuPercent = 0.0;
    double meanLatencyMs = 0.0;
    double meanLevel = 0.0;
    double requirementMet = 0.0;
    int floorViolations = 0;
    ThreatLevel estimatedThreat = ThreatLevel::Low;
    double compromisedTrustEstimate = 0.0;
    double optimizedShare = 0.0;  ///< messages sent with optimized parameters
};

struct SimulationSummary {
    std::string strategy;
    long long offered = 0;
    long long delivered = 0;
    long long dropped = 0;
    double deliveryRatio = 0.0;
    double meanLatencyMs = 0.0;
    double p95LatencyMs = 0.0;
    double p99LatencyMs = 0.0;
    double meanCpuPercent = 0.0;
    double peakCpuPercent = 0.0;
    double meanLevel = 0.0;
    double requirementMet = 0.0;
    double floorViolationRate = 0.0;
    long long criticalFloorViolations = 0;  ///< violations on CRITICAL S/C messages
    double meanOverheadBytes = 0.0;
    double meanStateBytes = 0.0;
};

class Simulator {
public:
    explicit Simulator(SimulationConfig config);

    /// Runs the scenario with one strategy; fills `summary`.
    std::vector<PeriodRecord> run(const PolicyStrategy& strategy,
                                  SimulationSummary& summary) const;

    const SimulationConfig& config() const { return config_; }

private:
    SimulationConfig config_;
};

}  // namespace aspe

#endif  // ASPE_SIMULATION_H
