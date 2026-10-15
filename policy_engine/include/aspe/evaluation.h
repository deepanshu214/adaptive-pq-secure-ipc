// ---------------------------------------------------------------------------
// Phase 4 calibration and Phase 6 evaluation.
//
//  * PolicyStrategy        : static (one level for every message) or adaptive
//  * evaluateClassifier    : accuracy / confusion matrix vs. reference policy
//  * calibrate             : experimental determination of the risk-model
//                            weights and thresholds (random search + local
//                            refinement, asymmetric cost, train/test split)
//  * evaluateStrategy      : security and performance metrics of a strategy
//  * resourceSweep         : policy chosen as resource pressure grows
// ---------------------------------------------------------------------------
#ifndef ASPE_EVALUATION_H
#define ASPE_EVALUATION_H

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "aspe/classifier.h"
#include "aspe/crypto_suite.h"
#include "aspe/dataset.h"
#include "aspe/policy_engine.h"

namespace aspe {

// ----- Strategies ---------------------------------------------------------------------

class PolicyStrategy {
public:
    virtual ~PolicyStrategy() = default;
    virtual std::string name() const = 0;
    virtual SecurityProfile select(const IpcMessage& message,
                                   const RuntimeContext& context) const = 0;
};

/// Uniform security: the same suite for every message.
class StaticPolicy : public PolicyStrategy {
public:
    explicit StaticPolicy(SecurityLevel level) : level_(level) {}
    std::string name() const override;
    SecurityProfile select(const IpcMessage&, const RuntimeContext&) const override;

private:
    SecurityLevel level_;
};

/// The adaptive policy engine (with or without Phase 5 resource adaptation).
class AdaptivePolicy : public PolicyStrategy {
public:
    AdaptivePolicy(std::string name, AdaptivePolicyEngine engine)
        : name_(std::move(name)), engine_(engine) {}
    std::string name() const override { return name_; }
    SecurityProfile select(const IpcMessage& message,
                           const RuntimeContext& context) const override;

private:
    std::string name_;
    AdaptivePolicyEngine engine_;
};

/// Static L1..L5, "Adaptive (risk only)" and "Adaptive (full)".
std::vector<std::unique_ptr<PolicyStrategy>> standardStrategies(
    const RiskParameters& parameters, const Platform& platform);

/// Mandatory minimum for a record, derived from its reference label.
SecurityLevel referenceFloor(const IpcMessage& message, const RuntimeContext& context,
                             SecurityLevel requiredLevel,
                             const QuantumHorizon& horizon = QuantumHorizon());

// ----- Classification quality -----------------------------------------------------------

struct ClassificationReport {
    std::size_t total = 0;
    std::array<std::array<int, kLevelCount>, kLevelCount> confusion{};  ///< [actual][predicted]
    double accuracy = 0.0;
    double underProtectionRate = 0.0;  ///< predicted < required
    double overProtectionRate = 0.0;   ///< predicted > required
    double withinOneLevel = 0.0;
    double macroF1 = 0.0;
    double meanCost = 0.0;             ///< asymmetric cost, see policyCost
    std::array<double, kLevelCount> precision{};
    std::array<double, kLevelCount> recall{};
    std::array<double, kLevelCount> f1{};
    std::array<int, kLevelCount> support{};
};

/// Asymmetric misclassification cost: under-protection by k levels costs
/// underPenalty * k, over-protection by k levels costs k.
double misclassificationCost(SecurityLevel predicted, SecurityLevel required,
                             double underPenalty = 4.0);

ClassificationReport evaluateClassifier(const std::vector<DatasetRecord>& records,
                                        const SecurityClassifier& classifier,
                                        double underPenalty = 4.0);

// ----- Calibration ---------------------------------------------------------------------

struct CalibrationConfig {
    std::uint32_t seed = 7;
    int randomSamples = 6000;
    int refinedCandidates = 8;   ///< best random samples that are refined locally
    int refinementRounds = 80;
    double trainFraction = 0.7;
    double underPenalty = 4.0;
};

struct CalibrationResult {
    RiskParameters initial;
    RiskParameters best;
    ClassificationReport initialTrain, initialTest;
    ClassificationReport bestTrain, bestTest;
    bool anchorsSatisfied = false;  ///< specification scenarios classified as expected
    int evaluations = 0;
    std::size_t trainSize = 0;
    std::size_t testSize = 0;
};

CalibrationResult calibrate(const std::vector<DatasetRecord>& records,
                            const RiskParameters& initial, const CalibrationConfig& config);

// ----- Static vs. adaptive ---------------------------------------------------------------

struct StrategyMetrics {
    std::string strategy;
    std::size_t messages = 0;
    double meanLevel = 0.0;
    double requirementMet = 0.0;       ///< share with provided >= required
    double floorViolations = 0.0;      ///< share with provided < mandatory floor
    double overProtection = 0.0;       ///< share with provided > required
    double quantumSafeCoverage = 0.0;  ///< share of PQ-needing messages given a PQ-safe suite
    double meanCpuMicros = 0.0;
    double p95CpuMicros = 0.0;
    double meanOverheadBytes = 0.0;
    double overheadRatio = 0.0;        ///< overhead bytes / payload bytes
    double meanStateBytes = 0.0;
    double throughputPerSecond = 0.0;  ///< messages/s the crypto cores can sustain
    double cpuAtReferenceRate = 0.0;   ///< share of crypto cores used at the reference rate
};

StrategyMetrics evaluateStrategy(const std::vector<DatasetRecord>& records,
                                 const PolicyStrategy& strategy, const Platform& platform,
                                 double referenceRatePerSecond);

// ----- Resource sweep (Phase 5) -------------------------------------------------------------

struct SweepPoint {
    std::string scenario;
    double cpuPercent = 0.0;
    SecurityLevel required = SecurityLevel::Basic;
    SecurityLevel selected = SecurityLevel::Basic;
    ProtectionMode mode = ProtectionMode::Standard;
    AdaptationAction action = AdaptationAction::None;
    ResourceState state = ResourceState::Normal;
    double cpuMicros = 0.0;
};

std::vector<SweepPoint> resourceSweep(const AdaptivePolicyEngine& engine,
                                      const std::vector<DatasetRecord>& scenarios,
                                      const std::vector<double>& cpuValues);

}  // namespace aspe

#endif  // ASPE_EVALUATION_H
