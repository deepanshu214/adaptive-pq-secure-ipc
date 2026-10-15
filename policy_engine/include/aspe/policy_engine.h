// ---------------------------------------------------------------------------
// Phases 4 and 5 - Adaptive, performance-aware security policy selection.
//
//   IPC message -> context extraction -> risk / sensitivity assessment
//               -> required level (classifier)
//               -> mandatory floor (never violated)
//               -> resource-aware adaptation -> SecurityProfile
//
// Adaptation rules (resource pressure P = max(CPU, memory)):
//   IDLE        (P <  0.30)  high threat and risk close to the next band
//                            -> HARDEN one level (opportunistic)
//   NORMAL      (P <  0.70)  apply the required level unchanged
//   ELEVATED    (P <  0.85)  keep the level, OPTIMIZE its parameters
//   CONSTRAINED (P >= 0.85)  DOWNGRADE one level (optimized parameters) if
//                            above the floor and cheaper, otherwise OPTIMIZE
//
// Floor: critical assets (S or C = CRITICAL) and CRITICAL threat allow no
// downgrade; otherwise one level below the requirement, but never below the
// level that provides every required security service (Phase 1).
// ---------------------------------------------------------------------------
#ifndef ASPE_POLICY_ENGINE_H
#define ASPE_POLICY_ENGINE_H

#include <cstdint>
#include <string>
#include <vector>

#include "aspe/classifier.h"
#include "aspe/crypto_suite.h"
#include "aspe/types.h"

namespace aspe {

enum class ResourceState { Idle, Normal, Elevated, Constrained };
enum class AdaptationAction { None, Hardened, Optimized, Downgraded };

std::string toString(ResourceState state);
std::string toString(AdaptationAction action);

struct AdaptationConfig {
    bool resourceAdaptation = true;       ///< Phase 5 on/off (off = risk-only policy)
    bool opportunisticHardening = true;
    double idlePressure = 0.30;
    double elevatedPressure = 0.70;
    double constrainedPressure = 0.85;
    double hardeningMargin = 0.05;        ///< max distance of R to the next band
    std::uint32_t optimizedRekeyMultiplier = 4;

    bool isValid() const;
};

struct PolicyDecision {
    Classification classification;
    SecurityLevel requiredLevel = SecurityLevel::Basic;
    SecurityLevel floorLevel = SecurityLevel::Basic;
    bool downgradeAllowed = true;
    ResourceState resourceState = ResourceState::Normal;
    AdaptationAction action = AdaptationAction::None;
    SecurityProfile profile;
    CostEstimate cost;
    const char* reason = "";  ///< static text, no allocation on the decision path

    SecurityLevel selectedLevel() const { return profile.level; }
};

/// Mandatory minimum level for a message. Shared with the evaluation code so
/// that every strategy is judged against the same rule.
SecurityLevel mandatoryFloor(SecurityLevel required, SecurityLevel requirementFloor,
                             bool downgradeAllowed);

/// Critical assets and a CRITICAL threat level forbid any downgrade.
bool isDowngradeAllowed(Sensitivity sensitivity, Criticality criticality, ThreatLevel threat);

class AdaptivePolicyEngine {
public:
    explicit AdaptivePolicyEngine(SecurityClassifier classifier = SecurityClassifier(),
                                  AdaptationConfig config = AdaptationConfig(),
                                  Platform platform = embeddedPlatform());

    PolicyDecision decide(const IpcMessage& message, const RuntimeContext& context) const;

    /// Full explanation trace (classification steps + adaptation steps).
    std::vector<std::string> explain(const PolicyDecision& decision) const;

    ResourceState resourceStateFor(double pressure) const;

    const SecurityClassifier& classifier() const { return classifier_; }
    const AdaptationConfig& config() const { return config_; }
    const Platform& platform() const { return platform_; }

private:
    SecurityClassifier classifier_;
    AdaptationConfig config_;
    Platform platform_;
};

/// Single-line JSON document describing a decision (integration format).
std::string toJson(const IpcMessage& message, const PolicyDecision& decision);

}  // namespace aspe

#endif  // ASPE_POLICY_ENGINE_H
