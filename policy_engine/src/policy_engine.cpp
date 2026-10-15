#include "aspe/policy_engine.h"

#include <sstream>
#include <stdexcept>

#include "aspe/util.h"

namespace aspe {

std::string toString(ResourceState state) {
    switch (state) {
        case ResourceState::Idle: return "IDLE";
        case ResourceState::Normal: return "NORMAL";
        case ResourceState::Elevated: return "ELEVATED";
        case ResourceState::Constrained: return "CONSTRAINED";
    }
    return "UNKNOWN";
}

std::string toString(AdaptationAction action) {
    switch (action) {
        case AdaptationAction::None: return "NONE";
        case AdaptationAction::Hardened: return "HARDENED";
        case AdaptationAction::Optimized: return "OPTIMIZED";
        case AdaptationAction::Downgraded: return "DOWNGRADED";
    }
    return "UNKNOWN";
}

bool AdaptationConfig::isValid() const {
    return idlePressure >= 0.0 && idlePressure < elevatedPressure &&
           elevatedPressure < constrainedPressure && constrainedPressure <= 1.0 &&
           hardeningMargin >= 0.0 && optimizedRekeyMultiplier >= 1;
}

SecurityLevel mandatoryFloor(SecurityLevel required, SecurityLevel requirementFloor,
                             bool downgradeAllowed) {
    if (!downgradeAllowed) return required;
    return maxLevel(requirementFloor, stepDown(required));
}

bool isDowngradeAllowed(Sensitivity sensitivity, Criticality criticality, ThreatLevel threat) {
    return sensitivity != Sensitivity::Critical && criticality != Criticality::Critical &&
           threat != ThreatLevel::Critical;
}

AdaptivePolicyEngine::AdaptivePolicyEngine(SecurityClassifier classifier,
                                           AdaptationConfig config, Platform platform)
    : classifier_(classifier), config_(config), platform_(platform) {
    if (!config_.isValid()) throw std::invalid_argument("invalid adaptation configuration");
}

ResourceState AdaptivePolicyEngine::resourceStateFor(double pressure) const {
    if (pressure >= config_.constrainedPressure) return ResourceState::Constrained;
    if (pressure >= config_.elevatedPressure) return ResourceState::Elevated;
    if (pressure < config_.idlePressure) return ResourceState::Idle;
    return ResourceState::Normal;
}

PolicyDecision AdaptivePolicyEngine::decide(const IpcMessage& message,
                                            const RuntimeContext& context) const {
    PolicyDecision d;
    d.classification = classifier_.classify(message, context);
    const Classification& c = d.classification;

    d.requiredLevel = c.level;
    d.downgradeAllowed = isDowngradeAllowed(message.sensitivity, message.criticality,
                                            context.threat);
    d.floorLevel = mandatoryFloor(d.requiredLevel, c.requirementFloor, d.downgradeAllowed);
    d.resourceState = resourceStateFor(c.context.resourcePressure);

    SecurityLevel level = d.requiredLevel;
    ProtectionMode mode = ProtectionMode::Standard;
    const bool optimizable = suiteFor(level).defaultRekeyInterval > 0;

    if (config_.resourceAdaptation) {
        switch (d.resourceState) {
            case ResourceState::Idle: {
                const bool nearNextBand = c.riskBand == d.requiredLevel &&
                                          c.risk.gapToUpperBound <= config_.hardeningMargin;
                const bool highThreat = ordinal(context.threat) >= ordinal(ThreatLevel::High);
                if (config_.opportunisticHardening && highThreat && nearNextBand &&
                    level != SecurityLevel::StrongPostQuantum) {
                    level = stepUp(level);
                    d.action = AdaptationAction::Hardened;
                }
                break;
            }
            case ResourceState::Normal:
                break;
            case ResourceState::Elevated:
                if (optimizable) {
                    mode = ProtectionMode::Optimized;
                    d.action = AdaptationAction::Optimized;
                }
                break;
            case ResourceState::Constrained: {
                // Option A: keep the level, optimize its parameters.
                const ProtectionMode keepMode =
                    optimizable ? ProtectionMode::Optimized : ProtectionMode::Standard;
                const double keepCost =
                    estimateCost(makeProfile(level, keepMode, config_.optimizedRekeyMultiplier),
                                 message.sizeBytes, platform_).cpuMicros;
                // Option B: lightweight policy one level down (within the floor). It
                // is taken only if it is actually cheaper - security is never given
                // up for nothing (e.g. HMAC can cost more per byte than AES-GCM).
                bool downgrade = false;
                if (toInt(level) > toInt(d.floorLevel)) {
                    const SecurityLevel lower = stepDown(level);
                    const ProtectionMode lowerMode = suiteFor(lower).defaultRekeyInterval > 0
                                                         ? ProtectionMode::Optimized
                                                         : ProtectionMode::Standard;
                    const double lowerCost =
                        estimateCost(makeProfile(lower, lowerMode, config_.optimizedRekeyMultiplier),
                                     message.sizeBytes, platform_).cpuMicros;
                    if (lowerCost < keepCost) {
                        level = lower;
                        mode = lowerMode;
                        d.action = AdaptationAction::Downgraded;
                        downgrade = true;
                    }
                }
                if (!downgrade && optimizable) {
                    mode = ProtectionMode::Optimized;
                    d.action = AdaptationAction::Optimized;
                }
                break;
            }
        }
    }

    // Safety invariant: the floor is never violated and every required
    // security service is provided by the selected suite.
    if (toInt(level) < toInt(d.floorLevel)) level = d.floorLevel;
    if (!satisfies(suiteFor(level), c.requirements)) {
        throw std::logic_error("policy engine selected a suite that misses a requirement");
    }

    d.profile = makeProfile(level, mode, config_.optimizedRekeyMultiplier);
    d.cost = estimateCost(d.profile, message.sizeBytes, platform_);

    switch (d.action) {
        case AdaptationAction::None:
            d.reason = d.resourceState == ResourceState::Idle
                           ? "Required level applied (IDLE resources)"
                           : "Required level applied (NORMAL resources)";
            break;
        case AdaptationAction::Hardened:
            d.reason = "Idle resources, high threat, risk near next band: hardened one level";
            break;
        case AdaptationAction::Optimized:
            if (d.resourceState == ResourceState::Elevated) {
                d.reason = "Elevated resource pressure: level kept, parameters optimized";
            } else if (!d.downgradeAllowed) {
                d.reason = "Constrained, downgrade forbidden (critical): optimized in place";
            } else if (d.requiredLevel == d.floorLevel) {
                d.reason = "Constrained, already at mandatory floor: optimized in place";
            } else {
                d.reason = "Constrained, lower level would not be cheaper: optimized in place";
            }
            break;
        case AdaptationAction::Downgraded:
            d.reason = "Constrained resources: lightweight policy (one level down, optimized)";
            break;
    }
    return d;
}

std::vector<std::string> AdaptivePolicyEngine::explain(const PolicyDecision& d) const {
    using util::fixed;
    std::vector<std::string> steps = classifier_.explain(d.classification);
    const SecurityProfile& p = d.profile;
    const CryptoSuite& s = p.suite();

    steps.push_back("Mandatory floor        : " + shortName(d.floorLevel) +
                    (d.downgradeAllowed ? " (one level of downgrade permitted)"
                                        : " (no downgrade: critical asset or critical threat)"));
    steps.push_back("Resource state         : " + toString(d.resourceState) + " (P=" +
                    fixed(d.classification.context.resourcePressure, 2) + ")");
    steps.push_back("Adaptation             : " + toString(d.action) + " - " + std::string(d.reason));
    steps.push_back("Selected policy        : " + shortName(p.level) + " / " +
                    toString(p.mode) + "  [" + s.keyEstablishment + " | " +
                    s.authentication + " | " + s.payloadProtection + "]");
    steps.push_back("Parameters             : rekey every " +
                    (p.rekeyInterval ? std::to_string(p.rekeyInterval) + " msgs" : std::string("n/a")) +
                    ", per-message signature " + util::boolText(p.perMessageSignature) +
                    ", anti-replay " + util::boolText(p.replayProtection));
    steps.push_back("Estimated cost         : " + fixed(d.cost.cpuMicros, 1) + " us CPU, +" +
                    std::to_string(d.cost.overheadBytes) + " B on the wire, " +
                    std::to_string(d.cost.memoryBytes) + " B session state (" + platform_.name +
                    ")");
    return steps;
}

std::string toJson(const IpcMessage& message, const PolicyDecision& d) {
    const SecurityProfile& p = d.profile;
    const CryptoSuite& s = p.suite();
    std::ostringstream out;
    out << "{\"message_id\":" << message.id << ",\"type\":\"" << util::jsonEscape(message.type)
        << "\",\"sender\":" << message.senderPid << ",\"receiver\":" << message.receiverPid
        << ",\"risk_score\":" << util::fixed(d.classification.risk.score, 4)
        << ",\"required_level\":" << toInt(d.requiredLevel)
        << ",\"floor_level\":" << toInt(d.floorLevel)
        << ",\"selected_level\":" << toInt(p.level) << ",\"policy\":\"" << toString(p.level)
        << "\",\"mode\":\"" << toString(p.mode) << "\",\"action\":\"" << toString(d.action)
        << "\",\"resource_state\":\"" << toString(d.resourceState)
        << "\",\"key_establishment\":\"" << util::jsonEscape(s.keyEstablishment)
        << "\",\"authentication\":\"" << util::jsonEscape(s.authentication)
        << "\",\"payload_protection\":\"" << util::jsonEscape(s.payloadProtection)
        << "\",\"rekey_interval\":" << p.rekeyInterval
        << ",\"per_message_signature\":" << (p.perMessageSignature ? "true" : "false")
        << ",\"replay_protection\":" << (p.replayProtection ? "true" : "false")
        << ",\"quantum_safe\":" << (s.quantumSafeConfidentiality ? "true" : "false")
        << ",\"est_cpu_us\":" << util::fixed(d.cost.cpuMicros, 2)
        << ",\"est_overhead_bytes\":" << d.cost.overheadBytes << ",\"reason\":\""
        << util::jsonEscape(d.reason) << "\"}";
    return out.str();
}

}  // namespace aspe
