#include "aspe/classifier.h"

#include "aspe/util.h"

namespace aspe {

Classification SecurityClassifier::classify(const IpcMessage& message,
                                            const RuntimeContext& context) const {
    Classification c;
    c.context = extractor_.extract(message, context);
    c.requirements = analyzer_.analyze(c.context);
    c.risk = model_.assess(c.context);
    c.riskBand = c.risk.band;
    c.requirementFloor = minimumLevelFor(c.requirements);
    c.level = maxLevel(c.riskBand, c.requirementFloor);
    c.raisedByRequirements = toInt(c.requirementFloor) > toInt(c.riskBand);
    return c;
}

std::vector<std::string> SecurityClassifier::explain(const Classification& c) const {
    using util::fixed;
    const ContextVector& v = c.context;
    std::vector<std::string> steps;
    steps.push_back("Sensitivity analysis   : S=" + toString(v.sensitivityLevel) + " (" +
                    fixed(v.sensitivity, 2) + "), lifetime " + fixed(v.lifetimeYears, 1) +
                    " y, quantum-exposed (Mosca) = " + util::boolText(v.quantumExposed));
    steps.push_back("Process trust analysis : trust=" + fixed(1.0 - v.distrust, 2) + " (" +
                    toString(v.trustLevel) + "), distrust D=" + fixed(v.distrust, 2));
    steps.push_back("Threat assessment      : H=" + toString(v.threatLevel) + " (" +
                    fixed(v.threat, 2) + ")");
    steps.push_back("Criticality assessment : C=" + toString(v.criticalityLevel) + " (" +
                    fixed(v.criticality, 2) + ")");
    steps.push_back("Requirements           : " + describe(c.requirements) + " -> floor " +
                    shortName(c.requirementFloor));
    steps.push_back("Risk model             : I=" + fixed(c.risk.impact, 3) +
                    " L=" + fixed(c.risk.likelihood, 3) + " R=" + fixed(c.risk.score, 3) +
                    " -> band " + shortName(c.riskBand));
    steps.push_back("Required level         : " + shortName(c.level) +
                    (c.raisedByRequirements ? " (raised to requirement floor)" : ""));
    return steps;
}

}  // namespace aspe
