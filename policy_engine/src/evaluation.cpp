#include "aspe/evaluation.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "aspe/util.h"

namespace aspe {

// ----- Strategies ---------------------------------------------------------------------

std::string StaticPolicy::name() const { return "Static " + toString(level_); }

SecurityProfile StaticPolicy::select(const IpcMessage&, const RuntimeContext&) const {
    return makeProfile(level_);
}

SecurityProfile AdaptivePolicy::select(const IpcMessage& message,
                                       const RuntimeContext& context) const {
    return engine_.decide(message, context).profile;
}

std::vector<std::unique_ptr<PolicyStrategy>> standardStrategies(
    const RiskParameters& parameters, const Platform& platform) {
    std::vector<std::unique_ptr<PolicyStrategy>> strategies;
    for (int level = kMinLevel; level <= kMaxLevel; ++level) {
        strategies.push_back(std::unique_ptr<PolicyStrategy>(new StaticPolicy(levelFromInt(level))));
    }
    const SecurityClassifier classifier{RiskModel(parameters)};

    AdaptationConfig riskOnly;
    riskOnly.resourceAdaptation = false;
    strategies.push_back(std::unique_ptr<PolicyStrategy>(new AdaptivePolicy(
        "Adaptive (risk only)", AdaptivePolicyEngine(classifier, riskOnly, platform))));
    strategies.push_back(std::unique_ptr<PolicyStrategy>(new AdaptivePolicy(
        "Adaptive (full)", AdaptivePolicyEngine(classifier, AdaptationConfig(), platform))));
    return strategies;
}

SecurityLevel referenceFloor(const IpcMessage& message, const RuntimeContext& context,
                             SecurityLevel requiredLevel, const QuantumHorizon& horizon) {
    const ContextVector vector = ContextExtractor(horizon).extract(message, context);
    const SecurityLevel requirementFloor = minimumLevelFor(SecurityAnalyzer().analyze(vector));
    const bool downgradeAllowed =
        isDowngradeAllowed(message.sensitivity, message.criticality, context.threat);
    return mandatoryFloor(maxLevel(requiredLevel, requirementFloor), requirementFloor,
                          downgradeAllowed);
}

// ----- Classification quality -----------------------------------------------------------

double misclassificationCost(SecurityLevel predicted, SecurityLevel required,
                             double underPenalty) {
    const int diff = toInt(predicted) - toInt(required);
    return diff < 0 ? underPenalty * static_cast<double>(-diff) : static_cast<double>(diff);
}

namespace {

ClassificationReport buildReport(const std::vector<SecurityLevel>& predicted,
                                 const std::vector<SecurityLevel>& actual, double underPenalty) {
    ClassificationReport r;
    r.total = actual.size();
    if (r.total == 0) return r;

    int correct = 0, under = 0, over = 0, withinOne = 0;
    double cost = 0.0;
    for (std::size_t i = 0; i < actual.size(); ++i) {
        const int a = toInt(actual[i]) - 1;
        const int p = toInt(predicted[i]) - 1;
        ++r.confusion[a][p];
        if (a == p) ++correct;
        if (p < a) ++under;
        if (p > a) ++over;
        if (std::abs(p - a) <= 1) ++withinOne;
        cost += misclassificationCost(predicted[i], actual[i], underPenalty);
    }
    const double n = static_cast<double>(r.total);
    r.accuracy = correct / n;
    r.underProtectionRate = under / n;
    r.overProtectionRate = over / n;
    r.withinOneLevel = withinOne / n;
    r.meanCost = cost / n;

    double f1Sum = 0.0;
    int classesPresent = 0;
    for (int k = 0; k < kLevelCount; ++k) {
        int tp = r.confusion[k][k], predictedK = 0, actualK = 0;
        for (int j = 0; j < kLevelCount; ++j) {
            predictedK += r.confusion[j][k];
            actualK += r.confusion[k][j];
        }
        r.support[k] = actualK;
        r.precision[k] = predictedK ? static_cast<double>(tp) / predictedK : 0.0;
        r.recall[k] = actualK ? static_cast<double>(tp) / actualK : 0.0;
        const double pr = r.precision[k] + r.recall[k];
        r.f1[k] = pr > 0.0 ? 2.0 * r.precision[k] * r.recall[k] / pr : 0.0;
        if (actualK > 0) {
            f1Sum += r.f1[k];
            ++classesPresent;
        }
    }
    r.macroF1 = classesPresent ? f1Sum / classesPresent : 0.0;
    return r;
}

/// Parameter-independent part of a classification, computed once.
struct PreparedRecord {
    ContextVector context;
    SecurityLevel requirementFloor;
    SecurityLevel required;
};

std::vector<PreparedRecord> prepare(const std::vector<DatasetRecord>& records) {
    const ContextExtractor extractor;
    const SecurityAnalyzer analyzer;
    std::vector<PreparedRecord> prepared;
    prepared.reserve(records.size());
    for (const DatasetRecord& r : records) {
        PreparedRecord p;
        p.context = extractor.extract(r.message, r.context);
        p.requirementFloor = minimumLevelFor(analyzer.analyze(p.context));
        p.required = r.requiredLevel;
        prepared.push_back(p);
    }
    return prepared;
}

SecurityLevel predict(const RiskModel& model, const PreparedRecord& p) {
    return maxLevel(model.assess(p.context).band, p.requirementFloor);
}

double meanCost(const RiskParameters& parameters, const std::vector<PreparedRecord>& data,
                double underPenalty) {
    const RiskModel model(parameters);
    double cost = 0.0;
    for (const PreparedRecord& p : data) {
        cost += misclassificationCost(predict(model, p), p.required, underPenalty);
    }
    return data.empty() ? 0.0 : cost / static_cast<double>(data.size());
}

int anchorErrors(const RiskParameters& parameters, const std::vector<PreparedRecord>& anchors) {
    const RiskModel model(parameters);
    int errors = 0;
    for (const PreparedRecord& p : anchors) {
        if (predict(model, p) != p.required) ++errors;
    }
    return errors;
}

RiskParameters normalised(RiskParameters p) {
    p.alpha = util::clamp01(p.alpha);
    p.beta = util::clamp01(p.beta);
    p.wImpact = std::max(0.0, p.wImpact);
    p.wLikelihood = std::max(0.0, p.wLikelihood);
    p.wInteraction = std::max(0.0, p.wInteraction);
    const double sum = p.wImpact + p.wLikelihood + p.wInteraction;
    if (sum <= 0.0) {
        p.wImpact = p.wLikelihood = p.wInteraction = 1.0 / 3.0;
    } else {
        p.wImpact /= sum;
        p.wLikelihood /= sum;
        p.wInteraction = 1.0 - p.wImpact - p.wLikelihood;
    }
    return p;
}

RiskParameters randomParameters(util::Random& random) {
    RiskParameters p;
    p.alpha = random.uniform();
    p.beta = random.uniform();
    // Uniform sample from the weight simplex (Dirichlet(1, 1, 1)).
    double e[3];
    for (double& x : e) x = -std::log(std::max(1e-12, random.uniform()));
    const double sum = e[0] + e[1] + e[2];
    p.wImpact = e[0] / sum;
    p.wLikelihood = e[1] / sum;
    p.wInteraction = 1.0 - p.wImpact - p.wLikelihood;
    do {
        for (double& t : p.thresholds) t = random.uniform(0.02, 0.98);
        std::sort(p.thresholds.begin(), p.thresholds.end());
    } while (!p.isValid());
    return p;
}

}  // namespace

ClassificationReport evaluateClassifier(const std::vector<DatasetRecord>& records,
                                        const SecurityClassifier& classifier,
                                        double underPenalty) {
    std::vector<SecurityLevel> predicted, actual;
    predicted.reserve(records.size());
    actual.reserve(records.size());
    for (const DatasetRecord& r : records) {
        predicted.push_back(classifier.classify(r.message, r.context).level);
        actual.push_back(r.requiredLevel);
    }
    return buildReport(predicted, actual, underPenalty);
}

// ----- Calibration ---------------------------------------------------------------------

CalibrationResult calibrate(const std::vector<DatasetRecord>& records,
                            const RiskParameters& initial, const CalibrationConfig& config) {
    CalibrationResult result;
    result.initial = initial;

    // Deterministic shuffle and train / test split.
    std::vector<DatasetRecord> shuffled = records;
    util::Random random(config.seed);
    for (std::size_t i = shuffled.size(); i > 1; --i) {
        const std::size_t j = static_cast<std::size_t>(random.uniformInt(0, static_cast<int>(i - 1)));
        std::swap(shuffled[i - 1], shuffled[j]);
    }
    const std::size_t trainSize =
        static_cast<std::size_t>(std::round(config.trainFraction * shuffled.size()));
    const std::vector<DatasetRecord> train(shuffled.begin(), shuffled.begin() + trainSize);
    const std::vector<DatasetRecord> test(shuffled.begin() + trainSize, shuffled.end());
    result.trainSize = train.size();
    result.testSize = test.size();

    const std::vector<PreparedRecord> trainData = prepare(train);
    const std::vector<PreparedRecord> anchors = prepare(specificationScenarios());

    // Objective: mean asymmetric cost on the training split; every misclassified
    // specification scenario adds a large penalty (hard constraint).
    auto objective = [&](const RiskParameters& p) {
        ++result.evaluations;
        return meanCost(p, trainData, config.underPenalty) + 10.0 * anchorErrors(p, anchors);
    };

    // Stage 1: global random search; the best few candidates are kept.
    struct Candidate {
        double score;
        RiskParameters parameters;
    };
    std::vector<Candidate> pool = {{objective(initial), initial}};
    for (int i = 0; i < config.randomSamples; ++i) {
        const RiskParameters candidate = randomParameters(random);
        pool.push_back({objective(candidate), candidate});
        if (pool.size() > 2 * static_cast<std::size_t>(config.refinedCandidates)) {
            std::sort(pool.begin(), pool.end(),
                      [](const Candidate& a, const Candidate& b) { return a.score < b.score; });
            pool.resize(static_cast<std::size_t>(config.refinedCandidates));
        }
    }
    std::sort(pool.begin(), pool.end(),
              [](const Candidate& a, const Candidate& b) { return a.score < b.score; });
    if (pool.size() > static_cast<std::size_t>(config.refinedCandidates)) {
        pool.resize(static_cast<std::size_t>(config.refinedCandidates));
    }

    // Stage 2: coordinate refinement (shrinking step) of every kept candidate.
    RiskParameters best = pool.front().parameters;
    double bestScore = pool.front().score;
    for (const Candidate& start : pool) {
        RiskParameters current = start.parameters;
        double currentScore = start.score;
        double step = 0.05;
        for (int round = 0; round < config.refinementRounds && step >= 0.0025; ++round) {
            bool improved = false;
            for (int move = 0; move < 16; ++move) {
                for (int sign = -1; sign <= 1; sign += 2) {
                    RiskParameters c = current;
                    const double d = sign * step;
                    switch (move) {
                        case 0: c.alpha += d; break;
                        case 1: c.beta += d; break;
                        case 2: c.wImpact += d; c.wLikelihood -= d; break;
                        case 3: c.wImpact += d; c.wInteraction -= d; break;
                        case 4: c.wLikelihood += d; c.wInteraction -= d; break;
                        case 5: case 6: case 7: case 8: c.thresholds[move - 5] += d; break;
                        case 9: for (double& t : c.thresholds) t += d; break;
                        default: {
                            // Adjacent threshold pairs: same direction (10-12), opposite (13-15).
                            const int k = (move - 10) % 3;
                            c.thresholds[k] += d;
                            c.thresholds[k + 1] += (move < 13 ? d : -d);
                            break;
                        }
                    }
                    c = normalised(c);
                    if (!c.isValid()) continue;
                    const double score = objective(c);
                    if (score + 1e-12 < currentScore) {
                        currentScore = score;
                        current = c;
                        improved = true;
                    }
                }
            }
            if (!improved) step *= 0.5;
        }
        if (currentScore + 1e-12 < bestScore) {
            bestScore = currentScore;
            best = current;
        }
    }

    result.best = best;
    result.anchorsSatisfied = anchorErrors(best, anchors) == 0;
    result.initialTrain = evaluateClassifier(train, SecurityClassifier(RiskModel(initial)),
                                             config.underPenalty);
    result.initialTest = evaluateClassifier(test, SecurityClassifier(RiskModel(initial)),
                                            config.underPenalty);
    result.bestTrain = evaluateClassifier(train, SecurityClassifier(RiskModel(best)),
                                          config.underPenalty);
    result.bestTest = evaluateClassifier(test, SecurityClassifier(RiskModel(best)),
                                         config.underPenalty);
    return result;
}

// ----- Static vs. adaptive ---------------------------------------------------------------

StrategyMetrics evaluateStrategy(const std::vector<DatasetRecord>& records,
                                 const PolicyStrategy& strategy, const Platform& platform,
                                 double referenceRatePerSecond) {
    StrategyMetrics m;
    m.strategy = strategy.name();
    m.messages = records.size();
    if (records.empty()) return m;

    std::vector<double> cpu;
    cpu.reserve(records.size());
    double levelSum = 0.0, overheadSum = 0.0, payloadSum = 0.0, stateSum = 0.0;
    std::size_t met = 0, violations = 0, over = 0, needQs = 0, gotQs = 0;

    for (const DatasetRecord& r : records) {
        const SecurityProfile profile = strategy.select(r.message, r.context);
        const CostEstimate cost = estimateCost(profile, r.message.sizeBytes, platform);
        const int provided = toInt(profile.level);
        const int required = toInt(r.requiredLevel);
        const SecurityLevel floor = referenceFloor(r.message, r.context, r.requiredLevel);

        levelSum += provided;
        if (provided >= required) ++met;
        if (provided > required) ++over;
        if (provided < toInt(floor)) ++violations;
        if (required >= toInt(SecurityLevel::Hybrid)) {
            ++needQs;
            if (profile.suite().quantumSafeConfidentiality) ++gotQs;
        }
        cpu.push_back(cost.cpuMicros);
        overheadSum += cost.overheadBytes;
        payloadSum += r.message.sizeBytes;
        stateSum += cost.memoryBytes;
    }

    const double n = static_cast<double>(records.size());
    m.meanLevel = levelSum / n;
    m.requirementMet = met / n;
    m.floorViolations = violations / n;
    m.overProtection = over / n;
    m.quantumSafeCoverage = needQs ? static_cast<double>(gotQs) / needQs : 1.0;
    m.meanCpuMicros = util::mean(cpu);
    m.p95CpuMicros = util::percentile(cpu, 95.0);
    m.meanOverheadBytes = overheadSum / n;
    m.overheadRatio = payloadSum > 0.0 ? overheadSum / payloadSum : 0.0;
    m.meanStateBytes = stateSum / n;
    const double coreMicrosPerSecond = platform.cryptoCores * 1e6;
    m.throughputPerSecond = m.meanCpuMicros > 0.0 ? coreMicrosPerSecond / m.meanCpuMicros : 0.0;
    m.cpuAtReferenceRate = referenceRatePerSecond * m.meanCpuMicros / coreMicrosPerSecond;
    return m;
}

// ----- Resource sweep -------------------------------------------------------------------

std::vector<SweepPoint> resourceSweep(const AdaptivePolicyEngine& engine,
                                      const std::vector<DatasetRecord>& scenarios,
                                      const std::vector<double>& cpuValues) {
    std::vector<SweepPoint> points;
    for (const DatasetRecord& scenario : scenarios) {
        for (double cpu : cpuValues) {
            RuntimeContext context = scenario.context;
            context.cpuPercent = cpu;
            context.memoryPercent = 20.0;  // CPU is the varied resource
            const PolicyDecision d = engine.decide(scenario.message, context);
            SweepPoint p;
            p.scenario = scenario.message.type;
            p.cpuPercent = cpu;
            p.required = d.requiredLevel;
            p.selected = d.profile.level;
            p.mode = d.profile.mode;
            p.action = d.action;
            p.state = d.resourceState;
            p.cpuMicros = d.cost.cpuMicros;
            points.push_back(p);
        }
    }
    return points;
}

}  // namespace aspe
