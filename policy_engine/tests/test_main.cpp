// ---------------------------------------------------------------------------
// Unit and property tests for the Adaptive Security Policy Engine.
// Self-contained (no test framework needed): build and run `aspe_tests`.
// ---------------------------------------------------------------------------
#include <cmath>
#include <cstdio>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include "aspe/classifier.h"
#include "aspe/crypto_suite.h"
#include "aspe/dataset.h"
#include "aspe/evaluation.h"
#include "aspe/integration.h"
#include "aspe/parameters.h"
#include "aspe/policy_engine.h"
#include "aspe/risk_model.h"
#include "aspe/runtime_monitor.h"
#include "aspe/simulation.h"
#include "aspe/threat_analysis.h"
#include "aspe/types.h"
#include "aspe/util.h"

using namespace aspe;

namespace {

struct TestCase {
    std::string name;
    std::function<void()> body;
};

std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const std::string& name, std::function<void()> body) {
        registry().push_back({name, body});
    }
};

int g_failures = 0;

void reportFailure(const char* file, int line, const std::string& what) {
    ++g_failures;
    std::cerr << "    FAILED " << file << ":" << line << "  " << what << "\n";
}

#define TEST(name)                                         \
    void name();                                           \
    const Registrar registrar_##name(#name, name);         \
    void name()

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) reportFailure(__FILE__, __LINE__, #condition);     \
    } while (0)

#define CHECK_EQ(a, b)                                                                  \
    do {                                                                                \
        if (!((a) == (b))) reportFailure(__FILE__, __LINE__, #a " == " #b);             \
    } while (0)

#define CHECK_NEAR(a, b, eps)                                                           \
    do {                                                                                \
        if (std::fabs((a) - (b)) > (eps)) reportFailure(__FILE__, __LINE__, #a " ~= " #b); \
    } while (0)

IpcMessage makeMessage(Sensitivity s, Criticality c, std::uint32_t size = 512,
                       double lifetime = 1.0) {
    IpcMessage m;
    m.id = 1;
    m.type = "Test";
    m.senderPid = 7;
    m.receiverPid = 8;
    m.sizeBytes = size;
    m.sensitivity = s;
    m.criticality = c;
    m.lifetimeYears = lifetime;
    return m;
}

RuntimeContext makeContext(double trust, ThreatLevel h, double cpu, double memory = 20.0) {
    RuntimeContext ctx;
    ctx.processTrust = trust;
    ctx.threat = h;
    ctx.cpuPercent = cpu;
    ctx.memoryPercent = memory;
    return ctx;
}

const double kTrustGrid[] = {0.1, 0.55, 0.9};

// ----- types / util ---------------------------------------------------------------------

TEST(enum_round_trip) {
    for (int i = 0; i < 4; ++i) {
        Sensitivity s;
        CHECK(parse(toString(static_cast<Sensitivity>(i)), s));
        CHECK_EQ(ordinal(s), i);
        ThreatLevel h;
        CHECK(parse(toString(static_cast<ThreatLevel>(i)), h));
        CHECK_EQ(ordinal(h), i);
    }
    for (int level = 1; level <= 5; ++level) {
        SecurityLevel l;
        CHECK(parse(toString(levelFromInt(level)), l));
        CHECK_EQ(toInt(l), level);
        CHECK(parse(shortName(levelFromInt(level)), l));
        CHECK_EQ(toInt(l), level);
    }
    SecurityLevel l;
    CHECK(parse("pq", l) && l == SecurityLevel::PostQuantum);
    CHECK(parse("Strong-PQ", l) && l == SecurityLevel::StrongPostQuantum);
    CHECK(parse("secure", l) && l == SecurityLevel::Classical);
    CHECK(!parse("ultra", l));
    Sensitivity s;
    CHECK(parse(" med ", s) && s == Sensitivity::Medium);
    CHECK(!parse("very high", s));
}

TEST(level_arithmetic_is_clamped) {
    CHECK(levelFromInt(0) == SecurityLevel::Basic);
    CHECK(levelFromInt(9) == SecurityLevel::StrongPostQuantum);
    CHECK(stepUp(SecurityLevel::StrongPostQuantum) == SecurityLevel::StrongPostQuantum);
    CHECK(stepDown(SecurityLevel::Basic) == SecurityLevel::Basic);
    CHECK(maxLevel(SecurityLevel::Hybrid, SecurityLevel::Classical) == SecurityLevel::Hybrid);
}

TEST(trust_level_boundaries) {
    CHECK(trustLevelFromScore(0.39) == TrustLevel::Low);
    CHECK(trustLevelFromScore(0.40) == TrustLevel::Medium);
    CHECK(trustLevelFromScore(0.69) == TrustLevel::Medium);
    CHECK(trustLevelFromScore(0.70) == TrustLevel::High);
    for (int i = 0; i < 3; ++i) {
        const TrustLevel t = static_cast<TrustLevel>(i);
        CHECK(trustLevelFromScore(representativeTrustScore(t)) == t);
    }
}

TEST(random_is_deterministic_and_in_range) {
    util::Random a(42), b(42);
    for (int i = 0; i < 1000; ++i) CHECK_EQ(a.uniformInt(3, 9), b.uniformInt(3, 9));
    // std::mt19937 is standardised: the first output for seed 42 is 1608637542.
    util::Random c(42);
    CHECK_NEAR(c.uniform(), 1608637542.0 / 4294967296.0, 1e-15);
    util::Random d(1);
    for (int i = 0; i < 10000; ++i) {
        const int v = d.uniformInt(-2, 2);
        CHECK(v >= -2 && v <= 2);
        const double u = d.uniform();
        CHECK(u >= 0.0 && u < 1.0);
    }
}

TEST(statistics_and_parsing) {
    CHECK_NEAR(util::percentile({1, 2, 3, 4, 5}, 50), 3.0, 1e-12);
    CHECK_NEAR(util::percentile({1, 2, 3, 4, 5}, 100), 5.0, 1e-12);
    CHECK_NEAR(util::percentile({10, 20}, 25), 12.5, 1e-12);
    CHECK_NEAR(util::mean({}), 0.0, 1e-12);
    double x = 0;
    CHECK(util::parseDouble(" 2.5 ", x) && x == 2.5);
    CHECK(!util::parseDouble("2.5x", x));
    CHECK(!util::parseDouble("", x));
    long long n = 0;
    CHECK(util::parseInt("-12", n) && n == -12);
    CHECK(!util::parseInt("1.5", n));
    CHECK_EQ(util::fixed(3.14159, 2), std::string("3.14"));
    CHECK_EQ(util::jsonEscape("a\"b\\"), std::string("a\\\"b\\\\"));
}

// ----- Phase 1 / 2 -----------------------------------------------------------------------

TEST(context_extraction_normalises_to_unit_interval) {
    const ContextExtractor extractor;
    const ContextVector v = extractor.extract(makeMessage(Sensitivity::High, Criticality::Low, 1u << 30),
                                              makeContext(1.7, ThreatLevel::Critical, 140, -5));
    CHECK_NEAR(v.sensitivity, 2.0 / 3.0, 1e-12);
    CHECK_NEAR(v.criticality, 0.0, 1e-12);
    CHECK_NEAR(v.threat, 1.0, 1e-12);
    CHECK_NEAR(v.distrust, 0.0, 1e-12);  // trust clamped to 1
    CHECK_NEAR(v.cpu, 1.0, 1e-12);
    CHECK_NEAR(v.memory, 0.0, 1e-12);
    CHECK_NEAR(v.size, 1.0, 1e-12);
    CHECK_NEAR(v.resourcePressure, 1.0, 1e-12);
    CHECK_NEAR(normaliseSize(16), 0.0, 1e-12);
    CHECK_NEAR(normaliseSize(0), 0.0, 1e-12);
}

TEST(mosca_inequality) {
    const QuantumHorizon h;  // y = 5, z = 15
    CHECK(!h.isExposed(10.0));
    CHECK(h.isExposed(10.01));
    const ContextExtractor extractor(h);
    const ContextVector exposed = extractor.extract(makeMessage(Sensitivity::Medium, Criticality::Low, 64, 12),
                                                    makeContext(0.9, ThreatLevel::Low, 30));
    CHECK(exposed.quantumExposed);
    CHECK_NEAR(exposed.quantumExposure, 1.0, 1e-12);
}

TEST(requirement_analysis) {
    const ContextExtractor extractor;
    const SecurityAnalyzer analyzer;
    auto floorOf = [&](const IpcMessage& m, const RuntimeContext& c) {
        return minimumLevelFor(analyzer.analyze(extractor.extract(m, c)));
    };
    CHECK(floorOf(makeMessage(Sensitivity::Low, Criticality::Low), makeContext(0.9, ThreatLevel::Low, 20)) ==
          SecurityLevel::Basic);
    CHECK(floorOf(makeMessage(Sensitivity::Medium, Criticality::Low), makeContext(0.9, ThreatLevel::Low, 20)) ==
          SecurityLevel::Classical);
    CHECK(floorOf(makeMessage(Sensitivity::Low, Criticality::Low), makeContext(0.2, ThreatLevel::Low, 20)) ==
          SecurityLevel::Classical);
    CHECK(floorOf(makeMessage(Sensitivity::High, Criticality::Low, 512, 20), makeContext(0.9, ThreatLevel::Low, 20)) ==
          SecurityLevel::Hybrid);
    CHECK(floorOf(makeMessage(Sensitivity::Low, Criticality::Critical), makeContext(0.9, ThreatLevel::Low, 20)) ==
          SecurityLevel::PostQuantum);
    CHECK_EQ(threatCatalogue().size(), std::size_t(6));
    const std::vector<ThreatExposure> exposure = analyzer.assessThreats(
        extractor.extract(makeMessage(Sensitivity::High, Criticality::High), makeContext(0.3, ThreatLevel::High, 20)));
    for (std::size_t i = 1; i < exposure.size(); ++i) CHECK(exposure[i - 1].risk() >= exposure[i].risk());
}

// ----- Risk model / classifier -------------------------------------------------------------

TEST(default_parameters_are_valid) {
    CHECK(RiskParameters::defaults().isValid());
    RiskParameters bad = RiskParameters::defaults();
    bad.thresholds[2] = bad.thresholds[1];
    CHECK(!bad.isValid());
    bool threw = false;
    try {
        RiskModel model(bad);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

TEST(risk_is_monotonic_in_every_input) {
    const RiskModel model;
    const double grid[] = {0.0, 1.0 / 3.0, 2.0 / 3.0, 1.0};
    for (double s : grid)
        for (double c : grid)
            for (double h : grid)
                for (double d : grid) {
                    ContextVector v;
                    v.sensitivity = s;
                    v.criticality = c;
                    v.threat = h;
                    v.distrust = d;
                    const double base = model.assess(v).score;
                    CHECK(base >= 0.0 && base <= 1.0);
                    ContextVector up = v;
                    up.sensitivity = std::min(1.0, s + 1.0 / 3.0);
                    CHECK(model.assess(up).score >= base - 1e-12);
                    up = v;
                    up.criticality = std::min(1.0, c + 1.0 / 3.0);
                    CHECK(model.assess(up).score >= base - 1e-12);
                    up = v;
                    up.threat = std::min(1.0, h + 1.0 / 3.0);
                    CHECK(model.assess(up).score >= base - 1e-12);
                    up = v;
                    up.distrust = std::min(1.0, d + 1.0 / 3.0);
                    CHECK(model.assess(up).score >= base - 1e-12);
                }
}

TEST(band_boundaries) {
    const RiskModel model;
    const RiskParameters& p = model.parameters();
    CHECK(model.bandFor(0.0) == SecurityLevel::Basic);
    CHECK(model.bandFor(p.thresholds[0]) == SecurityLevel::Classical);
    CHECK(model.bandFor(p.thresholds[1] - 1e-9) == SecurityLevel::Classical);
    CHECK(model.bandFor(p.thresholds[3]) == SecurityLevel::StrongPostQuantum);
    CHECK(model.bandFor(1.0) == SecurityLevel::StrongPostQuantum);
}

TEST(specification_scenarios_are_classified_as_specified) {
    const SecurityClassifier classifier;
    for (const DatasetRecord& r : specificationScenarios()) {
        const Classification c = classifier.classify(r.message, r.context);
        if (c.level != r.requiredLevel) {
            reportFailure(__FILE__, __LINE__, "scenario " + r.message.type + " -> " + shortName(c.level));
        }
        // The independent reference policy agrees with the specification too.
        CHECK(referenceRequiredLevel(r.message, r.context) == r.requiredLevel);
    }
}

TEST(classification_never_below_requirement_floor) {
    const SecurityClassifier classifier;
    for (const DatasetRecord& r : DatasetGenerator(3).generate(2000)) {
        const Classification c = classifier.classify(r.message, r.context);
        CHECK(toInt(c.level) >= toInt(c.requirementFloor));
        CHECK(toInt(c.level) >= toInt(c.riskBand));
        CHECK(satisfies(suiteFor(c.level), c.requirements));
    }
}

TEST(classifier_agrees_with_reference_on_fresh_data) {
    // Data generated with a seed that was not used for calibration.
    const ClassificationReport r = evaluateClassifier(DatasetGenerator(1234).generate(3000), SecurityClassifier());
    CHECK(r.accuracy > 0.95);
    CHECK(r.underProtectionRate < 0.01);
    CHECK(r.withinOneLevel > 0.999);
}

// ----- Crypto suites ------------------------------------------------------------------------

TEST(suite_catalogue_sizes_and_services) {
    CHECK_EQ(suiteCatalogue().size(), std::size_t(5));
    for (int level = 1; level <= 5; ++level) CHECK(toInt(suiteFor(levelFromInt(level)).level) == level);
    CHECK_EQ(suiteFor(SecurityLevel::PostQuantum).handshakeBytes, 1184u + 1088u + 3309u);
    CHECK_EQ(suiteFor(SecurityLevel::StrongPostQuantum).signatureBytes, 4627u);
    CHECK(!suiteFor(SecurityLevel::Classical).quantumSafeConfidentiality);
    CHECK(suiteFor(SecurityLevel::Hybrid).quantumSafeConfidentiality);
    CHECK(!suiteFor(SecurityLevel::Hybrid).quantumSafeAuthentication);
    CHECK(suiteFor(SecurityLevel::PostQuantum).quantumSafeAuthentication);

    // Every combination of requirements is met by its minimum level.
    for (int mask = 0; mask < 16; ++mask) {
        SecurityRequirements r;
        r.confidentiality = (mask & 1) != 0;
        r.strongAuthentication = (mask & 2) != 0;
        r.quantumSafeConfidentiality = (mask & 4) != 0;
        r.quantumSafeAuthentication = (mask & 8) != 0;
        const SecurityLevel minimum = minimumLevelFor(r);
        CHECK(satisfies(suiteFor(minimum), r));
        for (int level = toInt(minimum); level <= 5; ++level) CHECK(satisfies(suiteFor(levelFromInt(level)), r));
    }
}

TEST(cost_grows_with_level_and_optimisation_saves) {
    const Platform& p = referencePlatform();
    double previous = -1.0;
    for (int level = 1; level <= 5; ++level) {
        const CostEstimate cost = estimateCost(makeProfile(levelFromInt(level)), 1024, p);
        CHECK(cost.cpuMicros > previous);
        previous = cost.cpuMicros;
        if (level >= 2) {
            const CostEstimate optimized =
                estimateCost(makeProfile(levelFromInt(level), ProtectionMode::Optimized), 1024, p);
            CHECK(optimized.cpuMicros < cost.cpuMicros);
            CHECK(optimized.overheadBytes <= cost.overheadBytes);
        }
    }
    const CostEstimate ref = estimateCost(makeProfile(SecurityLevel::PostQuantum), 1024, referencePlatform());
    const CostEstimate emb = estimateCost(makeProfile(SecurityLevel::PostQuantum), 1024, embeddedPlatform());
    CHECK_NEAR(emb.cpuMicros, ref.cpuMicros * embeddedPlatform().costScale, 1e-9);
    const SecurityProfile optimized = makeProfile(SecurityLevel::StrongPostQuantum, ProtectionMode::Optimized);
    CHECK(!optimized.perMessageSignature);
    CHECK_EQ(optimized.rekeyInterval, 16u);
}

// ----- Policy engine (Phases 4 and 5) ---------------------------------------------------------

TEST(policy_invariants_hold_on_full_grid) {
    const AdaptivePolicyEngine engine;
    int checked = 0;
    for (int s = 0; s < 4; ++s)
        for (int c = 0; c < 4; ++c)
            for (int h = 0; h < 4; ++h)
                for (double trust : kTrustGrid)
                    for (double lifetime : {0.5, 12.0})
                        for (int cpu = 0; cpu <= 100; cpu += 5) {
                            const IpcMessage m = makeMessage(static_cast<Sensitivity>(s),
                                                             static_cast<Criticality>(c), 2048, lifetime);
                            const RuntimeContext ctx = makeContext(trust, static_cast<ThreatLevel>(h), cpu);
                            const PolicyDecision d = engine.decide(m, ctx);
                            const int selected = toInt(d.profile.level);
                            CHECK(selected >= toInt(d.floorLevel));
                            CHECK(satisfies(d.profile.suite(), d.classification.requirements));
                            CHECK(toInt(d.floorLevel) >= toInt(d.classification.requirementFloor));
                            if (!d.downgradeAllowed) CHECK(selected >= toInt(d.requiredLevel));
                            if (d.resourceState == ResourceState::Normal) {
                                CHECK(selected == toInt(d.requiredLevel));
                                CHECK(d.action == AdaptationAction::None);
                            }
                            if (d.resourceState == ResourceState::Elevated ||
                                d.resourceState == ResourceState::Constrained) {
                                // Adaptation under pressure never costs more than the requirement.
                                const CostEstimate standard =
                                    estimateCost(makeProfile(d.requiredLevel), m.sizeBytes, engine.platform());
                                CHECK(d.cost.cpuMicros <= standard.cpuMicros + 1e-9);
                                CHECK(selected <= toInt(d.requiredLevel));
                            }
                            ++checked;
                        }
    CHECK(checked == 4 * 4 * 4 * 3 * 2 * 21);
}

TEST(critical_messages_are_never_downgraded) {
    const AdaptivePolicyEngine engine;
    for (int cpu = 0; cpu <= 100; cpu += 10) {
        const PolicyDecision d = engine.decide(makeMessage(Sensitivity::Critical, Criticality::Critical, 256, 12),
                                               makeContext(0.2, ThreatLevel::High, cpu, cpu));
        CHECK(d.profile.level == SecurityLevel::StrongPostQuantum);
        if (cpu >= 70) CHECK(d.profile.mode == ProtectionMode::Optimized);
    }
}

TEST(low_risk_under_pressure_is_lightweight) {
    const AdaptivePolicyEngine engine;
    // Profile scenario: HYBRID required, one level of downgrade allowed.
    const DatasetRecord profile = specificationScenarios()[2];
    RuntimeContext ctx = profile.context;
    ctx.cpuPercent = 92;
    const PolicyDecision d = engine.decide(profile.message, ctx);
    CHECK(d.requiredLevel == SecurityLevel::Hybrid);
    CHECK(d.resourceState == ResourceState::Constrained);
    CHECK(d.action == AdaptationAction::Downgraded);
    CHECK(d.profile.level == SecurityLevel::Classical);
    CHECK(d.profile.mode == ProtectionMode::Optimized);
}

TEST(idle_hardening_and_switches) {
    const DatasetRecord emergency = specificationScenarios()[3];  // risk close to the L5 band
    RuntimeContext idle = emergency.context;
    idle.cpuPercent = 10;
    idle.memoryPercent = 10;
    const PolicyDecision hardened = AdaptivePolicyEngine().decide(emergency.message, idle);
    CHECK(hardened.action == AdaptationAction::Hardened);
    CHECK(hardened.profile.level == SecurityLevel::StrongPostQuantum);

    AdaptationConfig noHardening;
    noHardening.opportunisticHardening = false;
    CHECK(AdaptivePolicyEngine(SecurityClassifier(), noHardening).decide(emergency.message, idle).profile.level ==
          SecurityLevel::PostQuantum);

    AdaptationConfig riskOnly;
    riskOnly.resourceAdaptation = false;
    RuntimeContext busy = emergency.context;
    busy.cpuPercent = 99;
    const PolicyDecision d = AdaptivePolicyEngine(SecurityClassifier(), riskOnly).decide(emergency.message, busy);
    CHECK(d.profile.level == d.requiredLevel);
    CHECK(d.profile.mode == ProtectionMode::Standard);

    AdaptationConfig invalid;
    invalid.elevatedPressure = 0.9;
    invalid.constrainedPressure = 0.8;
    bool threw = false;
    try {
        AdaptivePolicyEngine bad(SecurityClassifier(), invalid);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

TEST(decision_json_contains_contract_fields) {
    const DatasetRecord alert = specificationScenarios().back();
    const PolicyDecision d = AdaptivePolicyEngine().decide(alert.message, alert.context);
    const std::string json = toJson(alert.message, d);
    for (const char* key : {"\"selected_level\":5", "\"policy\":\"STRONG_PQ\"", "\"key_establishment\":\"ML-KEM-1024\"",
                            "\"rekey_interval\"", "\"per_message_signature\"", "\"quantum_safe\":true"}) {
        if (json.find(key) == std::string::npos) reportFailure(__FILE__, __LINE__, std::string("missing ") + key);
    }
    CHECK(json.front() == '{' && json.back() == '}');
}

// ----- Runtime monitors ---------------------------------------------------------------------

TEST(threat_monitor_rises_and_releases_with_hysteresis) {
    ThreatMonitor monitor;
    CHECK(monitor.level() == ThreatLevel::Low);
    for (int i = 0; i < 10; ++i) {
        monitor.record(SecurityEventType::AuthenticationFailure, 120);
        monitor.endPeriod();
    }
    CHECK(monitor.level() == ThreatLevel::Critical);
    // One quiet period: score drops but stays above the release threshold.
    monitor.endPeriod();
    CHECK(monitor.level() == ThreatLevel::Critical);
    for (int i = 0; i < 30; ++i) monitor.endPeriod();
    CHECK(monitor.level() == ThreatLevel::Low);
    CHECK(ThreatMonitor::weightOf(SecurityEventType::ReplayDetected) >
          ThreatMonitor::weightOf(SecurityEventType::AccessDenied));
}

TEST(trust_manager_beta_reputation) {
    TrustManager trust;
    trust.registerProcess(1, 0.8);
    CHECK_NEAR(trust.trust(1), 0.8, 1e-12);
    for (int i = 0; i < 500; ++i) trust.recordOutcome(1, true);
    CHECK_NEAR(trust.trust(1), 0.8, 1e-9);  // good behaviour cannot exceed the prior
    for (int i = 0; i < 20; ++i) trust.recordOutcome(1, false);
    const double afterFailures = trust.trust(1);
    CHECK(afterFailures < 0.3);
    for (int i = 0; i < 20; ++i) trust.recordOutcome(1, true);
    CHECK(trust.trust(1) > afterFailures);
    CHECK(trust.trust(1) < 0.8);  // regaining trust takes longer than losing it
    CHECK_NEAR(trust.trust(99), 0.5, 1e-12);
}

// ----- Dataset ------------------------------------------------------------------------------

TEST(dataset_is_deterministic_and_round_trips) {
    const std::vector<DatasetRecord> a = DatasetGenerator(11).generate(300);
    const std::vector<DatasetRecord> b = DatasetGenerator(11).generate(300);
    CHECK_EQ(a.size(), std::size_t(300));
    for (std::size_t i = 0; i < a.size(); ++i) {
        CHECK_EQ(a[i].message.type, b[i].message.type);
        CHECK(a[i].requiredLevel == b[i].requiredLevel);
        CHECK(a[i].message.senderPid != a[i].message.receiverPid);
        CHECK(a[i].requiredLevel == referenceRequiredLevel(a[i].message, a[i].context));
    }

    const std::string path = "build/test_dataset.csv";
    std::string error;
    CHECK(writeDatasetCsv(path, a, &error));
    std::vector<DatasetRecord> loaded;
    CHECK(readDatasetCsv(path, loaded, &error));
    CHECK_EQ(loaded.size(), a.size());
    for (std::size_t i = 0; i < loaded.size() && i < a.size(); ++i) {
        CHECK_EQ(loaded[i].message.id, a[i].message.id);
        CHECK(loaded[i].message.sensitivity == a[i].message.sensitivity);
        CHECK(loaded[i].context.threat == a[i].context.threat);
        CHECK(loaded[i].requiredLevel == a[i].requiredLevel);
        CHECK_NEAR(loaded[i].context.processTrust, a[i].context.processTrust, 1e-3);
    }
    std::remove(path.c_str());
    CHECK(!readDatasetCsv("build/does_not_exist.csv", loaded, &error));
    CHECK(!error.empty());
}

TEST(reference_policy_is_monotonic) {
    // Raising any risk factor never lowers the reference requirement.
    for (int s = 0; s < 4; ++s)
        for (int c = 0; c < 4; ++c)
            for (int h = 0; h < 4; ++h)
                for (double trust : kTrustGrid) {
                    const IpcMessage m = makeMessage(static_cast<Sensitivity>(s), static_cast<Criticality>(c));
                    const int base = toInt(referenceRequiredLevel(m, makeContext(trust, static_cast<ThreatLevel>(h), 0)));
                    if (h < 3)
                        CHECK(toInt(referenceRequiredLevel(m, makeContext(trust, static_cast<ThreatLevel>(h + 1), 0))) >= base);
                    if (s < 3) {
                        const IpcMessage up = makeMessage(static_cast<Sensitivity>(s + 1), static_cast<Criticality>(c));
                        CHECK(toInt(referenceRequiredLevel(up, makeContext(trust, static_cast<ThreatLevel>(h), 0))) >= base);
                    }
                    CHECK(toInt(referenceRequiredLevel(m, makeContext(0.1, static_cast<ThreatLevel>(h), 0))) >= base);
                }
}

// ----- Calibration / evaluation / simulation -------------------------------------------------

TEST(calibration_improves_on_neutral_model) {
    const std::vector<DatasetRecord> data = DatasetGenerator(5).generate(800);
    RiskParameters neutral;
    neutral.alpha = neutral.beta = 0.5;
    neutral.wImpact = neutral.wLikelihood = 1.0 / 3.0;
    neutral.wInteraction = 1.0 - neutral.wImpact - neutral.wLikelihood;
    neutral.thresholds = {{0.2, 0.4, 0.6, 0.8}};
    CalibrationConfig config;
    config.randomSamples = 800;
    const CalibrationResult result = calibrate(data, neutral, config);
    CHECK(result.best.isValid());
    CHECK(result.anchorsSatisfied);
    CHECK(result.bestTrain.meanCost < result.initialTrain.meanCost);
    CHECK(result.bestTest.accuracy > result.initialTest.accuracy);
    CHECK_EQ(result.trainSize + result.testSize, data.size());
}

TEST(adaptive_beats_static_trade_off_on_dataset) {
    const std::vector<DatasetRecord> data = DatasetGenerator(77).generate(1500);
    const Platform platform = embeddedPlatform();
    const StrategyMetrics staticPq = evaluateStrategy(data, StaticPolicy(SecurityLevel::PostQuantum), platform, 500);
    const StrategyMetrics staticStrong =
        evaluateStrategy(data, StaticPolicy(SecurityLevel::StrongPostQuantum), platform, 500);
    const StrategyMetrics adaptive = evaluateStrategy(
        data, AdaptivePolicy("adaptive", AdaptivePolicyEngine(SecurityClassifier(), AdaptationConfig(), platform)),
        platform, 500);
    CHECK(adaptive.floorViolations < 0.01);
    CHECK(adaptive.floorViolations < staticPq.floorViolations);
    CHECK(adaptive.meanCpuMicros < staticPq.meanCpuMicros);
    CHECK(adaptive.meanCpuMicros < staticStrong.meanCpuMicros / 10.0);
    CHECK_NEAR(staticStrong.requirementMet, 1.0, 1e-12);
}

TEST(simulation_is_deterministic_and_adaptation_pays_off) {
    SimulationConfig config = SimulationConfig::standardScenario();
    config.durationSeconds = 300;
    const Simulator simulator(config);
    const AdaptivePolicy full("full", AdaptivePolicyEngine(SecurityClassifier(), AdaptationConfig(), config.platform));
    AdaptationConfig riskOnlyConfig;
    riskOnlyConfig.resourceAdaptation = false;
    const AdaptivePolicy riskOnly("risk", AdaptivePolicyEngine(SecurityClassifier(), riskOnlyConfig, config.platform));

    SimulationSummary a, b, r;
    const std::vector<PeriodRecord> pa = simulator.run(full, a);
    simulator.run(full, b);
    simulator.run(riskOnly, r);
    CHECK_EQ(pa.size(), std::size_t(300));
    CHECK_EQ(a.offered, b.offered);
    CHECK_NEAR(a.meanLatencyMs, b.meanLatencyMs, 1e-12);
    CHECK_EQ(a.offered, r.offered);  // common random numbers across strategies
    CHECK(a.deliveryRatio >= r.deliveryRatio);
    CHECK(a.p95LatencyMs < r.p95LatencyMs);
    CHECK(a.floorViolationRate < 0.01);

    bool threw = false;
    SimulationConfig broken = config;
    broken.channels.push_back({"NoSuchType", 1, 2, 1.0, 0.5});
    try {
        Simulator bad(broken);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

// ----- Integration ---------------------------------------------------------------------------

class FailingChannel : public ISecureChannel {
public:
    std::string name() const override { return "failing"; }
    TransmissionReport transmit(const IpcMessage&, const SecurityProfile& profile) override {
        lastProfile = profile;
        TransmissionReport report;
        report.peerAuthenticated = false;
        report.events.push_back({SecurityEventType::ReplayDetected, 42});
        return report;
    }
    SecurityProfile lastProfile;
};

TEST(framework_routes_decisions_and_feedback) {
    FailingChannel channel;
    SecureIpcFramework framework(AdaptivePolicyEngine(), channel);
    framework.registerProcess(42, 0.9);
    framework.observeResources(40, 40);
    const IpcMessage m = makeMessage(Sensitivity::High, Criticality::High, 1024, 3);
    IpcMessage fromPid = m;
    fromPid.senderPid = 42;
    const SecureIpcFramework::SendResult first = framework.send(fromPid);
    CHECK(channel.lastProfile.level == first.decision.profile.level);
    for (int i = 0; i < 30; ++i) framework.send(fromPid);
    CHECK(framework.trustManager().trust(42) < 0.4);
    const SecureIpcFramework::SendResult later = framework.send(fromPid);
    CHECK(toInt(later.decision.requiredLevel) >= toInt(first.decision.requiredLevel));

    ModelledSecureChannel modelled(referencePlatform());
    const TransmissionReport report = modelled.transmit(m, makeProfile(SecurityLevel::PostQuantum));
    CHECK(report.delivered && report.peerAuthenticated);
    CHECK(report.wireBytes > m.sizeBytes);
}

}  // namespace

int main() {
    util::ensureDirectory("build");
    int failedTests = 0;
    for (const TestCase& test : registry()) {
        const int before = g_failures;
        try {
            test.body();
        } catch (const std::exception& e) {
            reportFailure(__FILE__, __LINE__, std::string("unexpected exception: ") + e.what());
        }
        const bool passed = g_failures == before;
        if (!passed) ++failedTests;
        std::cout << (passed ? "[PASS] " : "[FAIL] ") << test.name << "\n";
    }
    std::cout << "\n" << registry().size() - static_cast<std::size_t>(failedTests) << "/" << registry().size()
              << " tests passed";
    if (g_failures) std::cout << " (" << g_failures << " failed checks)";
    std::cout << "\n";
    return failedTests == 0 ? 0 : 1;
}
