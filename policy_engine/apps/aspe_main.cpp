// ---------------------------------------------------------------------------
// aspe - command-line front end of the Adaptive Security Policy Engine.
//
// Every phase of the project can be run on its own; `aspe all` runs the
// complete pipeline and writes all artefacts to results/.
// ---------------------------------------------------------------------------
#include <chrono>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "aspe/classifier.h"
#include "aspe/crypto_suite.h"
#include "aspe/dataset.h"
#include "aspe/evaluation.h"
#include "aspe/integration.h"
#include "aspe/parameters.h"
#include "aspe/policy_engine.h"
#include "aspe/simulation.h"
#include "aspe/threat_analysis.h"
#include "aspe/util.h"

using namespace aspe;

namespace {

const char* const kVersion = "1.0.0";
const char* const kDefaultDataset = "data/ipc_dataset.csv";
const char* const kResultsDir = "results";

// ----- Command-line options -------------------------------------------------------

class Options {
public:
    bool parse(int argc, char** argv, int first, std::string& error) {
        for (int i = first; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg.size() < 3 || arg.compare(0, 2, "--") != 0) {
                error = "unexpected argument '" + arg + "'";
                return false;
            }
            arg = arg.substr(2);
            const std::size_t eq = arg.find('=');
            if (eq != std::string::npos) {
                values_[arg.substr(0, eq)] = arg.substr(eq + 1);
            } else if (i + 1 < argc && std::string(argv[i + 1]).compare(0, 2, "--") != 0) {
                values_[arg] = argv[++i];
            } else {
                values_[arg] = "";
            }
        }
        return true;
    }

    bool has(const std::string& key) const { return values_.count(key) != 0; }

    std::string get(const std::string& key, const std::string& fallback) const {
        const auto it = values_.find(key);
        return it == values_.end() || it->second.empty() ? fallback : it->second;
    }

    double number(const std::string& key, double fallback) const {
        const auto it = values_.find(key);
        if (it == values_.end()) return fallback;
        double value = 0.0;
        if (!util::parseDouble(it->second, value)) {
            throw std::invalid_argument("--" + key + " expects a number, got '" + it->second + "'");
        }
        return value;
    }

    long long integer(const std::string& key, long long fallback) const {
        const auto it = values_.find(key);
        if (it == values_.end()) return fallback;
        long long value = 0;
        if (!util::parseInt(it->second, value)) {
            throw std::invalid_argument("--" + key + " expects an integer, got '" + it->second + "'");
        }
        return value;
    }

    template <typename Enum>
    Enum level(const std::string& key, Enum fallback) const {
        const auto it = values_.find(key);
        if (it == values_.end()) return fallback;
        Enum value = fallback;
        if (!aspe::parse(it->second, value)) {
            throw std::invalid_argument("--" + key + ": unknown value '" + it->second + "'");
        }
        return value;
    }

private:
    std::map<std::string, std::string> values_;
};

Platform platformOption(const Options& options) {
    Platform platform;
    const std::string name = options.get("platform", "embedded");
    if (!findPlatform(name, platform)) {
        throw std::invalid_argument("--platform must be 'embedded' or 'reference'");
    }
    return platform;
}

std::vector<DatasetRecord> loadDataset(const Options& options) {
    const std::string path = options.get("dataset", kDefaultDataset);
    std::vector<DatasetRecord> records;
    std::string error;
    if (!readDatasetCsv(path, records, &error)) {
        // Fall back to a freshly generated default dataset so every command works
        // out of the box.
        if (options.has("dataset")) throw std::runtime_error(error);
        records = DatasetGenerator(42).generate(5000);
        writeDatasetCsv(path, records, nullptr);
    }
    if (records.empty()) throw std::runtime_error("dataset '" + path + "' contains no records");
    return records;
}

std::ofstream openResult(const std::string& name) {
    util::ensureDirectory(kResultsDir);
    const std::string path = std::string(kResultsDir) + "/" + name;
    std::ofstream file(path.c_str());
    if (!file) throw std::runtime_error("cannot write '" + path + "'");
    return file;
}

std::string pct(double ratio) { return util::percent(ratio, 1); }
std::string num(double value, int precision = 1) { return util::fixed(value, precision); }

// ----- Phase 1 -------------------------------------------------------------------------

int cmdAnalyze(const Options&, std::ostream& out) {
    util::printBanner(out, "PHASE 1 - IPC SECURITY ANALYSIS");

    util::printSection(out, "IPC threat catalogue");
    util::TextTable threats({"Threat", "Violated property", "IPC attack vector", "Countermeasure"});
    for (const ThreatProfile& t : threatCatalogue()) {
        threats.addRow({toString(t.threat), toString(t.violatedProperty), t.ipcAttackVector,
                        t.countermeasure});
    }
    threats.print(out);

    util::printSection(out, "Quantum threat model");
    const QuantumHorizon horizon;
    out << "  Shor's algorithm breaks X25519 / Ed25519 / RSA; Grover halves symmetric key\n"
        << "  strength (AES-256 keeps ~128-bit). Mosca's inequality x + y > z decides\n"
        << "  harvest-now-decrypt-later exposure with y = " << num(horizon.migrationYears, 0)
        << " years (migration) and z = " << num(horizon.quantumThreatYears, 0)
        << " years (time to a\n  cryptographically relevant quantum computer): data that must"
        << " stay secret for\n  more than " << num(horizon.quantumThreatYears - horizon.migrationYears, 0)
        << " years needs quantum-safe key establishment today.\n";

    util::printSection(out, "Requirement analysis of the specification scenarios");
    const ContextExtractor extractor;
    const SecurityAnalyzer analyzer;
    util::TextTable table({"Message", "Required services", "Floor", "Top threat (risk)"});
    for (const DatasetRecord& r : specificationScenarios()) {
        const ContextVector v = extractor.extract(r.message, r.context);
        const SecurityRequirements req = analyzer.analyze(v);
        const std::vector<ThreatExposure> exposure = analyzer.assessThreats(v);
        table.addRow({r.message.type, describe(req), shortName(minimumLevelFor(req)),
                      toString(exposure.front().threat) + " (" + num(exposure.front().risk(), 2) +
                          ")"});
    }
    table.print(out);
    return 0;
}

// ----- Phase 2 -------------------------------------------------------------------------

int cmdParams(const Options&, std::ostream& out) {
    util::printBanner(out, "PHASE 2 - SECURITY PARAMETERS");

    util::printSection(out, "Measurable parameters");
    util::TextTable params({"Parameter", "Symbol", "Domain", "Normalisation", "Role"});
    for (const ParameterSpec& p : parameterCatalogue()) {
        params.addRow({p.name, p.symbol, p.domain, p.normalisation, p.role});
    }
    params.print(out);

    util::printSection(out, "Normalised context vectors of the specification scenarios");
    const ContextExtractor extractor;
    util::TextTable vectors({"Message", "S", "C", "H", "D=1-T", "CPU", "MEM", "Size", "P", "Mosca"});
    for (const DatasetRecord& r : specificationScenarios()) {
        const ContextVector v = extractor.extract(r.message, r.context);
        vectors.addRow({r.message.type, num(v.sensitivity, 2), num(v.criticality, 2),
                        num(v.threat, 2), num(v.distrust, 2), num(v.cpu, 2), num(v.memory, 2),
                        num(v.size, 2), num(v.resourcePressure, 2),
                        v.quantumExposed ? "exposed" : "safe"});
    }
    vectors.print(out);

    util::printSection(out, "Security levels and cryptographic suites");
    util::TextTable suites({"Level", "Key establishment", "Authentication", "Payload", "PQ-safe",
                            "NIST cat.", "Rekey", "Handshake B", "State B"});
    for (const CryptoSuite& s : suiteCatalogue()) {
        suites.addRow({shortName(s.level), s.keyEstablishment, s.authentication,
                       s.payloadProtection,
                       s.quantumSafeAuthentication    ? "conf+auth"
                       : s.quantumSafeConfidentiality ? "conf"
                                                      : "no",
                       s.nistPqCategory ? std::to_string(s.nistPqCategory) : "-",
                       s.defaultRekeyInterval ? std::to_string(s.defaultRekeyInterval) : "-",
                       std::to_string(s.handshakeBytes), std::to_string(s.stateBytes)});
    }
    suites.print(out);
    return 0;
}

// ----- Dataset -----------------------------------------------------------------------------

int cmdGenerate(const Options& options, std::ostream& out) {
    const long long count = options.integer("count", 5000);
    const long long seed = options.integer("seed", 42);
    if (count <= 0) throw std::invalid_argument("--count must be positive");
    const std::string path = options.get("out", kDefaultDataset);

    const std::vector<DatasetRecord> records =
        DatasetGenerator(static_cast<std::uint32_t>(seed)).generate(static_cast<std::size_t>(count));
    std::string error;
    if (!writeDatasetCsv(path, records, &error)) throw std::runtime_error(error);

    int histogram[kLevelCount] = {0, 0, 0, 0, 0};
    for (const DatasetRecord& r : records) ++histogram[toInt(r.requiredLevel) - 1];

    util::printBanner(out, "SYNTHETIC IPC DATASET");
    out << "  " << count << " records (seed " << seed << ") written to " << path << "\n";
    util::TextTable table({"Reference level", "Records", "Share"});
    for (int k = 0; k < kLevelCount; ++k) {
        table.addRow({shortName(levelFromInt(k + 1)), std::to_string(histogram[k]),
                      pct(static_cast<double>(histogram[k]) / static_cast<double>(count))});
    }
    table.print(out);
    return 0;
}

// ----- Phase 3 -------------------------------------------------------------------------

void printReport(std::ostream& out, const ClassificationReport& r) {
    out << "  Records " << r.total << " | accuracy " << pct(r.accuracy) << " | within one level "
        << pct(r.withinOneLevel) << " | under-protection " << pct(r.underProtectionRate)
        << " | over-protection " << pct(r.overProtectionRate) << " | macro-F1 "
        << num(r.macroF1, 3) << "\n";
}

void printConfusion(std::ostream& out, const ClassificationReport& r) {
    std::vector<std::string> header = {"reference \\ engine"};
    for (int k = 0; k < kLevelCount; ++k) header.push_back(shortName(levelFromInt(k + 1)));
    header.insert(header.end(), {"Recall", "Precision", "F1"});
    util::TextTable table(header);
    for (int a = 0; a < kLevelCount; ++a) {
        std::vector<std::string> row = {shortName(levelFromInt(a + 1))};
        for (int p = 0; p < kLevelCount; ++p) row.push_back(std::to_string(r.confusion[a][p]));
        row.push_back(num(r.recall[a], 3));
        row.push_back(num(r.precision[a], 3));
        row.push_back(num(r.f1[a], 3));
        table.addRow(row);
    }
    table.print(out);
}

int cmdClassify(const Options& options, std::ostream& out) {
    util::printBanner(out, "PHASE 3 - SECURITY CLASSIFICATION ENGINE");
    const SecurityClassifier classifier;

    util::printSection(out, "Specification scenarios");
    util::TextTable table({"Message", "S", "Trust", "Threat", "C", "Risk R", "Band", "Floor",
                           "Level", "Expected", "Match"});
    for (const DatasetRecord& r : specificationScenarios()) {
        const Classification c = classifier.classify(r.message, r.context);
        table.addRow({r.message.type, toString(r.message.sensitivity),
                      toString(trustLevelFromScore(r.context.processTrust)),
                      toString(r.context.threat), toString(r.message.criticality),
                      num(c.risk.score, 3), shortName(c.riskBand), shortName(c.requirementFloor),
                      shortName(c.level), shortName(r.requiredLevel),
                      c.level == r.requiredLevel ? "yes" : "NO"});
    }
    table.print(out);

    util::printSection(out, "Classification trace - Alert");
    const DatasetRecord alert = specificationScenarios().back();
    for (const std::string& step : classifier.explain(classifier.classify(alert.message, alert.context))) {
        out << "    " << step << "\n";
    }

    const std::vector<DatasetRecord> records = loadDataset(options);
    const ClassificationReport report = evaluateClassifier(records, classifier);
    util::printSection(out, "Agreement with the reference policy on the dataset");
    printReport(out, report);
    printConfusion(out, report);

    std::ofstream csv = openResult("classification.csv");
    csv << "id,type,required_level,engine_level,risk_score,risk_band,requirement_floor\n";
    for (const DatasetRecord& r : records) {
        const Classification c = classifier.classify(r.message, r.context);
        csv << r.message.id << ',' << r.message.type << ',' << toInt(r.requiredLevel) << ','
            << toInt(c.level) << ',' << util::fixed(c.risk.score, 4) << ',' << toInt(c.riskBand)
            << ',' << toInt(c.requirementFloor) << '\n';
    }
    out << "  Per-record results written to results/classification.csv\n";
    return 0;
}

// ----- Phase 4 -------------------------------------------------------------------------

int cmdCalibrate(const Options& options, std::ostream& out) {
    util::printBanner(out, "PHASE 4 - EXPERIMENTAL CALIBRATION OF THE RISK MODEL");
    const std::vector<DatasetRecord> records = loadDataset(options);

    CalibrationConfig config;
    config.seed = static_cast<std::uint32_t>(options.integer("seed", config.seed));
    config.randomSamples = static_cast<int>(options.integer("samples", config.randomSamples));
    config.underPenalty = options.number("penalty", config.underPenalty);

    // Start from a neutral, uncalibrated model to show what calibration buys.
    RiskParameters neutral;
    neutral.alpha = 0.5;
    neutral.beta = 0.5;
    neutral.wImpact = neutral.wLikelihood = neutral.wInteraction = 1.0 / 3.0;
    neutral.wInteraction = 1.0 - neutral.wImpact - neutral.wLikelihood;
    neutral.thresholds = {{0.2, 0.4, 0.6, 0.8}};

    const auto start = std::chrono::steady_clock::now();
    const CalibrationResult result = calibrate(records, neutral, config);
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    out << "  Objective      : mean asymmetric cost (under-protection x" << num(config.underPenalty, 0)
        << ", over-protection x1) + specification scenarios as hard constraints\n"
        << "  Search         : " << config.randomSamples << " random samples, best " << config.refinedCandidates
        << " refined by coordinate search ("
        << result.evaluations << " evaluations, " << num(seconds, 2) << " s)\n"
        << "  Split          : " << result.trainSize << " train / " << result.testSize << " test (seed "
        << config.seed << ")\n\n";

    util::TextTable table({"Model", "Split", "Accuracy", "Under-prot.", "Over-prot.", "Macro-F1", "Cost"});
    auto row = [&](const std::string& model, const std::string& split, const ClassificationReport& r) {
        table.addRow({model, split, pct(r.accuracy), pct(r.underProtectionRate),
                      pct(r.overProtectionRate), num(r.macroF1, 3), num(r.meanCost, 3)});
    };
    row("neutral", "train", result.initialTrain);
    row("neutral", "test", result.initialTest);
    row("calibrated", "train", result.bestTrain);
    row("calibrated", "test", result.bestTest);
    table.print(out);

    out << "\n  Calibrated parameters : " << result.best.toString() << "\n"
        << "  Built-in defaults     : " << RiskParameters::defaults().toString() << "\n"
        << "  Specification scenarios satisfied: " << util::boolText(result.anchorsSatisfied) << "\n";

    std::ofstream file = openResult("calibration.txt");
    file << "calibrated " << result.best.toString() << "\n"
         << "defaults   " << RiskParameters::defaults().toString() << "\n"
         << "test_accuracy " << util::fixed(result.bestTest.accuracy, 4) << "\n"
         << "test_under_protection " << util::fixed(result.bestTest.underProtectionRate, 4) << "\n"
         << "anchors_satisfied " << (result.anchorsSatisfied ? 1 : 0) << "\n";
    out << "  Written to results/calibration.txt\n";
    return 0;
}

// ----- Single decision -----------------------------------------------------------------

int cmdDecide(const Options& options, std::ostream& out) {
    IpcMessage message;
    RuntimeContext context;
    message.id = static_cast<std::uint64_t>(options.integer("id", 1));
    message.type = options.get("type", "Custom");
    message.senderPid = static_cast<int>(options.integer("sender", 100));
    message.receiverPid = static_cast<int>(options.integer("receiver", 200));
    message.sizeBytes = static_cast<std::uint32_t>(options.integer("size", 512));
    message.sensitivity = options.level("sensitivity", Sensitivity::Medium);
    message.criticality = options.level("criticality", Criticality::Medium);
    message.lifetimeYears = options.number("lifetime", 1.0);

    if (options.has("trust")) {
        TrustLevel level;
        const std::string text = options.get("trust", "");
        double score = 0.0;
        if (util::parseDouble(text, score)) context.processTrust = util::clamp01(score);
        else if (aspe::parse(text, level)) context.processTrust = representativeTrustScore(level);
        else throw std::invalid_argument("--trust expects a score in [0,1] or LOW|MEDIUM|HIGH");
    } else {
        context.processTrust = 0.8;
    }
    context.threat = options.level("threat", ThreatLevel::Low);
    context.cpuPercent = options.number("cpu", 40.0);
    context.memoryPercent = options.number("memory", 40.0);

    const AdaptivePolicyEngine engine(SecurityClassifier(), AdaptationConfig(), platformOption(options));
    const PolicyDecision decision = engine.decide(message, context);

    if (options.has("json")) {
        out << toJson(message, decision) << "\n";
        return 0;
    }
    util::printBanner(out, "ADAPTIVE POLICY DECISION - " + message.type);
    for (const std::string& step : engine.explain(decision)) out << "    " << step << "\n";
    out << "\n  JSON: " << toJson(message, decision) << "\n";
    return 0;
}

// ----- Phase 5 -------------------------------------------------------------------------

int cmdAdapt(const Options& options, std::ostream& out) {
    util::printBanner(out, "PHASE 5 - PERFORMANCE-AWARE ADAPTATION");
    const AdaptivePolicyEngine engine(SecurityClassifier(), AdaptationConfig(), platformOption(options));
    const AdaptationConfig& cfg = engine.config();
    out << "  Resource states: IDLE < " << num(cfg.idlePressure * 100, 0) << "% <= NORMAL < "
        << num(cfg.elevatedPressure * 100, 0) << "% <= ELEVATED < "
        << num(cfg.constrainedPressure * 100, 0) << "% <= CONSTRAINED (P = max(CPU, memory))\n";

    std::vector<double> cpuValues;
    for (int cpu = 10; cpu <= 95; cpu += 5) cpuValues.push_back(cpu);
    const std::vector<DatasetRecord> scenarios = specificationScenarios();
    const std::vector<SweepPoint> sweep = resourceSweep(engine, scenarios, cpuValues);

    util::printSection(out, "Selected policy per scenario and CPU load (memory fixed at 20%)");
    const double shown[] = {20, 50, 75, 90};
    util::TextTable table({"Message", "Required", "CPU 20% (idle)", "CPU 50% (normal)",
                           "CPU 75% (elevated)", "CPU 90% (constrained)"});
    for (const DatasetRecord& s : scenarios) {
        std::vector<std::string> row = {s.message.type, ""};
        for (double cpu : shown) {
            for (const SweepPoint& p : sweep) {
                if (p.scenario == s.message.type && p.cpuPercent == cpu) {
                    row[1] = shortName(p.required);
                    std::string cell = shortName(p.selected);
                    if (p.mode == ProtectionMode::Optimized) cell += " opt";
                    cell += " (" + num(p.cpuMicros, 0) + " us)";
                    row.push_back(cell);
                }
            }
        }
        table.addRow(row);
    }
    table.print(out);
    out << "  'opt' = same algorithms with optimized parameters (rekey x"
        << cfg.optimizedRekeyMultiplier << ", session-level authentication).\n"
        << "  Costs are per message on the " << engine.platform().name << ".\n";

    util::printSection(out, "Adaptation rules confirmed by the sweep");
    out << "    High risk + sufficient resources   -> required PQ / strong PQ applied\n"
        << "    High risk + constrained resources  -> optimized policy (critical: never downgraded)\n"
        << "    Low risk  + constrained resources  -> lightweight policy (one level, within floor)\n";

    std::ofstream csv = openResult("resource_sweep.csv");
    csv << "scenario,cpu_percent,resource_state,required_level,selected_level,mode,action,cpu_us\n";
    for (const SweepPoint& p : sweep) {
        csv << p.scenario << ',' << num(p.cpuPercent, 0) << ',' << toString(p.state) << ','
            << toInt(p.required) << ',' << toInt(p.selected) << ',' << toString(p.mode) << ','
            << toString(p.action) << ',' << util::fixed(p.cpuMicros, 2) << '\n';
    }
    out << "  Full sweep written to results/resource_sweep.csv\n";
    return 0;
}

// ----- Phase 6 -------------------------------------------------------------------------

int cmdEvaluate(const Options& options, std::ostream& out) {
    util::printBanner(out, "PHASE 6a - STATIC vs ADAPTIVE SECURITY (DATASET)");
    const std::vector<DatasetRecord> records = loadDataset(options);
    const Platform platform = platformOption(options);
    const double rate = options.number("rate", 500.0);

    out << "  " << records.size() << " messages, " << platform.name << " ("
        << platform.cryptoCores << " crypto cores), reference rate " << num(rate, 0) << " msg/s\n\n";

    util::TextTable table({"Strategy", "Mean level", "Req. met", "Floor viol.", "Over-prot.",
                           "PQ coverage", "Mean CPU us", "p95 CPU us", "Overhead B",
                           "State B", "Max msg/s", "CPU @rate"});
    std::ofstream csv = openResult("static_vs_adaptive.csv");
    csv << "strategy,mean_level,requirement_met,floor_violations,over_protection,pq_coverage,"
           "mean_cpu_us,p95_cpu_us,mean_overhead_bytes,overhead_ratio,mean_state_bytes,"
           "throughput_msgs_per_s,cpu_at_reference_rate\n";

    for (const auto& strategy : standardStrategies(RiskParameters::defaults(), platform)) {
        const StrategyMetrics m = evaluateStrategy(records, *strategy, platform, rate);
        table.addRow({m.strategy, num(m.meanLevel, 2), pct(m.requirementMet), pct(m.floorViolations),
                      pct(m.overProtection), pct(m.quantumSafeCoverage), num(m.meanCpuMicros, 1),
                      num(m.p95CpuMicros, 1), num(m.meanOverheadBytes, 0), num(m.meanStateBytes, 0),
                      num(m.throughputPerSecond, 0), pct(m.cpuAtReferenceRate)});
        csv << m.strategy << ',' << m.meanLevel << ',' << m.requirementMet << ','
            << m.floorViolations << ',' << m.overProtection << ',' << m.quantumSafeCoverage << ','
            << m.meanCpuMicros << ',' << m.p95CpuMicros << ',' << m.meanOverheadBytes << ','
            << m.overheadRatio << ',' << m.meanStateBytes << ',' << m.throughputPerSecond << ','
            << m.cpuAtReferenceRate << '\n';
    }
    table.print(out);
    out << "  Req. met    = provided level >= reference level\n"
        << "  Floor viol. = provided level below the mandatory minimum (a security failure)\n"
        << "  CPU @rate   = share of the crypto cores needed at the reference rate (>100% = overload)\n"
        << "  Written to results/static_vs_adaptive.csv\n";
    return 0;
}

int cmdSimulate(const Options& options, std::ostream& out) {
    util::printBanner(out, "PHASE 6b - CLOSED-LOOP SIMULATION (LOAD + INTRUSION)");
    SimulationConfig config = SimulationConfig::standardScenario();
    config.seed = static_cast<std::uint32_t>(options.integer("seed", config.seed));
    config.platform = platformOption(options);
    const Simulator simulator(config);

    double rate = 0.0;
    for (const ChannelSpec& ch : config.channels) rate += ch.messagesPerSecond;
    out << "  " << config.channels.size() << " IPC channels, ~" << num(rate, 0) << " msg/s, "
        << config.durationSeconds << " s, deadline " << num(config.deadlineMs, 0) << " ms, "
        << config.platform.name << "\n  Phases:";
    for (const ScenarioPhase& p : config.phases) {
        out << " [" << num(p.startSecond, 0) << "-" << num(p.endSecond, 0) << "s " << p.name
            << ", bg CPU " << num(p.backgroundCpuPercent, 0) << "%, threat " << toString(p.trueThreat)
            << "]";
    }
    out << "\n\n";

    util::TextTable table({"Strategy", "Delivered", "Mean lat. ms", "p95 lat. ms", "p99 lat. ms",
                           "Mean CPU", "Peak CPU", "Mean level", "Req. met", "Floor viol.",
                           "Crit. viol.", "Overhead B"});
    std::ofstream summaryCsv = openResult("simulation_summary.csv");
    summaryCsv << "strategy,offered,delivered,dropped,delivery_ratio,mean_latency_ms,p95_latency_ms,"
                  "p99_latency_ms,mean_cpu_percent,peak_cpu_percent,mean_level,requirement_met,"
                  "floor_violation_rate,critical_floor_violations,mean_overhead_bytes,mean_state_bytes\n";
    std::ofstream series = openResult("simulation_timeseries.csv");
    series << "strategy,second,phase,offered,delivered,dropped,total_cpu_percent,crypto_cpu_percent,"
              "mean_latency_ms,mean_level,requirement_met,floor_violations,estimated_threat,"
              "compromised_trust,optimized_share\n";

    for (const auto& strategy : standardStrategies(RiskParameters::defaults(), config.platform)) {
        SimulationSummary s;
        const std::vector<PeriodRecord> periods = simulator.run(*strategy, s);
        table.addRow({s.strategy, pct(s.deliveryRatio), num(s.meanLatencyMs, 2), num(s.p95LatencyMs, 2),
                      num(s.p99LatencyMs, 2), num(s.meanCpuPercent, 1) + "%",
                      num(s.peakCpuPercent, 1) + "%", num(s.meanLevel, 2), pct(s.requirementMet),
                      pct(s.floorViolationRate), std::to_string(s.criticalFloorViolations),
                      num(s.meanOverheadBytes, 0)});
        summaryCsv << s.strategy << ',' << s.offered << ',' << s.delivered << ',' << s.dropped << ','
                   << s.deliveryRatio << ',' << s.meanLatencyMs << ',' << s.p95LatencyMs << ','
                   << s.p99LatencyMs << ',' << s.meanCpuPercent << ',' << s.peakCpuPercent << ','
                   << s.meanLevel << ',' << s.requirementMet << ',' << s.floorViolationRate << ','
                   << s.criticalFloorViolations << ',' << s.meanOverheadBytes << ','
                   << s.meanStateBytes << '\n';
        for (const PeriodRecord& p : periods) {
            series << s.strategy << ',' << p.second << ',' << p.phase << ',' << p.offered << ','
                   << p.delivered << ',' << p.dropped << ',' << util::fixed(p.totalCpuPercent, 2) << ','
                   << util::fixed(p.cryptoCpuPercent, 3) << ',' << util::fixed(p.meanLatencyMs, 4)
                   << ',' << util::fixed(p.meanLevel, 3) << ',' << util::fixed(p.requirementMet, 4)
                   << ',' << p.floorViolations << ',' << ordinal(p.estimatedThreat) << ','
                   << util::fixed(p.compromisedTrustEstimate, 3) << ','
                   << util::fixed(p.optimizedShare, 3) << '\n';
        }
    }
    table.print(out);
    out << "  Delivered   = messages processed within the " << num(config.deadlineMs, 0)
        << " ms IPC deadline\n"
        << "  Crit. viol. = critical messages protected below their mandatory minimum\n"
        << "  Written to results/simulation_summary.csv and results/simulation_timeseries.csv\n";
    return 0;
}

// ----- Benchmark ---------------------------------------------------------------------------

int cmdBench(const Options& options, std::ostream& out) {
    util::printBanner(out, "DECISION OVERHEAD BENCHMARK (measured)");
    const long long iterations = options.integer("iterations", 200000);
    if (iterations <= 0) throw std::invalid_argument("--iterations must be positive");
    const std::vector<DatasetRecord> records = DatasetGenerator(99).generate(4096);
    const AdaptivePolicyEngine engine;

    // Warm-up (also yields the mean crypto cost of the selected policies on the
    // reference platform), then the timed run. The checksum keeps the optimiser honest.
    long long checksum = 0;
    double cryptoMicros = 0.0;
    for (const DatasetRecord& r : records) {
        const PolicyDecision d = engine.decide(r.message, r.context);
        checksum += toInt(d.profile.level);
        cryptoMicros += estimateCost(d.profile, r.message.sizeBytes, referencePlatform()).cpuMicros;
    }
    cryptoMicros /= static_cast<double>(records.size());

    const auto start = std::chrono::steady_clock::now();
    for (long long i = 0; i < iterations; ++i) {
        const DatasetRecord& r = records[static_cast<std::size_t>(i) % records.size()];
        checksum += toInt(engine.decide(r.message, r.context).profile.level);
    }
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    const double nanos = seconds * 1e9 / static_cast<double>(iterations);

    out << "  " << iterations << " decisions in " << num(seconds * 1000.0, 1) << " ms on this machine\n"
        << "  Mean decision time : " << num(nanos, 0) << " ns  (" << num(1e9 / nanos / 1e6, 2)
        << " M decisions/s on one core)\n"
        << "  Mean crypto cost of the selected policies (reference x86-64 model): "
        << num(cryptoMicros, 1) << " us\n"
        << "  Decision overhead relative to that protection cost : "
        << util::percent(nanos / 1000.0 / cryptoMicros, 1) << "\n"
        << "  Checksum           : " << checksum << "\n";

    std::ofstream file = openResult("benchmark.txt");
    file << "iterations " << iterations << "\nmean_decision_ns " << util::fixed(nanos, 1)
         << "\nmean_selected_crypto_us_reference " << util::fixed(cryptoMicros, 2) << "\n";
    return 0;
}

// ----- Integration demo -------------------------------------------------------------------

int cmdDemo(const Options& options, std::ostream& out) {
    util::printBanner(out, "INTEGRATION DEMO - SecureIpcFramework + ISecureChannel");
    ModelledSecureChannel channel(platformOption(options));
    SecureIpcFramework framework(AdaptivePolicyEngine(), channel);
    framework.registerProcess(10, 0.9);  // trusted UI service
    framework.registerProcess(20, 0.6);  // third-party plug-in
    out << "  Channel: " << channel.name() << "\n"
        << "  The partner's PQC engine replaces ModelledSecureChannel by implementing ISecureChannel.\n\n";

    MessageArchetype status, alert;
    findArchetype("Status", status);
    findArchetype("Alert", alert);
    util::Random random(5);

    auto sendBoth = [&](const std::string& label) {
        out << "  -- " << label << " (threat " << toString(framework.threatMonitor().level())
            << ", plug-in trust " << num(framework.trustManager().trust(20), 2) << ")\n";
        const IpcMessage a = sampleMessage(status, 1, 10, 1, 0.0, random);
        const IpcMessage b = sampleMessage(alert, 2, 20, 1, 0.0, random);
        for (const IpcMessage& m : {a, b}) {
            const SecureIpcFramework::SendResult r = framework.send(m);
            out << "     " << toJson(m, r.decision) << "\n";
        }
    };

    framework.observeResources(35, 40);
    sendBoth("normal operation");

    for (int i = 0; i < 8; ++i) {  // an attack is detected over several periods
        for (int e = 0; e < 90; ++e) framework.reportSecurityEvent({SecurityEventType::AuthenticationFailure, 20});
        framework.endPeriod();
    }
    sendBoth("after repeated authentication failures from the plug-in");

    for (int i = 0; i < 4; ++i) framework.observeResources(92, 85);  // smoothed load rises
    sendBoth("same attack, system overloaded");
    return 0;
}

// ----- all ---------------------------------------------------------------------------------

int cmdAll(const Options& options, std::ostream& out) {
    using Command = std::function<int(const Options&, std::ostream&)>;
    const std::vector<std::pair<std::string, Command>> steps = {
        {"generate", cmdGenerate}, {"analyze", cmdAnalyze},     {"params", cmdParams},
        {"classify", cmdClassify}, {"calibrate", cmdCalibrate}, {"adapt", cmdAdapt},
        {"evaluate", cmdEvaluate}, {"simulate", cmdSimulate},   {"bench", cmdBench},
        {"demo", cmdDemo},
    };
    std::ostringstream report;
    report << "Adaptive Security Policy Engine " << kVersion << " - full pipeline report\n";
    for (const auto& step : steps) {
        std::ostringstream buffer;
        const int code = step.second(options, buffer);
        out << buffer.str() << std::flush;
        report << buffer.str();
        if (code != 0) return code;
    }
    std::ofstream file = openResult("report.txt");
    file << report.str();
    out << "\n  All phases completed. Console report saved to results/report.txt\n";
    return 0;
}

void printUsage(std::ostream& out) {
    out << "Adaptive Security Policy Engine (ASPE) " << kVersion << "\n"
        << "Adaptive post-quantum secure IPC: security policy and threat intelligence\n\n"
        << "Usage: aspe <command> [options]\n\n"
        << "Commands:\n"
        << "  all         Run every phase and write results/ (recommended first run)\n"
        << "  analyze     Phase 1  IPC threat catalogue and requirement analysis\n"
        << "  params      Phase 2  security parameters, context vectors, crypto suites\n"
        << "  generate    Synthetic dataset      [--count 5000] [--seed 42] [--out data/ipc_dataset.csv]\n"
        << "  classify    Phase 3  classification engine vs reference policy [--dataset PATH]\n"
        << "  calibrate   Phase 4  experimental calibration [--samples 6000] [--seed 7] [--penalty 4]\n"
        << "  decide      Phase 4  one decision with explanation\n"
        << "              --sensitivity LOW|MEDIUM|HIGH|CRITICAL --criticality ... --threat ...\n"
        << "              --trust 0..1|LOW|MEDIUM|HIGH --cpu % --memory % --size B --lifetime years\n"
        << "              [--type NAME] [--json]\n"
        << "  adapt       Phase 5  resource-aware adaptation sweep\n"
        << "  evaluate    Phase 6  static vs adaptive on the dataset [--rate 500]\n"
        << "  simulate    Phase 6  closed-loop simulation with load and intrusion [--seed 2024]\n"
        << "  bench       Measured decision overhead [--iterations 200000]\n"
        << "  demo        Integration demo through the ISecureChannel interface\n"
        << "  help        Show this text\n\n"
        << "Common options: --platform embedded|reference (default embedded)\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage(std::cout);
        return 2;
    }
    const std::string command = argv[1];
    if (command == "help" || command == "--help" || command == "-h") {
        printUsage(std::cout);
        return 0;
    }
    if (command == "version" || command == "--version") {
        std::cout << "aspe " << kVersion << "\n";
        return 0;
    }

    const std::map<std::string, std::function<int(const Options&, std::ostream&)>> commands = {
        {"all", cmdAll},           {"analyze", cmdAnalyze},   {"params", cmdParams},
        {"generate", cmdGenerate}, {"classify", cmdClassify}, {"calibrate", cmdCalibrate},
        {"decide", cmdDecide},     {"adapt", cmdAdapt},       {"evaluate", cmdEvaluate},
        {"simulate", cmdSimulate}, {"bench", cmdBench},       {"demo", cmdDemo},
    };
    const auto it = commands.find(command);
    if (it == commands.end()) {
        std::cerr << "aspe: unknown command '" << command << "'\n\n";
        printUsage(std::cerr);
        return 2;
    }

    Options options;
    std::string error;
    if (!options.parse(argc, argv, 2, error)) {
        std::cerr << "aspe: " << error << "\n";
        return 2;
    }
    try {
        return it->second(options, std::cout);
    } catch (const std::invalid_argument& e) {
        std::cerr << "aspe: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "aspe: error: " << e.what() << "\n";
        return 1;
    }
}
