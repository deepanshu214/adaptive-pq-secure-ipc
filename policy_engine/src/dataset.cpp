#include "aspe/dataset.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>

namespace aspe {

namespace {

// Reference risk matrix: rows = impact tier, columns = likelihood tier.
const int kRiskMatrix[4][4] = {
    {1, 2, 2, 2},  // LOW impact
    {2, 2, 3, 3},  // MEDIUM impact
    {3, 3, 4, 4},  // HIGH impact
    {4, 4, 4, 5},  // CRITICAL impact
};

template <typename Enum>
Enum shiftOrdinal(Enum value, int delta, int count) {
    const int shifted = std::max(0, std::min(count - 1, ordinal(value) + delta));
    return static_cast<Enum>(shifted);
}

const char* const kCsvHeader =
    "id,type,sender_pid,receiver_pid,size_bytes,sensitivity,criticality,lifetime_years,"
    "process_trust,trust_level,threat,cpu_percent,memory_percent,required_level,required_policy";

void setError(std::string* error, const std::string& message) {
    if (error) *error = message;
}

}  // namespace

const std::vector<MessageArchetype>& messageArchetypes() {
    static const std::vector<MessageArchetype> archetypes = {
        {"Status", Sensitivity::Low, Criticality::Low, 32, 256, 0.0, 0.1, 14},
        {"Heartbeat", Sensitivity::Low, Criticality::Medium, 16, 64, 0.0, 0.05, 10},
        {"Telemetry", Sensitivity::Low, Criticality::Low, 256, 4096, 0.0, 1.0, 12},
        {"Gaze", Sensitivity::Medium, Criticality::Medium, 64, 512, 0.5, 3.0, 12},
        {"Configuration", Sensitivity::Medium, Criticality::High, 512, 8192, 1.0, 5.0, 8},
        {"Profile", Sensitivity::High, Criticality::High, 1024, 16384, 5.0, 20.0, 10},
        {"Credential", Sensitivity::High, Criticality::High, 128, 1024, 2.0, 15.0, 7},
        {"Payment", Sensitivity::Critical, Criticality::High, 256, 2048, 7.0, 25.0, 6},
        {"Emergency", Sensitivity::Critical, Criticality::Critical, 128, 2048, 10.0, 30.0, 6},
        {"Alert", Sensitivity::Critical, Criticality::Critical, 64, 1024, 5.0, 25.0, 8},
        {"KeyMaterial", Sensitivity::Critical, Criticality::Critical, 32, 256, 15.0, 30.0, 4},
    };
    return archetypes;
}

bool findArchetype(const std::string& type, MessageArchetype& out) {
    const std::string key = util::toUpper(type);
    for (const MessageArchetype& a : messageArchetypes()) {
        if (util::toUpper(a.type) == key) {
            out = a;
            return true;
        }
    }
    return false;
}

SecurityLevel referenceRequiredLevel(const IpcMessage& message, const RuntimeContext& context,
                                     const QuantumHorizon& horizon) {
    const int impact = std::max(ordinal(message.sensitivity), ordinal(message.criticality));
    const TrustLevel trust = trustLevelFromScore(context.processTrust);
    int likelihood = ordinal(context.threat);
    if (trust == TrustLevel::Low) ++likelihood;
    if (trust == TrustLevel::High) --likelihood;
    likelihood = std::max(0, std::min(3, likelihood));

    int level = kRiskMatrix[impact][likelihood];
    const bool confidential = ordinal(message.sensitivity) >= ordinal(Sensitivity::Medium);
    if (confidential && horizon.isExposed(message.lifetimeYears)) {
        level = std::max(level, toInt(SecurityLevel::Hybrid));
    }
    return levelFromInt(level);
}

IpcMessage sampleMessage(const MessageArchetype& archetype, std::uint64_t id, int senderPid,
                         int receiverPid, double variationProbability, util::Random& random) {
    IpcMessage m;
    m.id = id;
    m.type = archetype.type;
    m.senderPid = senderPid;
    m.receiverPid = receiverPid;

    const double logMin = std::log(static_cast<double>(std::max<std::uint32_t>(1, archetype.minSize)));
    const double logMax = std::log(static_cast<double>(std::max(archetype.minSize, archetype.maxSize)));
    m.sizeBytes = static_cast<std::uint32_t>(std::lround(std::exp(random.uniform(logMin, logMax))));

    m.sensitivity = archetype.sensitivity;
    m.criticality = archetype.criticality;
    if (random.bernoulli(variationProbability)) {
        m.sensitivity = shiftOrdinal(m.sensitivity, random.bernoulli(0.5) ? 1 : -1, 4);
    }
    if (random.bernoulli(variationProbability)) {
        m.criticality = shiftOrdinal(m.criticality, random.bernoulli(0.5) ? 1 : -1, 4);
    }
    m.lifetimeYears = random.uniform(archetype.minLifetimeYears, archetype.maxLifetimeYears);
    return m;
}

std::vector<DatasetRecord> DatasetGenerator::generate(std::size_t count) const {
    util::Random random(seed_);
    const std::vector<MessageArchetype>& archetypes = messageArchetypes();
    std::vector<double> weights;
    for (const MessageArchetype& a : archetypes) weights.push_back(a.weight);

    const std::vector<double> threatWeights = {0.40, 0.30, 0.20, 0.10};
    const std::vector<double> trustWeights = {0.12, 0.28, 0.60};  // LOW, MEDIUM, HIGH

    std::vector<DatasetRecord> records;
    records.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        DatasetRecord r;
        const MessageArchetype& archetype = archetypes[random.weightedIndex(weights)];
        const int sender = random.uniformInt(100, 139);
        int receiver = random.uniformInt(100, 139);
        if (receiver == sender) receiver = sender == 139 ? 100 : sender + 1;
        r.message = sampleMessage(archetype, i + 1, sender, receiver, 0.25, random);

        switch (random.weightedIndex(trustWeights)) {
            case 0: r.context.processTrust = random.uniform(0.05, 0.40); break;
            case 1: r.context.processTrust = random.uniform(0.40, 0.70); break;
            default: r.context.processTrust = random.uniform(0.70, 0.98); break;
        }
        r.context.threat = static_cast<ThreatLevel>(random.weightedIndex(threatWeights));
        r.context.cpuPercent = std::round(random.uniform(10.0, 95.0));
        r.context.memoryPercent = std::round(random.uniform(15.0, 95.0));
        r.requiredLevel = referenceRequiredLevel(r.message, r.context, horizon_);
        records.push_back(r);
    }
    return records;
}

std::vector<DatasetRecord> specificationScenarios() {
    struct Row {
        const char* type;
        Sensitivity s;
        TrustLevel t;
        ThreatLevel h;
        Criticality c;
        double cpu;
        double memory;
        std::uint32_t size;
        double lifetime;
        SecurityLevel expected;
    };
    const Row rows[] = {
        {"Status", Sensitivity::Low, TrustLevel::High, ThreatLevel::Low, Criticality::Low, 30, 40,
         128, 0.05, SecurityLevel::Basic},
        {"Gaze", Sensitivity::Medium, TrustLevel::High, ThreatLevel::Low, Criticality::Medium, 40,
         45, 256, 1.0, SecurityLevel::Classical},
        {"Profile", Sensitivity::High, TrustLevel::Medium, ThreatLevel::Medium, Criticality::High,
         50, 50, 4096, 8.0, SecurityLevel::Hybrid},
        {"Emergency", Sensitivity::Critical, TrustLevel::Medium, ThreatLevel::High,
         Criticality::Critical, 60, 55, 512, 15.0, SecurityLevel::PostQuantum},
        {"Alert", Sensitivity::Critical, TrustLevel::Low, ThreatLevel::High, Criticality::Critical,
         80, 60, 256, 12.0, SecurityLevel::StrongPostQuantum},
    };

    std::vector<DatasetRecord> records;
    std::uint64_t id = 1;
    for (const Row& row : rows) {
        DatasetRecord r;
        r.message.id = id++;
        r.message.type = row.type;
        r.message.senderPid = 10 + static_cast<int>(id);
        r.message.receiverPid = 1;
        r.message.sizeBytes = row.size;
        r.message.sensitivity = row.s;
        r.message.criticality = row.c;
        r.message.lifetimeYears = row.lifetime;
        r.context.processTrust = representativeTrustScore(row.t);
        r.context.threat = row.h;
        r.context.cpuPercent = row.cpu;
        r.context.memoryPercent = row.memory;
        r.requiredLevel = row.expected;
        records.push_back(r);
    }
    return records;
}

bool writeDatasetCsv(const std::string& path, const std::vector<DatasetRecord>& records,
                     std::string* error) {
    util::ensureDirectory(util::parentDirectory(path));
    std::ofstream out(path.c_str());
    if (!out) {
        setError(error, "cannot open '" + path + "' for writing");
        return false;
    }
    out << kCsvHeader << '\n';
    for (const DatasetRecord& r : records) {
        const IpcMessage& m = r.message;
        const RuntimeContext& c = r.context;
        out << m.id << ',' << m.type << ',' << m.senderPid << ',' << m.receiverPid << ','
            << m.sizeBytes << ',' << toString(m.sensitivity) << ',' << toString(m.criticality)
            << ',' << util::fixed(m.lifetimeYears, 2) << ',' << util::fixed(c.processTrust, 3)
            << ',' << toString(trustLevelFromScore(c.processTrust)) << ',' << toString(c.threat)
            << ',' << util::fixed(c.cpuPercent, 1) << ',' << util::fixed(c.memoryPercent, 1)
            << ',' << toInt(r.requiredLevel) << ',' << toString(r.requiredLevel) << '\n';
    }
    if (!out) {
        setError(error, "write error on '" + path + "'");
        return false;
    }
    return true;
}

bool readDatasetCsv(const std::string& path, std::vector<DatasetRecord>& records,
                    std::string* error) {
    std::ifstream in(path.c_str());
    if (!in) {
        setError(error, "cannot open '" + path + "' (run `aspe generate` first)");
        return false;
    }

    std::string line;
    if (!std::getline(in, line)) {
        setError(error, "'" + path + "' is empty");
        return false;
    }
    std::map<std::string, std::size_t> column;
    const std::vector<std::string> header = util::split(util::trim(line), ',');
    for (std::size_t i = 0; i < header.size(); ++i) column[util::trim(header[i])] = i;

    const char* const required[] = {"id", "type", "sender_pid", "receiver_pid", "size_bytes",
                                    "sensitivity", "criticality", "lifetime_years",
                                    "process_trust", "threat", "cpu_percent", "memory_percent",
                                    "required_level"};
    for (const char* name : required) {
        if (column.find(name) == column.end()) {
            setError(error, "'" + path + "' has no column '" + name + "'");
            return false;
        }
    }

    std::vector<DatasetRecord> parsed;
    std::size_t lineNumber = 1;
    while (std::getline(in, line)) {
        ++lineNumber;
        if (util::trim(line).empty()) continue;
        const std::vector<std::string> f = util::split(util::trim(line), ',');
        if (f.size() < header.size()) {
            setError(error, path + ":" + std::to_string(lineNumber) + ": too few fields");
            return false;
        }
        auto field = [&](const char* name) { return util::trim(f[column[name]]); };

        DatasetRecord r;
        long long id = 0, sender = 0, receiver = 0, size = 0, level = 0;
        double lifetime = 0, trust = 0, cpu = 0, memory = 0;
        const bool ok =
            util::parseInt(field("id"), id) && util::parseInt(field("sender_pid"), sender) &&
            util::parseInt(field("receiver_pid"), receiver) &&
            util::parseInt(field("size_bytes"), size) && size >= 0 &&
            parse(field("sensitivity"), r.message.sensitivity) &&
            parse(field("criticality"), r.message.criticality) &&
            util::parseDouble(field("lifetime_years"), lifetime) &&
            util::parseDouble(field("process_trust"), trust) &&
            parse(field("threat"), r.context.threat) &&
            util::parseDouble(field("cpu_percent"), cpu) &&
            util::parseDouble(field("memory_percent"), memory) &&
            util::parseInt(field("required_level"), level) && level >= kMinLevel &&
            level <= kMaxLevel;
        if (!ok) {
            setError(error, path + ":" + std::to_string(lineNumber) + ": invalid value");
            return false;
        }
        r.message.id = static_cast<std::uint64_t>(id);
        r.message.type = field("type");
        r.message.senderPid = static_cast<int>(sender);
        r.message.receiverPid = static_cast<int>(receiver);
        r.message.sizeBytes = static_cast<std::uint32_t>(size);
        r.message.lifetimeYears = lifetime;
        r.context.processTrust = trust;
        r.context.cpuPercent = cpu;
        r.context.memoryPercent = memory;
        r.requiredLevel = levelFromInt(static_cast<int>(level));
        parsed.push_back(r);
    }
    records.swap(parsed);
    return true;
}

}  // namespace aspe
