#include "aspe/parameters.h"

#include <algorithm>
#include <cmath>

#include "aspe/util.h"

namespace aspe {

const std::vector<ParameterSpec>& parameterCatalogue() {
    static const std::vector<ParameterSpec> catalogue = {
        {"Message sensitivity", "S", "LOW | MEDIUM | HIGH | CRITICAL", "ordinal / 3",
         "Impact of disclosure (confidentiality)"},
        {"Communication criticality", "C", "LOW | MEDIUM | HIGH | CRITICAL", "ordinal / 3",
         "Impact of tampering / loss (integrity, availability)"},
        {"Threat level", "H", "LOW | MEDIUM | HIGH | CRITICAL", "ordinal / 3",
         "Likelihood of an active attack (from threat monitor)"},
        {"Process trust", "T", "[0, 1] score (LOW < 0.4 <= MEDIUM < 0.7 <= HIGH)", "D = 1 - T",
         "Likelihood that the sender is malicious / impersonated"},
        {"CPU utilisation", "U_cpu", "[0, 100] %", "value / 100",
         "Available compute budget for cryptography"},
        {"Memory utilisation", "U_mem", "[0, 100] %", "value / 100",
         "Available memory for key material and buffers"},
        {"Message size", "M", "bytes", "log2(M/16) / 16, clamped",
         "Symmetric cost and wire overhead"},
        {"Confidentiality lifetime", "x", "years", "Mosca: x + y > z",
         "Exposure to harvest-now-decrypt-later attacks"},
        {"Resource pressure", "P", "derived", "max(U_cpu, U_mem)",
         "Selects the resource state used by the adaptation step"},
    };
    return catalogue;
}

double normaliseOrdinal(int index, int count) {
    if (count <= 1) return 0.0;
    return util::clamp01(static_cast<double>(index) / static_cast<double>(count - 1));
}

double normaliseSize(std::uint32_t sizeBytes) {
    // log2(16) = 4, log2(1 MiB) = 20 -> 16 octaves mapped to [0, 1].
    const double bytes = std::max(16.0, static_cast<double>(sizeBytes));
    return util::clamp01((std::log2(bytes) - 4.0) / 16.0);
}

ContextVector ContextExtractor::extract(const IpcMessage& message,
                                        const RuntimeContext& context) const {
    ContextVector v;
    v.sensitivityLevel = message.sensitivity;
    v.criticalityLevel = message.criticality;
    v.threatLevel = context.threat;
    v.lifetimeYears = std::max(0.0, message.lifetimeYears);

    const double trust = util::clamp01(context.processTrust);
    v.trustLevel = trustLevelFromScore(trust);

    v.sensitivity = normaliseOrdinal(ordinal(message.sensitivity), 4);
    v.criticality = normaliseOrdinal(ordinal(message.criticality), 4);
    v.threat = normaliseOrdinal(ordinal(context.threat), 4);
    v.distrust = 1.0 - trust;
    v.cpu = util::clamp01(context.cpuPercent / 100.0);
    v.memory = util::clamp01(context.memoryPercent / 100.0);
    v.size = normaliseSize(message.sizeBytes);
    v.resourcePressure = std::max(v.cpu, v.memory);
    v.quantumExposed = horizon_.isExposed(v.lifetimeYears);
    v.quantumExposure =
        v.quantumExposed
            ? 1.0
            : util::clamp01((v.lifetimeYears + horizon_.migrationYears) /
                            std::max(1e-9, horizon_.quantumThreatYears));
    return v;
}

}  // namespace aspe
