// ---------------------------------------------------------------------------
// Phase 2 - Security parameters and context extraction.
//
// Turns the qualitative / raw attributes of an IPC message and its runtime
// environment into a normalised context vector in which every component lies
// in [0, 1] (0 = harmless / idle, 1 = worst case).
// ---------------------------------------------------------------------------
#ifndef ASPE_PARAMETERS_H
#define ASPE_PARAMETERS_H

#include <string>
#include <vector>

#include "aspe/types.h"

namespace aspe {

/// Mosca's inequality: data is exposed to "harvest now, decrypt later" if
/// (confidentiality lifetime + migration time) > time until a cryptographically
/// relevant quantum computer exists.
struct QuantumHorizon {
    double migrationYears = 5.0;       ///< y: time needed to migrate deployed systems
    double quantumThreatYears = 15.0;  ///< z: conservative estimate until Q-day

    bool isExposed(double lifetimeYears) const {
        return lifetimeYears + migrationYears > quantumThreatYears;
    }
};

/// Normalised view of a message and its environment.
struct ContextVector {
    double sensitivity = 0.0;       ///< S
    double criticality = 0.0;       ///< C
    double threat = 0.0;            ///< H
    double distrust = 0.0;          ///< 1 - T (T = process trust)
    double cpu = 0.0;               ///< CPU utilisation
    double memory = 0.0;            ///< Memory utilisation
    double size = 0.0;              ///< log-scaled message size
    double resourcePressure = 0.0;  ///< max(cpu, memory)
    bool quantumExposed = false;    ///< Mosca's inequality holds
    double quantumExposure = 0.0;   ///< (x + y) / z clamped to [0, 1]; 1 when exposed

    // The original qualitative values are kept for rule-based checks.
    Sensitivity sensitivityLevel = Sensitivity::Low;
    Criticality criticalityLevel = Criticality::Low;
    ThreatLevel threatLevel = ThreatLevel::Low;
    TrustLevel trustLevel = TrustLevel::High;
    double lifetimeYears = 0.0;
};

/// Documentation entry for one measurable security parameter.
struct ParameterSpec {
    std::string name;
    std::string symbol;
    std::string domain;
    std::string normalisation;
    std::string role;
};

/// Catalogue of the parameters used by the engine (printed by `aspe params`).
const std::vector<ParameterSpec>& parameterCatalogue();

/// Maps an ordinal scale value to [0, 1]: index / (count - 1).
double normaliseOrdinal(int index, int count);
/// Log-scaled size: 16 B -> 0, 1 MiB -> 1.
double normaliseSize(std::uint32_t sizeBytes);

class ContextExtractor {
public:
    explicit ContextExtractor(QuantumHorizon horizon = QuantumHorizon()) : horizon_(horizon) {}

    ContextVector extract(const IpcMessage& message, const RuntimeContext& context) const;
    const QuantumHorizon& horizon() const { return horizon_; }

private:
    QuantumHorizon horizon_;
};

}  // namespace aspe

#endif  // ASPE_PARAMETERS_H
