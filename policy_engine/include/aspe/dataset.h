// ---------------------------------------------------------------------------
// Synthetic IPC dataset (independent input of this project).
//
// Each record is an IPC message, the runtime context at send time and the
// security level required by an independent *reference policy*: a
// qualitative risk matrix (impact tier x likelihood tier) in the style of
// NIST SP 800-30, extended with Mosca's quantum-exposure rule. The engine is
// evaluated and calibrated against this reference, which it does not use.
// ---------------------------------------------------------------------------
#ifndef ASPE_DATASET_H
#define ASPE_DATASET_H

#include <cstdint>
#include <string>
#include <vector>

#include "aspe/parameters.h"
#include "aspe/types.h"
#include "aspe/util.h"

namespace aspe {

struct DatasetRecord {
    IpcMessage message;
    RuntimeContext context;
    SecurityLevel requiredLevel = SecurityLevel::Basic;  ///< reference label
};

/// Template from which messages of one application type are drawn.
struct MessageArchetype {
    std::string type;
    Sensitivity sensitivity;
    Criticality criticality;
    std::uint32_t minSize;
    std::uint32_t maxSize;
    double minLifetimeYears;
    double maxLifetimeYears;
    double weight;  ///< relative frequency in the dataset
};

const std::vector<MessageArchetype>& messageArchetypes();
bool findArchetype(const std::string& type, MessageArchetype& out);

/// Reference ("expert") policy used as ground truth.
///   impact tier     = max(S, C)
///   likelihood tier = clamp(H + [trust LOW] - [trust HIGH], 0, 3)
///   level           = matrix[impact][likelihood]
///   + Mosca rule    : S >= MEDIUM and quantum-exposed -> at least HYBRID
SecurityLevel referenceRequiredLevel(const IpcMessage& message, const RuntimeContext& context,
                                     const QuantumHorizon& horizon = QuantumHorizon());

/// Draws one message of the given archetype (attributes vary around it).
/// With probability `variationProbability` sensitivity and criticality are
/// each shifted one step up or down.
IpcMessage sampleMessage(const MessageArchetype& archetype, std::uint64_t id, int senderPid,
                         int receiverPid, double variationProbability, util::Random& random);

class DatasetGenerator {
public:
    explicit DatasetGenerator(std::uint32_t seed = 42, QuantumHorizon horizon = QuantumHorizon())
        : seed_(seed), horizon_(horizon) {}

    std::vector<DatasetRecord> generate(std::size_t count) const;

private:
    std::uint32_t seed_;
    QuantumHorizon horizon_;
};

/// The five illustrative scenarios from the project specification
/// (Status, Gaze, Profile, Emergency, Alert) with their expected levels.
std::vector<DatasetRecord> specificationScenarios();

bool writeDatasetCsv(const std::string& path, const std::vector<DatasetRecord>& records,
                     std::string* error = nullptr);
bool readDatasetCsv(const std::string& path, std::vector<DatasetRecord>& records,
                    std::string* error = nullptr);

}  // namespace aspe

#endif  // ASPE_DATASET_H
