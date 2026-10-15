// ---------------------------------------------------------------------------
// Phase 3 - Security classification engine.
//
//   IPC message -> context extraction -> requirement analysis (Phase 1)
//               -> risk assessment -> security level (L1 .. L5)
//
// The required level is the maximum of the risk band and the requirement
// floor, so a message can never be classified below the services it needs.
// ---------------------------------------------------------------------------
#ifndef ASPE_CLASSIFIER_H
#define ASPE_CLASSIFIER_H

#include <string>
#include <vector>

#include "aspe/parameters.h"
#include "aspe/risk_model.h"
#include "aspe/threat_analysis.h"
#include "aspe/types.h"

namespace aspe {

struct Classification {
    ContextVector context;
    SecurityRequirements requirements;
    RiskAssessment risk;
    SecurityLevel riskBand = SecurityLevel::Basic;
    SecurityLevel requirementFloor = SecurityLevel::Basic;
    SecurityLevel level = SecurityLevel::Basic;  ///< Required security level
    bool raisedByRequirements = false;           ///< Floor was above the risk band
};

class SecurityClassifier {
public:
    explicit SecurityClassifier(RiskModel model = RiskModel(),
                                ContextExtractor extractor = ContextExtractor())
        : model_(model), extractor_(extractor) {}

    Classification classify(const IpcMessage& message, const RuntimeContext& context) const;

    /// Step-by-step explanation of a classification (for the CLI / reports).
    std::vector<std::string> explain(const Classification& classification) const;

    const RiskModel& riskModel() const { return model_; }
    const ContextExtractor& extractor() const { return extractor_; }

private:
    RiskModel model_;
    ContextExtractor extractor_;
    SecurityAnalyzer analyzer_;
};

}  // namespace aspe

#endif  // ASPE_CLASSIFIER_H
