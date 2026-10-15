// ---------------------------------------------------------------------------
// Risk model (Phases 3 and 4).
//
//   Impact      I = a * max(S, C) + (1 - a) * (S + C) / 2
//   Likelihood  L = b * H         + (1 - b) * D            (D = 1 - trust)
//   Risk        R = wI * I + wL * L + wX * I * L          (wI + wL + wX = 1)
//
// R lies in [0, 1] and is mapped to one of five risk bands by four ascending
// thresholds. The weights and thresholds are determined experimentally by
// the calibration procedure (see evaluation.h, `aspe calibrate`).
// ---------------------------------------------------------------------------
#ifndef ASPE_RISK_MODEL_H
#define ASPE_RISK_MODEL_H

#include <array>
#include <string>

#include "aspe/parameters.h"
#include "aspe/types.h"

namespace aspe {

struct RiskParameters {
    double alpha = 0.0;         ///< a  : weight of max(S, C) inside the impact term
    double beta = 0.0;          ///< b  : weight of threat (vs. distrust) in likelihood
    double wImpact = 0.0;       ///< wI
    double wLikelihood = 0.0;   ///< wL
    double wInteraction = 0.0;  ///< wX = 1 - wI - wL
    /// Lower bounds of bands L2..L5.
    std::array<double, 4> thresholds = {{0.0, 0.0, 0.0, 0.0}};

    /// Calibrated defaults (produced by `aspe calibrate` on the seed-42 dataset).
    static RiskParameters defaults();

    /// Weights non-negative and summing to 1, thresholds strictly ascending in (0, 1).
    bool isValid() const;
    std::string toString() const;
};

struct RiskAssessment {
    double impact = 0.0;
    double likelihood = 0.0;
    double score = 0.0;
    SecurityLevel band = SecurityLevel::Basic;
    double gapToLowerBound = 0.0;  ///< score - lower threshold of the band
    double gapToUpperBound = 0.0;  ///< upper threshold of the band - score (inf. for L5)
};

class RiskModel {
public:
    explicit RiskModel(RiskParameters parameters = RiskParameters::defaults());

    RiskAssessment assess(const ContextVector& context) const;
    SecurityLevel bandFor(double score) const;
    const RiskParameters& parameters() const { return parameters_; }

private:
    RiskParameters parameters_;
};

}  // namespace aspe

#endif  // ASPE_RISK_MODEL_H
