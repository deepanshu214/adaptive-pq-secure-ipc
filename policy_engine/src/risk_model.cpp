#include "aspe/risk_model.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <sstream>
#include <stdexcept>

#include "aspe/util.h"

namespace aspe {

RiskParameters RiskParameters::defaults() {
    // Obtained with `aspe calibrate` on the default dataset (5000 records,
    // generator seed 42, split seed 7) and rounded to three decimals.
    // See results/calibration.txt.
    RiskParameters p;
    p.alpha = 0.844;
    p.beta = 0.517;
    p.wImpact = 0.473;
    p.wLikelihood = 0.247;
    p.wInteraction = 0.280;
    p.thresholds = {{0.078, 0.298, 0.514, 0.805}};
    return p;
}

bool RiskParameters::isValid() const {
    const double eps = 1e-6;
    if (alpha < 0.0 || alpha > 1.0 || beta < 0.0 || beta > 1.0) return false;
    if (wImpact < 0.0 || wLikelihood < 0.0 || wInteraction < 0.0) return false;
    if (std::fabs(wImpact + wLikelihood + wInteraction - 1.0) > eps) return false;
    if (thresholds[0] <= 0.0 || thresholds[3] >= 1.0) return false;
    for (std::size_t i = 1; i < thresholds.size(); ++i) {
        if (thresholds[i] <= thresholds[i - 1]) return false;
    }
    return true;
}

std::string RiskParameters::toString() const {
    std::ostringstream out;
    out << "alpha=" << util::fixed(alpha, 3) << " beta=" << util::fixed(beta, 3)
        << " wI=" << util::fixed(wImpact, 3) << " wL=" << util::fixed(wLikelihood, 3)
        << " wX=" << util::fixed(wInteraction, 3) << " thresholds=["
        << util::fixed(thresholds[0], 3) << ", " << util::fixed(thresholds[1], 3) << ", "
        << util::fixed(thresholds[2], 3) << ", " << util::fixed(thresholds[3], 3) << "]";
    return out.str();
}

RiskModel::RiskModel(RiskParameters parameters) : parameters_(parameters) {
    if (!parameters_.isValid()) {
        throw std::invalid_argument("invalid risk parameters: " + parameters_.toString());
    }
}

SecurityLevel RiskModel::bandFor(double score) const {
    int level = kMinLevel;
    for (double threshold : parameters_.thresholds) {
        if (score >= threshold) ++level;
    }
    return levelFromInt(level);
}

RiskAssessment RiskModel::assess(const ContextVector& c) const {
    const RiskParameters& p = parameters_;
    RiskAssessment a;
    a.impact = p.alpha * std::max(c.sensitivity, c.criticality) +
               (1.0 - p.alpha) * 0.5 * (c.sensitivity + c.criticality);
    a.likelihood = p.beta * c.threat + (1.0 - p.beta) * c.distrust;
    a.score = util::clamp01(p.wImpact * a.impact + p.wLikelihood * a.likelihood +
                            p.wInteraction * a.impact * a.likelihood);
    a.band = bandFor(a.score);

    const int index = toInt(a.band) - 1;  // 0..4
    const double lower = index == 0 ? 0.0 : p.thresholds[index - 1];
    const double upper =
        index == 4 ? std::numeric_limits<double>::infinity() : p.thresholds[index];
    a.gapToLowerBound = a.score - lower;
    a.gapToUpperBound = upper - a.score;
    return a;
}

}  // namespace aspe
