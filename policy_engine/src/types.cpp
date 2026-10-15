#include "aspe/types.h"

#include <algorithm>
#include <cctype>

#include "aspe/util.h"

namespace aspe {

namespace {

const char* const kFourLevelNames[] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
const char* const kTrustNames[] = {"LOW", "MEDIUM", "HIGH"};

template <typename Enum>
bool parseOrdinalScale(const std::string& text, const char* const* names, int count,
                       Enum& out) {
    const std::string key = util::toUpper(util::trim(text));
    for (int i = 0; i < count; ++i) {
        if (key == names[i] || key == std::to_string(i)) {
            out = static_cast<Enum>(i);
            return true;
        }
    }
    // Common abbreviations.
    if (key == "MED") {
        out = static_cast<Enum>(1);
        return true;
    }
    if (key == "CRIT" && count == 4) {
        out = static_cast<Enum>(3);
        return true;
    }
    return false;
}

}  // namespace

SecurityLevel levelFromInt(int value) {
    return static_cast<SecurityLevel>(std::max(kMinLevel, std::min(kMaxLevel, value)));
}

SecurityLevel stepUp(SecurityLevel level) { return levelFromInt(toInt(level) + 1); }

SecurityLevel stepDown(SecurityLevel level) { return levelFromInt(toInt(level) - 1); }

SecurityLevel maxLevel(SecurityLevel a, SecurityLevel b) {
    return toInt(a) >= toInt(b) ? a : b;
}

TrustLevel trustLevelFromScore(double trustScore) {
    if (trustScore >= 0.70) return TrustLevel::High;
    if (trustScore >= 0.40) return TrustLevel::Medium;
    return TrustLevel::Low;
}

double representativeTrustScore(TrustLevel level) {
    switch (level) {
        case TrustLevel::High: return 0.85;
        case TrustLevel::Medium: return 0.55;
        case TrustLevel::Low: return 0.20;
    }
    return 0.5;
}

std::string toString(Sensitivity value) { return kFourLevelNames[ordinal(value)]; }
std::string toString(Criticality value) { return kFourLevelNames[ordinal(value)]; }
std::string toString(ThreatLevel value) { return kFourLevelNames[ordinal(value)]; }
std::string toString(TrustLevel value) { return kTrustNames[ordinal(value)]; }

std::string toString(SecurityLevel value) {
    switch (value) {
        case SecurityLevel::Basic: return "BASIC";
        case SecurityLevel::Classical: return "CLASSICAL";
        case SecurityLevel::Hybrid: return "HYBRID";
        case SecurityLevel::PostQuantum: return "POST_QUANTUM";
        case SecurityLevel::StrongPostQuantum: return "STRONG_PQ";
    }
    return "UNKNOWN";
}

std::string shortName(SecurityLevel value) {
    switch (value) {
        case SecurityLevel::Basic: return "L1-BASIC";
        case SecurityLevel::Classical: return "L2-CLASSICAL";
        case SecurityLevel::Hybrid: return "L3-HYBRID";
        case SecurityLevel::PostQuantum: return "L4-PQ";
        case SecurityLevel::StrongPostQuantum: return "L5-STRONG-PQ";
    }
    return "UNKNOWN";
}

bool parse(const std::string& text, Sensitivity& out) {
    return parseOrdinalScale(text, kFourLevelNames, 4, out);
}

bool parse(const std::string& text, Criticality& out) {
    return parseOrdinalScale(text, kFourLevelNames, 4, out);
}

bool parse(const std::string& text, ThreatLevel& out) {
    return parseOrdinalScale(text, kFourLevelNames, 4, out);
}

bool parse(const std::string& text, TrustLevel& out) {
    return parseOrdinalScale(text, kTrustNames, 3, out);
}

bool parse(const std::string& text, SecurityLevel& out) {
    std::string key = util::toUpper(util::trim(text));
    std::replace(key.begin(), key.end(), '-', '_');
    if (key.size() == 2 && key[0] == 'L') key = key.substr(1);
    if (key.size() > 3 && key[0] == 'L' && std::isdigit(static_cast<unsigned char>(key[1])) &&
        key[2] == '_') {
        key = key.substr(3);  // "L3_HYBRID" -> "HYBRID"
    }

    if (key == "1" || key == "BASIC") out = SecurityLevel::Basic;
    else if (key == "2" || key == "CLASSICAL" || key == "SECURE") out = SecurityLevel::Classical;
    else if (key == "3" || key == "HYBRID") out = SecurityLevel::Hybrid;
    else if (key == "4" || key == "PQ" || key == "POST_QUANTUM") out = SecurityLevel::PostQuantum;
    else if (key == "5" || key == "STRONG_PQ" || key == "STRONG_POST_QUANTUM")
        out = SecurityLevel::StrongPostQuantum;
    else return false;
    return true;
}

}  // namespace aspe
