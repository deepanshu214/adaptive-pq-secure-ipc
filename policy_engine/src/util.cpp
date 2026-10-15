#include "aspe/util.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ostream>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#endif

namespace aspe {
namespace util {

// ----- Strings ---------------------------------------------------------------------

std::string trim(const std::string& text) {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin]))) ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) --end;
    return text.substr(begin, end - begin);
}

std::string toUpper(std::string text) {
    for (char& c : text) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return text;
}

std::vector<std::string> split(const std::string& text, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : text) {
        if (c == delimiter) {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(current);
    return parts;
}

std::string fixed(double value, int precision) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f", precision, value);
    return buffer;
}

std::string percent(double ratio, int precision) { return fixed(ratio * 100.0, precision) + "%"; }

std::string boolText(bool value) { return value ? "yes" : "no"; }

std::string jsonEscape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

bool parseDouble(const std::string& text, double& out) {
    const std::string value = trim(text);
    if (value.empty()) return false;
    char* end = nullptr;
    errno = 0;
    const double parsed = std::strtod(value.c_str(), &end);
    if (errno != 0 || end != value.c_str() + value.size() || !std::isfinite(parsed)) return false;
    out = parsed;
    return true;
}

bool parseInt(const std::string& text, long long& out) {
    const std::string value = trim(text);
    if (value.empty()) return false;
    char* end = nullptr;
    errno = 0;
    const long long parsed = std::strtoll(value.c_str(), &end, 10);
    if (errno != 0 || end != value.c_str() + value.size()) return false;
    out = parsed;
    return true;
}

double clamp01(double value) { return clamp(value, 0.0, 1.0); }

double clamp(double value, double lo, double hi) { return std::max(lo, std::min(hi, value)); }

// ----- Random ----------------------------------------------------------------------------

double Random::uniform() {
    // 32 random bits -> [0, 1). mt19937 output is identical on all platforms.
    return static_cast<double>(engine_()) / 4294967296.0;
}

double Random::uniform(double lo, double hi) { return lo + (hi - lo) * uniform(); }

int Random::uniformInt(int lo, int hi) {
    if (hi <= lo) return lo;
    const double span = static_cast<double>(hi) - static_cast<double>(lo) + 1.0;
    const int value = lo + static_cast<int>(std::floor(uniform() * span));
    return std::min(value, hi);
}

bool Random::bernoulli(double probability) { return uniform() < probability; }

double Random::normal(double mean, double stddev) {
    double u1 = uniform();
    if (u1 < 1e-12) u1 = 1e-12;
    const double u2 = uniform();
    const double z = std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * 3.14159265358979323846 * u2);
    return mean + stddev * z;
}

std::size_t Random::weightedIndex(const std::vector<double>& weights) {
    double total = 0.0;
    for (double w : weights) total += std::max(0.0, w);
    if (weights.empty() || total <= 0.0) return 0;
    double target = uniform() * total;
    for (std::size_t i = 0; i < weights.size(); ++i) {
        target -= std::max(0.0, weights[i]);
        if (target < 0.0) return i;
    }
    return weights.size() - 1;
}

int Random::stochasticRound(double expected) {
    if (expected <= 0.0) return 0;
    const double base = std::floor(expected);
    return static_cast<int>(base) + (bernoulli(expected - base) ? 1 : 0);
}

// ----- Statistics -----------------------------------------------------------------------

double mean(const std::vector<double>& values) {
    if (values.empty()) return 0.0;
    double sum = 0.0;
    for (double v : values) sum += v;
    return sum / static_cast<double>(values.size());
}

double percentile(std::vector<double> values, double p) {
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    const double rank = clamp(p, 0.0, 100.0) / 100.0 * static_cast<double>(values.size() - 1);
    const std::size_t lower = static_cast<std::size_t>(std::floor(rank));
    const std::size_t upper = std::min(lower + 1, values.size() - 1);
    const double fraction = rank - static_cast<double>(lower);
    return values[lower] + (values[upper] - values[lower]) * fraction;
}

// ----- Console tables ------------------------------------------------------------------

TextTable::TextTable(std::vector<std::string> header) { rows_.push_back(std::move(header)); }

void TextTable::addRow(std::vector<std::string> row) { rows_.push_back(std::move(row)); }

void TextTable::print(std::ostream& out) const {
    std::vector<std::size_t> widths;
    for (const auto& row : rows_) {
        if (row.size() > widths.size()) widths.resize(row.size(), 0);
        for (std::size_t c = 0; c < row.size(); ++c) widths[c] = std::max(widths[c], row[c].size());
    }

    auto printRule = [&]() {
        out << "  +";
        for (std::size_t w : widths) out << std::string(w + 2, '-') << '+';
        out << '\n';
    };

    printRule();
    for (std::size_t r = 0; r < rows_.size(); ++r) {
        out << "  |";
        for (std::size_t c = 0; c < widths.size(); ++c) {
            const std::string cell = c < rows_[r].size() ? rows_[r][c] : "";
            out << ' ' << cell << std::string(widths[c] - cell.size(), ' ') << " |";
        }
        out << '\n';
        if (r == 0) printRule();
    }
    printRule();
}

void printBanner(std::ostream& out, const std::string& title) {
    const std::string rule(78, '=');
    out << '\n' << rule << '\n' << "  " << title << '\n' << rule << '\n';
}

void printSection(std::ostream& out, const std::string& title) {
    out << '\n' << "  " << title << '\n' << "  " << std::string(title.size(), '-') << '\n';
}

// ----- File system ----------------------------------------------------------------------

namespace {

bool isDirectory(const std::string& path) {
    struct stat info;
    return stat(path.c_str(), &info) == 0 && (info.st_mode & S_IFDIR) != 0;
}

bool makeSingleDirectory(const std::string& path) {
#ifdef _WIN32
    return _mkdir(path.c_str()) == 0 || errno == EEXIST;
#else
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

}  // namespace

bool ensureDirectory(const std::string& path) {
    if (path.empty() || isDirectory(path)) return true;
    const std::string parent = parentDirectory(path);
    if (!parent.empty() && parent != path && !ensureDirectory(parent)) return false;
    return makeSingleDirectory(path) && isDirectory(path);
}

std::string parentDirectory(const std::string& path) {
    const std::size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos) return "";
    return path.substr(0, slash);
}

}  // namespace util
}  // namespace aspe
