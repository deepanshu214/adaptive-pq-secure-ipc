// ---------------------------------------------------------------------------
// Small, dependency-free utilities: string helpers, deterministic random
// numbers, statistics, console tables and file-system helpers.
// ---------------------------------------------------------------------------
#ifndef ASPE_UTIL_H
#define ASPE_UTIL_H

#include <cstdint>
#include <iosfwd>
#include <random>
#include <string>
#include <vector>

namespace aspe {
namespace util {

// ----- Strings ---------------------------------------------------------------------

std::string trim(const std::string& text);
std::string toUpper(std::string text);
std::vector<std::string> split(const std::string& text, char delimiter);
/// Fixed-point formatting, e.g. fixed(3.14159, 2) == "3.14".
std::string fixed(double value, int precision);
/// Percentage formatting of a ratio, e.g. percent(0.257, 1) == "25.7%".
std::string percent(double ratio, int precision = 1);
std::string boolText(bool value);
std::string jsonEscape(const std::string& text);

bool parseDouble(const std::string& text, double& out);
bool parseInt(const std::string& text, long long& out);

double clamp01(double value);
double clamp(double value, double lo, double hi);

// ----- Deterministic random numbers ------------------------------------------------

/// Random number generator whose output is identical on every platform.
/// std::mt19937 is fully specified by the C++ standard, but the standard
/// distributions are not, so the distributions are implemented here.
class Random {
public:
    explicit Random(std::uint32_t seed) : engine_(seed) {}

    double uniform();                              ///< [0, 1)
    double uniform(double lo, double hi);          ///< [lo, hi)
    int uniformInt(int lo, int hi);                ///< [lo, hi] inclusive
    bool bernoulli(double probability);
    double normal(double mean, double stddev);     ///< Box-Muller
    /// Samples an index according to non-negative weights.
    std::size_t weightedIndex(const std::vector<double>& weights);
    /// Rounds a real expected count stochastically (keeps the expectation).
    int stochasticRound(double expected);

private:
    std::mt19937 engine_;
};

// ----- Statistics ----------------------------------------------------------------------

double mean(const std::vector<double>& values);
/// Linear-interpolated percentile, p in [0, 100]. Returns 0 for empty input.
double percentile(std::vector<double> values, double p);

// ----- Console tables --------------------------------------------------------------

/// Minimal aligned text table used by the command-line reports.
class TextTable {
public:
    explicit TextTable(std::vector<std::string> header);
    void addRow(std::vector<std::string> row);
    void print(std::ostream& out) const;

private:
    std::vector<std::vector<std::string>> rows_;
};

void printBanner(std::ostream& out, const std::string& title);
void printSection(std::ostream& out, const std::string& title);

// ----- File system -------------------------------------------------------------------

/// Creates a directory (and missing parents). Returns true if it exists afterwards.
bool ensureDirectory(const std::string& path);
/// Directory part of a path ("results/a.csv" -> "results"), or "" if none.
std::string parentDirectory(const std::string& path);

}  // namespace util
}  // namespace aspe

#endif  // ASPE_UTIL_H
