#include "aspe/crypto_suite.h"

#include <algorithm>
#include <cmath>

#include "aspe/util.h"

namespace aspe {

namespace {

// Object sizes in bytes (FIPS 203, FIPS 204, RFC 7748, RFC 8032).
constexpr std::uint32_t kX25519Public = 32, kX25519Secret = 32;
constexpr std::uint32_t kEd25519Public = 32, kEd25519Secret = 64, kEd25519Sig = 64;
constexpr std::uint32_t kMlKem512Public = 800, kMlKem512Secret = 1632, kMlKem512Ct = 768;
constexpr std::uint32_t kMlKem768Public = 1184, kMlKem768Secret = 2400, kMlKem768Ct = 1088;
constexpr std::uint32_t kMlKem1024Public = 1568, kMlKem1024Secret = 3168, kMlKem1024Ct = 1568;
constexpr std::uint32_t kMlDsa65Public = 1952, kMlDsa65Secret = 4032, kMlDsa65Sig = 3309;
constexpr std::uint32_t kMlDsa87Public = 2592, kMlDsa87Secret = 4896, kMlDsa87Sig = 4627;
constexpr std::uint32_t kAesGcmContext = 560;  // expanded key schedule + GHASH table
constexpr std::uint32_t kHmacContext = 208;    // two SHA-256 states + key block

// Reference timings in microseconds (both peers, ~3 GHz x86-64, portable C).
constexpr double kX25519Exchange = 140.0;  // 2 x keygen + 2 x shared secret
constexpr double kEd25519SignVerify = 85.0;
constexpr double kMlKem512Exchange = 60.0;  // keygen + encaps + decaps
constexpr double kMlKem768Exchange = 90.0;
constexpr double kMlKem1024Exchange = 130.0;
constexpr double kMlDsa65SignVerify = 390.0;
constexpr double kMlDsa87SignVerify = 560.0;

// Per-message framing: 12 B nonce + 16 B tag + 8 B sequence number.
constexpr std::uint32_t kAeadFraming = 36;
// MAC framing: 32 B HMAC-SHA-256 tag + 8 B sequence number.
constexpr std::uint32_t kMacFraming = 40;

std::vector<CryptoSuite> buildCatalogue() {
    std::vector<CryptoSuite> suites;

    suites.push_back(CryptoSuite{
        SecurityLevel::Basic, "Basic integrity",
        "Pre-provisioned channel key", "HMAC-SHA-256", "HMAC-SHA-256 (no encryption)",
        false, false, false, false, 128, 0,
        0.0, 0, 0, false, 0.0, 0,
        0.8, 0.0040, kMacFraming,
        32 + kHmacContext});

    suites.push_back(CryptoSuite{
        SecurityLevel::Classical, "Classical secure",
        "X25519 ECDHE", "Ed25519", "AES-256-GCM",
        true, true, false, false, 128, 0,
        kX25519Exchange + kEd25519SignVerify, 2 * kX25519Public + kEd25519Sig, 64, false, 0.0, 0,
        0.6, 0.0015, kAeadFraming,
        kX25519Secret + 2 * kX25519Public + kEd25519Secret + kEd25519Public + kEd25519Sig +
            kAesGcmContext});

    suites.push_back(CryptoSuite{
        SecurityLevel::Hybrid, "Hybrid classical + PQ",
        "X25519 + ML-KEM-512", "Ed25519", "AES-256-GCM",
        true, true, true, false, 128, 1,
        kX25519Exchange + kMlKem512Exchange + kEd25519SignVerify,
        2 * kX25519Public + kMlKem512Public + kMlKem512Ct + kEd25519Sig, 32, false, 0.0, 0,
        0.6, 0.0015, kAeadFraming,
        kX25519Secret + 2 * kX25519Public + kMlKem512Secret + kMlKem512Public + kMlKem512Ct +
            kEd25519Secret + kEd25519Public + kEd25519Sig + kAesGcmContext});

    suites.push_back(CryptoSuite{
        SecurityLevel::PostQuantum, "Post-quantum",
        "ML-KEM-768", "ML-DSA-65", "AES-256-GCM",
        true, true, true, true, 192, 3,
        kMlKem768Exchange + kMlDsa65SignVerify, kMlKem768Public + kMlKem768Ct + kMlDsa65Sig, 16,
        false, 0.0, 0,
        0.6, 0.0015, kAeadFraming,
        kMlKem768Secret + kMlKem768Public + kMlKem768Ct + kMlDsa65Secret + kMlDsa65Public +
            kMlDsa65Sig + kAesGcmContext});

    suites.push_back(CryptoSuite{
        SecurityLevel::StrongPostQuantum, "Strong post-quantum",
        "ML-KEM-1024", "ML-DSA-87", "AES-256-GCM",
        true, true, true, true, 256, 5,
        kMlKem1024Exchange + kMlDsa87SignVerify, kMlKem1024Public + kMlKem1024Ct + kMlDsa87Sig, 4,
        true, kMlDsa87SignVerify, kMlDsa87Sig,
        0.6, 0.0015, kAeadFraming,
        kMlKem1024Secret + kMlKem1024Public + kMlKem1024Ct + kMlDsa87Secret + kMlDsa87Public +
            kMlDsa87Sig + kAesGcmContext});

    return suites;
}

}  // namespace

const std::vector<CryptoSuite>& suiteCatalogue() {
    static const std::vector<CryptoSuite> catalogue = buildCatalogue();
    return catalogue;
}

const CryptoSuite& suiteFor(SecurityLevel level) {
    return suiteCatalogue()[static_cast<std::size_t>(toInt(level) - 1)];
}

bool satisfies(const CryptoSuite& suite, const SecurityRequirements& r) {
    if (r.confidentiality && !suite.confidentiality) return false;
    if (r.strongAuthentication && !suite.strongAuthentication) return false;
    if (r.quantumSafeConfidentiality && !suite.quantumSafeConfidentiality) return false;
    if (r.quantumSafeAuthentication && !suite.quantumSafeAuthentication) return false;
    return true;  // integrity, origin authentication and anti-replay: every suite
}

std::string toString(ProtectionMode mode) {
    return mode == ProtectionMode::Optimized ? "OPTIMIZED" : "STANDARD";
}

SecurityProfile makeProfile(SecurityLevel level, ProtectionMode mode,
                            std::uint32_t optimizedRekeyMultiplier) {
    const CryptoSuite& suite = suiteFor(level);
    SecurityProfile profile;
    profile.level = level;
    profile.mode = mode;
    profile.rekeyInterval = suite.defaultRekeyInterval;
    profile.perMessageSignature = suite.defaultPerMessageSignature;
    profile.replayProtection = true;
    if (mode == ProtectionMode::Optimized) {
        profile.rekeyInterval *= std::max<std::uint32_t>(1, optimizedRekeyMultiplier);
        profile.perMessageSignature = false;  // session-level authentication only
    }
    return profile;
}

const Platform& referencePlatform() {
    static const Platform platform{"reference x86-64 desktop", 1.0, 4};
    return platform;
}

const Platform& embeddedPlatform() {
    static const Platform platform{"embedded ARM Cortex-A class device", 6.0, 2};
    return platform;
}

bool findPlatform(const std::string& name, Platform& out) {
    const std::string key = util::toUpper(util::trim(name));
    if (key == "REFERENCE" || key == "DESKTOP" || key == "X86") {
        out = referencePlatform();
        return true;
    }
    if (key == "EMBEDDED" || key == "ARM") {
        out = embeddedPlatform();
        return true;
    }
    return false;
}

CostEstimate estimateCost(const SecurityProfile& profile, std::uint32_t payloadBytes,
                          const Platform& platform) {
    const CryptoSuite& s = profile.suite();
    double micros = s.fixedMicros + s.perByteMicros * static_cast<double>(payloadBytes);
    double bytes = static_cast<double>(s.framingBytes);

    if (profile.rekeyInterval > 0) {
        micros += s.handshakeMicros / static_cast<double>(profile.rekeyInterval);
        bytes += static_cast<double>(s.handshakeBytes) / static_cast<double>(profile.rekeyInterval);
    }
    if (profile.perMessageSignature) {
        micros += s.signatureMicros;
        bytes += static_cast<double>(s.signatureBytes);
    }

    CostEstimate cost;
    cost.cpuMicros = micros * platform.costScale;
    cost.latencyMicros = cost.cpuMicros;
    cost.overheadBytes = static_cast<std::uint32_t>(std::ceil(bytes));
    cost.memoryBytes = s.stateBytes;
    return cost;
}

}  // namespace aspe
