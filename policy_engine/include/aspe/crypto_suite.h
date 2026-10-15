// ---------------------------------------------------------------------------
// Cryptographic suites behind each security level and their cost model.
//
// The engine does not perform cryptography itself: it selects a suite and a
// parameterisation (a SecurityProfile) which the secure IPC / PQC engine of
// the partner project executes. To compare policies before integration, each
// suite carries an analytical cost model. The timing constants are
// order-of-magnitude estimates for reference (portable C) implementations on
// a ~3 GHz x86-64 core, consistent with published liboqs / SUPERCOP figures;
// object sizes are the exact values from FIPS 203 / FIPS 204 / RFC 7748 /
// RFC 8032. After integration the constants are replaced by measurements.
// ---------------------------------------------------------------------------
#ifndef ASPE_CRYPTO_SUITE_H
#define ASPE_CRYPTO_SUITE_H

#include <cstdint>
#include <string>
#include <vector>

#include "aspe/threat_analysis.h"
#include "aspe/types.h"

namespace aspe {

struct CryptoSuite {
    SecurityLevel level;
    std::string name;
    // Algorithms --------------------------------------------------------------
    std::string keyEstablishment;
    std::string authentication;
    std::string payloadProtection;
    // Security services provided ---------------------------------------------
    bool confidentiality;
    bool strongAuthentication;
    bool quantumSafeConfidentiality;
    bool quantumSafeAuthentication;
    int classicalSecurityBits;
    int nistPqCategory;  ///< 0 = not quantum-safe
    // Cost model ---------------------------------------------------------------
    double handshakeMicros;            ///< key establishment + authentication, both peers
    std::uint32_t handshakeBytes;      ///< public keys + ciphertexts + signatures
    std::uint32_t defaultRekeyInterval;///< messages per session key (0 = static key)
    bool defaultPerMessageSignature;   ///< sign every message (non-repudiation)
    double signatureMicros;            ///< sign + verify of one message
    std::uint32_t signatureBytes;
    double fixedMicros;                ///< per-message AEAD / MAC set-up
    double perByteMicros;              ///< per-byte AEAD / MAC cost
    std::uint32_t framingBytes;        ///< nonce + tag + sequence number
    std::uint32_t stateBytes;          ///< key material and contexts per session
};

/// Returns the suite of a security level (L1..L5).
const CryptoSuite& suiteFor(SecurityLevel level);
const std::vector<CryptoSuite>& suiteCatalogue();

/// True if the suite provides every service in the requirements.
bool satisfies(const CryptoSuite& suite, const SecurityRequirements& requirements);

/// How the selected suite is parameterised.
enum class ProtectionMode {
    Standard,   ///< suite defaults
    Optimized,  ///< same algorithms, longer re-key interval, no per-message signatures
};

std::string toString(ProtectionMode mode);

/// The selected security policy: everything the secure IPC engine needs.
struct SecurityProfile {
    SecurityLevel level = SecurityLevel::Basic;
    ProtectionMode mode = ProtectionMode::Standard;
    std::uint32_t rekeyInterval = 0;
    bool perMessageSignature = false;
    bool replayProtection = true;

    const CryptoSuite& suite() const { return suiteFor(level); }
};

/// Builds the profile for a level and mode. `optimizedRekeyMultiplier`
/// stretches the re-key interval in Optimized mode.
SecurityProfile makeProfile(SecurityLevel level, ProtectionMode mode = ProtectionMode::Standard,
                            std::uint32_t optimizedRekeyMultiplier = 4);

/// Hardware platform the cost model is evaluated on.
struct Platform {
    std::string name;
    double costScale;  ///< multiplier applied to the x86-64 reference timings
    int cryptoCores;   ///< cores available to the IPC security layer
};

const Platform& referencePlatform();  ///< x86-64 desktop, scale 1.0
const Platform& embeddedPlatform();   ///< ARM Cortex-A class device, scale 6.0
/// Looks up a platform by name ("reference" | "embedded").
bool findPlatform(const std::string& name, Platform& out);

struct CostEstimate {
    double cpuMicros = 0.0;          ///< CPU time spent on security for the message
    double latencyMicros = 0.0;      ///< added latency (sender + receiver, unloaded)
    std::uint32_t overheadBytes = 0; ///< bytes added on the wire (amortised handshake incl.)
    std::uint32_t memoryBytes = 0;   ///< key material / context per session
};

CostEstimate estimateCost(const SecurityProfile& profile, std::uint32_t payloadBytes,
                          const Platform& platform);

}  // namespace aspe

#endif  // ASPE_CRYPTO_SUITE_H
