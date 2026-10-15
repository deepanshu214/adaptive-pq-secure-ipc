"""Crypto building blocks for the five security levels chosen by the policy engine.

The suites are the ones defined in policy_engine/src/crypto_suite.cpp:

L1 BASIC        : pre-provisioned channel key, HMAC-SHA-256, no encryption
L2 CLASSICAL    : X25519               + Ed25519   + AES-256-GCM
L3 HYBRID       : X25519 + ML-KEM-512  + Ed25519   + AES-256-GCM
L4 POST_QUANTUM : ML-KEM-768           + ML-DSA-65 + AES-256-GCM
L5 STRONG_PQ    : ML-KEM-1024          + ML-DSA-87 + AES-256-GCM (+ ML-DSA-87 signature on every message)
"""
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

# level -> (name, key establishment, authentication, default re-key interval in messages)
LEVELS = {
    1: ("BASIC", [], [], 0),
    2: ("CLASSICAL", ["X25519"], ["Ed25519"], 64),
    3: ("HYBRID", ["X25519", "ML-KEM-512"], ["Ed25519"], 32),
    4: ("POST_QUANTUM", ["ML-KEM-768"], ["ML-DSA-65"], 16),
    5: ("STRONG_PQ", ["ML-KEM-1024"], ["ML-DSA-87"], 4),
}
KEMS = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}
PQ_SIGNERS = {"ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}
NAMES = {"basic": 1, "classical": 2, "hybrid": 3, "pq": 4, "post_quantum": 4, "strong_pq": 5}

_RAW_PUB = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
_RAW_PRIV = dict(encoding=ser.Encoding.Raw, format=ser.PrivateFormat.Raw,
                 encryption_algorithm=ser.NoEncryption())


@dataclass
class Profile:
    """What the secure channel has to apply - the SecurityProfile of the policy engine."""
    level: int
    rekey_interval: int = 0          # new key every N messages (0 = never)
    per_message_signature: bool = False

    @property
    def name(self):
        return LEVELS[self.level][0]

    @classmethod
    def standard(cls, level):
        """Suite defaults, e.g. 'pq' / 4 / 'L4' -> ML-KEM-768 + ML-DSA-65, re-key every 16 messages."""
        level = level_of(level)
        return cls(level, LEVELS[level][3], level == 5)

    @classmethod
    def from_decision(cls, decision):
        """Profile from the JSON printed by `aspe decide --json`."""
        return cls(int(decision["selected_level"]), int(decision["rekey_interval"]),
                   bool(decision["per_message_signature"]))


def level_of(value):
    text = str(value).strip().lower()
    text = text[1:] if text.startswith("l") and text[1:].isdigit() else text
    level = int(text) if text.isdigit() else NAMES.get(text)
    if level not in LEVELS:
        raise ValueError(f"unknown security level {value!r}")
    return level


def as_profile(value):
    return value if isinstance(value, Profile) else Profile.standard(value)


# ---------- length-prefixed packing for handshake messages ----------

def pack(*parts):
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def unpack(data):
    parts, i = [], 0
    while i < len(data):
        n = int.from_bytes(data[i:i + 4], "big")
        if i + 4 + n > len(data):
            raise ValueError("truncated message")
        parts.append(data[i + 4:i + 4 + n])
        i += 4 + n
    return parts


# ---------- process identities ----------

def _write_private(path, data):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data)


def create_identity(name, key_dir):
    """Signing keys for a process. The public half (<name>.pub.json) is its registry entry."""
    os.makedirs(key_dir, exist_ok=True)
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    public = {"Ed25519": ed_sk.public_key().public_bytes(**_RAW_PUB).hex()}
    private = {"Ed25519": ed_sk.private_bytes(**_RAW_PRIV).hex()}
    for alg, scheme in PQ_SIGNERS.items():
        pk, sk = scheme.keygen()
        public[alg], private[alg] = pk.hex(), sk.hex()
    with open(os.path.join(key_dir, f"{name}.pub.json"), "w") as f:
        json.dump(public, f)
    _write_private(os.path.join(key_dir, f"{name}.key.json"),
                   json.dumps({"name": name, "private": private}).encode())


def channel_key(key_dir):
    """The pre-provisioned key shared by the authorized processes (used by L1 BASIC)."""
    path = os.path.join(key_dir, "channel.key")
    if not os.path.exists(path):
        os.makedirs(key_dir, exist_ok=True)
        _write_private(path, os.urandom(32))
    with open(path, "rb") as f:
        return f.read()


def load_identity(name, key_dir):
    with open(os.path.join(key_dir, f"{name}.key.json")) as f:
        data = json.load(f)
    return {"name": data["name"], "channel_key": channel_key(key_dir),
            "private": {k: bytes.fromhex(v) for k, v in data["private"].items()}}


def load_public(name, key_dir):
    """Public keys of an *authorized* process, or None if it is not registered."""
    path = os.path.join(key_dir, f"{name}.pub.json")
    if not re.fullmatch(r"\w+", name) or not os.path.exists(path):
        return None
    with open(path) as f:
        return {k: bytes.fromhex(v) for k, v in json.load(f).items()}


def ensure_keys(key_dir):
    for name in ("processA", "processB"):
        if not os.path.exists(os.path.join(key_dir, f"{name}.key.json")):
            create_identity(name, key_dir)
    channel_key(key_dir)


# ---------- authentication: signatures (L2-L5) or HMAC with the channel key (L1) ----------

def sign_with(alg, me, msg):
    if alg == "Ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(me["private"][alg]).sign(msg)
    return PQ_SIGNERS[alg].sign(me["private"][alg], msg)


def verify_with(alg, public, msg, sig):
    try:
        if alg == "Ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(public[alg]).verify(sig, msg)
            return True
        return PQ_SIGNERS[alg].verify(public[alg], msg, sig)
    except Exception:  # bad signature or malformed input from an untrusted peer
        return False


def sign(me, level, msg):
    if level == 1:
        return hmac.new(me["channel_key"], msg, hashlib.sha256).digest()
    return pack(*[sign_with(alg, me, msg) for alg in LEVELS[level][2]])


def verify(me, peer, level, msg, sig):
    if level == 1:
        return hmac.compare_digest(sign(me, 1, msg), sig)
    try:
        parts = unpack(sig)
    except ValueError:
        return False
    algs = LEVELS[level][2]
    return len(parts) == len(algs) and all(verify_with(a, peer, msg, s) for a, s in zip(algs, parts))


# ---------- key establishment ----------

def _x_pub(private_key):
    return private_key.public_key().public_bytes(**_RAW_PUB)


def kex_start(level):
    """Initiator: returns (private state, public blob to send)."""
    state, parts = [], []
    for alg in LEVELS[level][1]:
        if alg == "X25519":
            sk = x25519.X25519PrivateKey.generate()
            state.append(sk)
            parts.append(_x_pub(sk))
        else:
            ek, dk = KEMS[alg].keygen()
            state.append(dk)
            parts.append(ek)
    return state, pack(*parts)


def kex_respond(level, blob):
    """Responder: returns (reply blob, shared secret)."""
    algs, parts = LEVELS[level][1], unpack(blob)
    if len(parts) != len(algs):
        raise ValueError("wrong number of key-exchange parts")
    reply, secret = [], b""
    for alg, public in zip(algs, parts):
        if alg == "X25519":
            sk = x25519.X25519PrivateKey.generate()
            secret += sk.exchange(x25519.X25519PublicKey.from_public_bytes(public))
            reply.append(_x_pub(sk))
        else:
            shared, ct = KEMS[alg].encaps(public)
            secret += shared
            reply.append(ct)
    return pack(*reply), secret


def kex_finish(level, state, reply):
    """Initiator: shared secret from the responder's reply."""
    algs, parts = LEVELS[level][1], unpack(reply)
    if len(parts) != len(algs):
        raise ValueError("wrong number of key-exchange parts")
    secret = b""
    for alg, private, part in zip(algs, state, parts):
        if alg == "X25519":
            secret += private.exchange(x25519.X25519PublicKey.from_public_bytes(part))
        else:
            secret += KEMS[alg].decaps(private, part)
    return secret


def derive_keys(secret, me, level, nonce_a, nonce_b):
    """One session key per direction (A->B, B->A). L1 has no key exchange, so it starts from the channel key."""
    ikm = secret if level > 1 else me["channel_key"]
    okm = HKDF(hashes.SHA256(), 64, salt=nonce_a + nonce_b,
               info=f"secure-ipc L{level}".encode()).derive(ikm)
    return okm[:32], okm[32:]


def next_key(key):
    """Re-key step: the next key is derived from the current one, which is then dropped."""
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"secure-ipc rekey").derive(key)
