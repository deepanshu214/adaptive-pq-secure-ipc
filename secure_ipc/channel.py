"""Authenticated handshake + protected channel on top of any connection with send_bytes/recv_bytes.

Handshake (Process A = initiator, Process B = responder, both authenticate each other):
  A -> B : hello = [name, profile, nonce_a, key-exchange public] + A's signature (L1: HMAC)
  B -> A : reply = [name, nonce_b, key-exchange reply]           + B's signature over (hello + reply)
Each side looks the other up in the registry of authorized processes (public keys in key_dir).
B refuses any level below its minimum, so a connection cannot be pushed below the policy.
Session keys = HKDF(shared secret, nonces), one key per direction.

Messages:  frame = seq (8 B) [+ ML-DSA signature if per-message signatures are on] + payload
  L1    : data + HMAC-SHA-256 tag (32 B)   -> integrity only, no encryption
  L2-L5 : AES-256-GCM ciphertext + tag     -> confidentiality + integrity
The sequence number is covered by the tag, and the receiver only accepts increasing numbers
(replay protection). Every `rekey_interval` messages the key of that direction is replaced.
"""
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (LEVELS, Profile, as_profile, derive_keys, kex_finish, kex_respond, kex_start,
                     load_public, next_key, pack, sign, sign_with, unpack, verify, verify_with)

SIG_LEN = {"Ed25519": 64, "ML-DSA-65": 3309, "ML-DSA-87": 4627}
MAX_REKEY_STEPS = 1000


class AuthError(Exception):
    """Peer is unknown, signed with the wrong key, asked for a too-low level, or the handshake is malformed."""


class IntegrityError(Exception):
    """Message was modified or corrupted."""


class ReplayError(Exception):
    """Message sequence number was already seen."""


class SecureChannel:
    def __init__(self, conn, keys, initiator, profile, me, peer):
        self.conn, self.profile, self.me, self.peer = conn, profile, me, peer
        self.seq = 0        # last number we sent
        self.last_seq = 0   # last number we accepted
        self.send_dir, self.recv_dir = (b"A2B\0", b"B2A\0") if initiator else (b"B2A\0", b"A2B\0")
        send_key, recv_key = keys if initiator else keys[::-1]
        self.send_key = [0, send_key]   # [key epoch, key]
        self.recv_key = [0, recv_key]
        self.sig_alg = LEVELS[profile.level][2][-1] if profile.per_message_signature else None
        self.last_frame_bytes = 0

    def _key(self, state, seq):
        """Key for message number `seq` (moves forward one re-key step per `rekey_interval` messages)."""
        interval = self.profile.rekey_interval
        epoch = (seq - 1) // interval if interval else 0
        if epoch - state[0] > MAX_REKEY_STEPS:
            raise IntegrityError("sequence number too far ahead")
        key = state[1]
        for _ in range(epoch - state[0]):
            key = next_key(key)
        return epoch, key

    def seal(self, data):
        self.seq += 1
        seq = self.seq.to_bytes(8, "big")
        self.send_key[:] = self._key(self.send_key, self.seq)
        key = self.send_key[1]
        if self.profile.level == 1:
            body = data + hmac.new(key, self.send_dir + seq + data, hashlib.sha256).digest()
        else:
            body = AESGCM(key).encrypt(self.send_dir + seq, data, seq)
        if self.sig_alg:
            body = sign_with(self.sig_alg, self.me, self.send_dir + seq + body) + body
        return seq + body

    def open(self, frame):
        seq, body = frame[:8], frame[8:]
        n = int.from_bytes(seq, "big")
        if len(body) < 16 or n == 0:
            raise IntegrityError("frame too short")
        if n <= self.last_seq:
            raise ReplayError(f"sequence {n} already seen (last {self.last_seq})")
        if self.sig_alg:
            sig, body = body[:SIG_LEN[self.sig_alg]], body[SIG_LEN[self.sig_alg]:]
            if not verify_with(self.sig_alg, self.peer, self.recv_dir + seq + body, sig):
                raise IntegrityError("invalid message signature")
        epoch, key = self._key(self.recv_key, n)
        if self.profile.level == 1:
            data, tag = body[:-32], body[-32:]
            if not hmac.compare_digest(tag, hmac.new(key, self.recv_dir + seq + data, hashlib.sha256).digest()):
                raise IntegrityError("HMAC tag mismatch")
        else:
            try:
                data = AESGCM(key).decrypt(self.recv_dir + seq, body, seq)
            except InvalidTag:
                raise IntegrityError("authentication tag mismatch") from None
        self.recv_key[:] = [epoch, key]
        self.last_seq = n
        return data

    def send(self, data):
        frame = self.seal(data)
        self.last_frame_bytes = len(frame)
        self.conn.send_bytes(frame)

    def recv(self):
        return self.open(self.conn.recv_bytes())

    def close(self):
        self.conn.close()


def _encode(profile):
    return bytes([profile.level, int(profile.per_message_signature)]) + profile.rekey_interval.to_bytes(4, "big")


def _decode(raw):
    if len(raw) != 6 or raw[0] not in LEVELS:
        raise AuthError("malformed security profile")
    return Profile(raw[0], int.from_bytes(raw[2:], "big"), bool(raw[1]))


def connect(conn, me, key_dir, profile, peer_name):
    """Initiator side. `profile` is a crypto.Profile or a level ('classical', 4, 'L5', ...)."""
    try:
        return _connect(conn, me, key_dir, as_profile(profile), peer_name)
    except Exception as e:
        conn.close()
        raise (e if isinstance(e, AuthError) else AuthError(f"handshake failed: {e!r}"))


def _connect(conn, me, key_dir, profile, peer_name):
    level = profile.level
    state, kex = kex_start(level)
    nonce_a = os.urandom(16)
    body = pack(me["name"].encode(), _encode(profile), nonce_a, kex)
    conn.send_bytes(pack(body, sign(me, level, body)))

    r_body, r_sig = unpack(conn.recv_bytes())
    name_b, nonce_b, kex_reply = unpack(r_body)
    peer = load_public(name_b.decode(), key_dir)
    if name_b.decode() != peer_name or peer is None:
        raise AuthError(f"unexpected peer {name_b!r}")
    if not verify(me, peer, level, body + r_body, r_sig):
        raise AuthError("invalid signature from responder")

    keys = derive_keys(kex_finish(level, state, kex_reply), me, level, nonce_a, nonce_b)
    return SecureChannel(conn, keys, True, profile, me, peer)


def accept(conn, me, key_dir, min_level=1):
    """Responder side. Returns (channel, authenticated peer name, profile chosen by the peer)."""
    try:
        return _accept(conn, me, key_dir, min_level)
    except Exception as e:
        conn.close()
        raise (e if isinstance(e, AuthError) else AuthError(f"handshake failed: {e!r}"))


def _accept(conn, me, key_dir, min_level):
    body, sig = unpack(conn.recv_bytes())
    name_a, raw_profile, nonce_a, kex = unpack(body)
    profile = _decode(raw_profile)
    peer = load_public(name_a.decode(), key_dir)
    if peer is None:
        raise AuthError(f"process {name_a!r} is not authorized")
    if profile.level < min_level:
        raise AuthError(f"L{profile.level} is below the required minimum L{min_level}")
    if not verify(me, peer, profile.level, body, sig):
        raise AuthError(f"invalid signature from {name_a!r}")

    nonce_b = os.urandom(16)
    kex_reply, secret = kex_respond(profile.level, kex)
    r_body = pack(me["name"].encode(), nonce_b, kex_reply)
    conn.send_bytes(pack(r_body, sign(me, profile.level, body + r_body)))

    keys = derive_keys(secret, me, profile.level, nonce_a, nonce_b)
    return SecureChannel(conn, keys, False, profile, me, peer), name_a.decode(), profile
