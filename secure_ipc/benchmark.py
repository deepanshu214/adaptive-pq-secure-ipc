"""Performance evaluation of all five security levels. Run: python3 -m secure_ipc.benchmark

1. Primitive timings (key establishment, signatures, AES-GCM, HMAC)
2. Per level x transport: handshake time/bytes, round-trip latency, throughput, CPU, memory
3. Measured values next to the policy engine's cost model (the model was written before integration)
"""
import hashlib
import hmac
import os
import statistics
import time
import tracemalloc

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .channel import accept, connect
from .crypto import KEMS, LEVELS, Profile, ensure_keys, load_identity, load_public, sign_with, verify_with
from .transport import TRANSPORTS, local_pair, spawn_peer

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
SMALL, LARGE = 1024, 64 * 1024
N_SMALL, N_LARGE = 100, 30

# Handshake cost model of the policy engine (policy_engine/src/crypto_suite.cpp, reference x86-64
# platform; bytes as printed by `aspe params`). Per-message framing: 36 B (AEAD) / 40 B (HMAC).
MODEL = {1: (0, 0, 40), 2: (225, 128, 36), 3: (285, 1696, 36), 4: (480, 5581, 36), 5: (690, 7763, 36 + 4627)}


def median_ms(fn, runs=20):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times) * 1000


def primitives():
    me, pub = load_identity("processA", KEY_DIR), load_public("processA", KEY_DIR)
    msg, data = os.urandom(256), os.urandom(SMALL)
    peer = x25519.X25519PrivateKey.generate().public_key()
    rows = [("X25519 keygen + exchange", lambda: x25519.X25519PrivateKey.generate().exchange(peer), "32 B public key")]
    for name, kem in KEMS.items():
        ek, dk = kem.keygen()
        _, ct = kem.encaps(ek)
        rows.append((f"{name} keygen + encaps + decaps",
                     lambda kem=kem, ek=ek, dk=dk, ct=ct: (kem.keygen(), kem.encaps(ek), kem.decaps(dk, ct)),
                     f"{len(ek)} B public key, {len(ct)} B ciphertext"))
    for alg in ("Ed25519", "ML-DSA-65", "ML-DSA-87"):
        sig = sign_with(alg, me, msg)
        rows.append((f"{alg} sign", lambda alg=alg: sign_with(alg, me, msg), f"{len(sig)} B signature"))
        rows.append((f"{alg} verify", lambda alg=alg, sig=sig: verify_with(alg, pub, msg, sig), ""))
    key, nonce = AESGCM(os.urandom(32)), os.urandom(12)
    sealed = key.encrypt(nonce, data, None)
    rows += [("AES-256-GCM encrypt 1 KB", lambda: key.encrypt(nonce, data, None), "16 B tag"),
             ("AES-256-GCM decrypt 1 KB", lambda: key.decrypt(nonce, sealed, None), ""),
             ("HMAC-SHA-256 1 KB", lambda: hmac.new(nonce, data, hashlib.sha256).digest(), "32 B tag")]
    print("| Operation | Median time (ms) | Size |\n|---|---|---|")
    for name, fn, size in rows:
        print(f"| {name} | {median_ms(fn, runs=10):.3f} | {size} |", flush=True)


class Counting:
    """Connection wrapper that counts bytes sent and received."""
    def __init__(self, conn):
        self.conn, self.bytes = conn, 0

    def send_bytes(self, data):
        self.bytes += len(data)
        self.conn.send_bytes(data)

    def recv_bytes(self):
        data = self.conn.recv_bytes()
        self.bytes += len(data)
        return data

    def close(self):
        self.conn.close()


def echo_peer(conn, key_dir):
    conn.send_bytes(b"ready")  # lets the benchmark exclude process start-up from the handshake time
    chan, _, _ = accept(conn, load_identity("processB", key_dir), key_dir)
    while True:
        msg = chan.recv()
        if msg == b"quit":
            break
        chan.send(msg)


def handshake_memory_kb(profile):
    tracemalloc.start()
    local_pair(profile, KEY_DIR)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return peak / 1024


def bench(profile, transport):
    proc, raw = spawn_peer(transport, echo_peer, KEY_DIR)
    raw.recv_bytes()
    conn = Counting(raw)
    cpu_start = time.process_time()

    start = time.perf_counter()
    chan = connect(conn, load_identity("processA", KEY_DIR), KEY_DIR, profile, "processB")
    handshake_ms = (time.perf_counter() - start) * 1000
    handshake_bytes = conn.bytes

    payload = os.urandom(SMALL)
    start = time.perf_counter()
    for _ in range(N_SMALL):
        chan.send(payload)
        chan.recv()
    rtt_ms = (time.perf_counter() - start) * 1000 / N_SMALL
    overhead = chan.last_frame_bytes - SMALL

    payload = os.urandom(LARGE)
    start = time.perf_counter()
    for _ in range(N_LARGE):
        chan.send(payload)
        chan.recv()
    throughput = N_LARGE * LARGE / (time.perf_counter() - start) / 1e6

    cpu_ms = (time.process_time() - cpu_start) * 1000
    chan.send(b"quit")
    proc.join()
    return dict(hs=handshake_ms, hs_bytes=handshake_bytes, rtt=rtt_ms, tp=throughput, cpu=cpu_ms, overhead=overhead)


def main():
    ensure_keys(KEY_DIR)
    print("## Primitives\n")
    primitives()

    print("\n## IPC (standard profile of each level)\n")
    print(f"Round-trip = {SMALL} B message sent and echoed back; throughput = {LARGE // 1024} KB messages echoed; "
          "CPU = Process A CPU time for handshake + all messages; memory = peak Python heap during one handshake (both ends).\n")
    print("| Transport | Level | Handshake (ms) | Handshake bytes | Round-trip (ms) | Throughput (MB/s) | CPU A (ms) | Handshake mem (KB) |")
    print("|---|---|---|---|---|---|---|---|")
    results = {}
    for transport in TRANSPORTS:
        for level in LEVELS:
            profile = Profile.standard(level)
            r = results[transport, level] = bench(profile, transport)
            print(f"| {transport} | L{level} {profile.name} | {r['hs']:.1f} | {r['hs_bytes']} | {r['rtt']:.3f} | "
                  f"{r['tp']:.1f} | {r['cpu']:.0f} | {handshake_memory_kb(profile):.0f} |", flush=True)

    print("\n## Measured vs the policy engine's cost model (socket transport)\n")
    print("| Level | Handshake: model (us) | Handshake: measured (ms) | Handshake bytes: model | Handshake bytes: measured | "
          "Per-message bytes: model | Per-message bytes: measured |")
    print("|---|---|---|---|---|---|---|")
    for level in LEVELS:
        m_us, m_bytes, m_frame = MODEL[level]
        r = results["socket", level]
        print(f"| L{level} {LEVELS[level][0]} | {m_us} | {r['hs']:.1f} | {m_bytes} | {r['hs_bytes']} | {m_frame} | {r['overhead']} |")
    print("\nThe model assumes optimised C code; this engine uses pure-Python ML-KEM / ML-DSA, so its PQ timings are"
          "\nhigher. Measured handshake bytes also include names, nonces, the profile and both peers' signatures.")


if __name__ == "__main__":
    main()
