"""Controlled attack experiments on all five security levels. Run: python3 -m secure_ipc.attacks

Every attack is run at every level; we record whether it was detected and how long detection took.
"""
import os
import statistics
import tempfile
import time
from threading import Thread
from multiprocessing import Pipe

from .channel import AuthError, IntegrityError, ReplayError, accept, connect
from .crypto import LEVELS, Profile, create_identity, ensure_keys, load_identity
from .transport import local_pair

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
REPEATS = 3
MESSAGE = b"Emergency detected"


def flip_last_byte(data):
    return data[:-1] + bytes([data[-1] ^ 1])


class Tamper:
    """Connection wrapper that modifies everything sent through it (the man in the middle)."""
    def __init__(self, conn, change):
        self.conn, self.change = conn, change

    def send_bytes(self, data):
        self.conn.send_bytes(self.change(data))

    def recv_bytes(self):
        return self.conn.recv_bytes()

    def close(self):
        self.conn.close()


def handshake_attack(profile, a_identity, tamper_a=None, tamper_b=None):
    """Run a handshake where A uses `a_identity`; detected = either side raised AuthError."""
    a_conn, b_conn = Pipe()
    errors = []

    def side(fn, *args):
        try:
            fn(*args)
        except AuthError as e:
            errors.append(e)
        except EOFError:  # the other side rejected us and hung up
            pass

    b_end = Tamper(b_conn, tamper_b) if tamper_b else b_conn
    a_end = Tamper(a_conn, tamper_a) if tamper_a else a_conn
    start = time.perf_counter()
    t = Thread(target=side, args=(accept, b_end, load_identity("processB", KEY_DIR), KEY_DIR))
    t.start()
    side(connect, a_end, a_identity, KEY_DIR, profile, "processB")
    t.join()
    return bool(errors), time.perf_counter() - start


def message_attack(profile, attack):
    """Attack on an established channel. Returns (detected, seconds)."""
    a, b = local_pair(profile, KEY_DIR)
    frame = a.seal(MESSAGE)
    if attack == "replayed message":
        a.conn.send_bytes(frame)
        b.recv()  # first delivery is legitimate
        expected = ReplayError
    elif attack == "modified message":
        frame = flip_last_byte(frame)
        expected = IntegrityError
    else:  # corrupted ciphertext
        frame = frame[:8] + os.urandom(len(frame) - 8)
        expected = IntegrityError
    a.conn.send_bytes(frame)
    start = time.perf_counter()
    try:
        b.recv()
    except expected:
        return True, time.perf_counter() - start
    return False, time.perf_counter() - start


def run_attack(name, profile, tmp_dir):
    if name == "unauthorized process":      # valid keys, but not in the registry
        create_identity("mallory", tmp_dir)
        return handshake_attack(profile, load_identity("mallory", tmp_dir))
    if name == "fake process":              # claims to be processA but holds different keys
        create_identity("processA", tmp_dir)
        return handshake_attack(profile, load_identity("processA", tmp_dir))
    if name == "invalid authentication":    # A's signature is corrupted in transit
        return handshake_attack(profile, load_identity("processA", KEY_DIR), tamper_a=flip_last_byte)
    if name == "invalid signature":         # B's signature is corrupted in transit
        return handshake_attack(profile, load_identity("processA", KEY_DIR), tamper_b=flip_last_byte)
    return message_attack(profile, name)


ATTACKS = ["unauthorized process", "fake process", "modified message", "replayed message",
           "invalid authentication", "corrupted ciphertext", "invalid signature"]


def main():
    ensure_keys(KEY_DIR)
    profiles = [Profile.standard(level) for level in LEVELS]
    print("| Attack | " + " | ".join(f"L{p.level} {p.name}" for p in profiles) + " |")
    print("|---|" + "---|" * len(profiles))
    all_detected = True
    with tempfile.TemporaryDirectory() as tmp_dir:
        for name in ATTACKS:
            cells = []
            for profile in profiles:
                runs = [run_attack(name, profile, tmp_dir) for _ in range(REPEATS)]
                detected = all(d for d, _ in runs)
                all_detected &= detected
                ms = statistics.median(t for _, t in runs) * 1000
                cells.append(f"{'Detected' if detected else 'MISSED'} ({ms:.1f} ms)")
            print(f"| {name} | " + " | ".join(cells) + " |", flush=True)
    print("\nAll attacks detected at all levels." if all_detected else "\nSOME ATTACKS WERE MISSED.")


if __name__ == "__main__":
    main()
