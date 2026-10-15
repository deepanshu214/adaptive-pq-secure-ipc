"""The complete framework: the policy engine decides, the secure IPC engine carries it out.

For every message from Process A to Process B:
  1. context   message attributes + runtime state (sender trust, threat level, CPU, memory)
  2. decide    policy engine (C++, `aspe decide --json`) -> security level + parameters
  3. transmit  secure IPC engine sends the message with exactly that profile
               (a new authenticated session is opened whenever the profile changes)
  4. feedback  an attack detected by Process B lowers the sender's trust and raises the
               threat level, so the next decision is stricter

Run from the project root:  python3 -m secure_ipc.framework
"""
import os
import tempfile
import time
from multiprocessing import Event, Process
from multiprocessing.connection import Client, Listener

from . import policy
from .channel import AuthError, IntegrityError, ReplayError, accept, connect
from .crypto import Profile, ensure_keys, load_identity

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
THREATS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# The specification scenarios of the policy engine (policy_engine/src/dataset.cpp).
SCENARIOS = [
    dict(type="Status", sensitivity="LOW", criticality="LOW", size=128, lifetime=0.05,
         trust="HIGH", threat="LOW", cpu=30, memory=40),
    dict(type="Gaze", sensitivity="MEDIUM", criticality="MEDIUM", size=256, lifetime=1.0,
         trust="HIGH", threat="LOW", cpu=40, memory=45),
    dict(type="Profile", sensitivity="HIGH", criticality="HIGH", size=4096, lifetime=8.0,
         trust="MEDIUM", threat="MEDIUM", cpu=50, memory=50),
    dict(type="Emergency", sensitivity="CRITICAL", criticality="CRITICAL", size=512, lifetime=15.0,
         trust="MEDIUM", threat="HIGH", cpu=60, memory=55),
    dict(type="Alert", sensitivity="CRITICAL", criticality="CRITICAL", size=256, lifetime=12.0,
         trust="LOW", threat="HIGH", cpu=80, memory=60),
]


# ---------- Process B: the receiver ----------

def process_b(path, key_dir, ready):
    """Accepts sessions at any level, answers every message, and reports detected attacks."""
    me = load_identity("processB", key_dir)
    with Listener(path, family="AF_UNIX") as listener:
        ready.set()
        while True:
            conn = listener.accept()
            try:
                chan, peer, profile = accept(conn, me, key_dir)
            except AuthError:
                continue
            while True:
                try:
                    msg = chan.recv()
                except EOFError:
                    break
                except (IntegrityError, ReplayError) as e:
                    chan.send(f"ATTACK {type(e).__name__}: {e}".encode())
                    continue
                if msg == b"__shutdown__":
                    chan.send(b"BYE")
                    return
                chan.send(f"ACK L{profile.level} {len(msg)} B from {peer}".encode())


# ---------- Process A: the framework ----------

class Link:
    """The IPC connection, with a switch that simulates a man in the middle changing the next frame."""
    def __init__(self, conn):
        self.conn, self.tamper_next = conn, False

    def send_bytes(self, data):
        if self.tamper_next:
            data, self.tamper_next = data[:-1] + bytes([data[-1] ^ 1]), False
        self.conn.send_bytes(data)

    def recv_bytes(self):
        return self.conn.recv_bytes()

    def close(self):
        self.conn.close()


class Monitors:
    """Runtime state fed back into the policy engine: trust in the sender and the threat level.
    (A simple version of the engine's own monitors in policy_engine/src/runtime_monitor.cpp.)"""
    def __init__(self):
        self.trust = None       # sender trust after feedback (None = nothing observed yet)
        self.threat_steps = 0   # how many levels detected attacks have added to the threat

    def context(self, message):
        trust = policy.TRUST_SCORES[message["trust"]]
        if self.trust is not None:
            trust = min(trust, self.trust)
        threat = THREATS[min(3, THREATS.index(message["threat"]) + self.threat_steps)]
        return dict(trust=trust, threat=threat, cpu=message["cpu"], memory=message["memory"])

    def attack_detected(self, message):
        self.trust = self.context(message)["trust"] / 2
        self.threat_steps += 1


class SecureIpcFramework:
    def __init__(self, key_dir=KEY_DIR):
        ensure_keys(key_dir)
        policy.warm_up()
        self.key_dir, self.me = key_dir, load_identity("processA", key_dir)
        self.monitors = Monitors()
        self.path = os.path.join(tempfile.mkdtemp(), "ipc.sock")
        ready = Event()
        self.receiver = Process(target=process_b, args=(self.path, key_dir, ready))
        self.receiver.start()
        ready.wait()
        self.chan, self.profile, self.link = None, None, None

    def _session(self, profile):
        """Reuses the open session, or opens a new authenticated one if the profile changed."""
        if profile == self.profile:
            return 0.0
        if self.chan:
            self.chan.close()
        start = time.perf_counter()
        self.link = Link(Client(self.path, family="AF_UNIX"))
        self.chan = connect(self.link, self.me, self.key_dir, profile, "processB")
        self.profile = profile
        return (time.perf_counter() - start) * 1000

    def send(self, message, payload, tamper=False):
        context = self.monitors.context(message)
        start = time.perf_counter()
        decision = policy.decide(message, context)
        decide_ms = (time.perf_counter() - start) * 1000

        handshake_ms = self._session(Profile.from_decision(decision))
        self.link.tamper_next = tamper
        start = time.perf_counter()
        self.chan.send(payload)
        reply = self.chan.recv().decode()
        send_ms = (time.perf_counter() - start) * 1000

        attacked = reply.startswith("ATTACK")
        if attacked:
            self.monitors.attack_detected(message)
        return dict(decision=decision, context=context, decide_ms=decide_ms, handshake_ms=handshake_ms,
                    send_ms=send_ms, wire_bytes=self.chan.last_frame_bytes, reply=reply, attacked=attacked)

    def close(self):
        if self.chan is None:
            self._session(Profile.standard(1))
        self.chan.send(b"__shutdown__")
        self.chan.recv()
        self.receiver.join()


def describe(r):
    d, c = r["decision"], r["context"]
    return (f"    context  : trust {c['trust']:.2f}, threat {c['threat']}, CPU {c['cpu']}%\n"
            f"    decision : L{d['selected_level']} {d['policy']} / {d['mode']}  "
            f"[{d['key_establishment']} | {d['authentication']} | {d['payload_protection']}]\n"
            f"               re-key every {d['rekey_interval'] or '-'} msgs, per-message signature "
            f"{'yes' if d['per_message_signature'] else 'no'}  ({d['reason']})\n"
            f"    measured : decision {r['decide_ms']:.1f} ms, "
            + (f"new session {r['handshake_ms']:.1f} ms, " if r["handshake_ms"] else "session reused, ")
            + f"send + reply {r['send_ms']:.2f} ms, {r['wire_bytes']} B on the wire\n"
            f"    Process B: {r['reply']}")


def main():
    framework = SecureIpcFramework()

    print("=== Part 1: the five specification scenarios, end to end ===\n")
    for message in SCENARIOS:
        payload = f"{message['type']} message".encode().ljust(message["size"], b".")
        print(f"[{message['type']}] sensitivity {message['sensitivity']}, criticality {message['criticality']}")
        print(describe(framework.send(message, payload)) + "\n")

    print("=== Part 2: adaptation after an attack (6 Gaze messages, a man in the middle changes #3) ===\n")
    gaze = SCENARIOS[1]
    for i in range(1, 7):
        result = framework.send(gaze, f"Gaze sample {i}".encode(), tamper=(i == 3))
        d = result["decision"]
        note = "  <- frame changed in transit" if i == 3 else ""
        print(f"  #{i}  trust {result['context']['trust']:.2f}  threat {result['context']['threat']:<6}  ->  "
              f"L{d['selected_level']} {d['policy']:<9}  {result['reply']}{note}")
    print("\n  After the attack the policy engine raised Gaze from CLASSICAL to a quantum-safe level"
          "\n  and a new authenticated session was opened automatically.")
    framework.close()


if __name__ == "__main__":
    main()
