"""Process A -> secure IPC -> Process B for every transport and every security level, chosen by hand.

This is the secure IPC engine on its own. For the full project, where the policy engine picks the
level, run:  python3 -m secure_ipc.framework

Run from the project root:  python3 -m secure_ipc.demo
"""
import os

from .channel import accept, connect
from .crypto import LEVELS, Profile, ensure_keys, load_identity
from .transport import TRANSPORTS, spawn_peer

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")


def process_b(conn, key_dir):
    chan, peer, profile = accept(conn, load_identity("processB", key_dir), key_dir)
    msg = chan.recv()
    print(f"    B: authenticated '{peer}' at L{profile.level}, received {msg!r}", flush=True)
    chan.send(b"ACK " + msg)


def main():
    ensure_keys(KEY_DIR)
    for transport in TRANSPORTS:
        for level in LEVELS:
            profile = Profile.standard(level)
            print(f"[{transport} / L{level} {profile.name}]", flush=True)
            proc, conn = spawn_peer(transport, process_b, KEY_DIR)
            chan = connect(conn, load_identity("processA", KEY_DIR), KEY_DIR, profile, "processB")
            chan.send(b"Emergency detected")
            print(f"    A: got reply {chan.recv()!r}", flush=True)
            proc.join()


if __name__ == "__main__":
    main()
