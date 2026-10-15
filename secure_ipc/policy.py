"""Bridge to the Adaptive Security Policy Engine (Aditya's C++ part, in policy_engine/).

The engine is asked through its documented JSON interface:  aspe decide --json ...
It answers with the selected security level and its parameters (re-key interval, per-message
signature, ...), which crypto.Profile.from_decision turns into a profile for the secure channel.
"""
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASPE = os.path.join(ROOT, "policy_engine", "build", "aspe")
PLATFORM = "reference"   # x86-64 / desktop-class cost model; "embedded" is the ARM device model
TRUST_SCORES = {"LOW": 0.20, "MEDIUM": 0.55, "HIGH": 0.85}   # same values as the engine (types.cpp)


def decide(message, context):
    """message: type, sensitivity, criticality, size, lifetime.  context: trust (0..1), threat, cpu, memory."""
    if not os.path.exists(ASPE):
        raise RuntimeError("policy engine not built yet - run:  make -C policy_engine")
    args = [ASPE, "decide", "--json", "--platform", PLATFORM,
            "--type", message["type"], "--sensitivity", message["sensitivity"],
            "--criticality", message["criticality"], "--size", str(message["size"]),
            "--lifetime", str(message["lifetime"]), "--trust", f"{context['trust']:.3f}",
            "--threat", context["threat"], "--cpu", str(context["cpu"]), "--memory", str(context["memory"])]
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def warm_up():
    """The first run of a freshly built program is slow on macOS (security scan); do it before timing."""
    decide(dict(type="WarmUp", sensitivity="LOW", criticality="LOW", size=1, lifetime=0),
           dict(trust=0.5, threat="LOW", cpu=0, memory=0))
