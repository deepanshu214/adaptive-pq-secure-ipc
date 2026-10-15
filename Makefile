# Adaptive Post-Quantum Secure IPC Framework - one entry point for both parts.
#
#   make setup      install the Python libraries (secure IPC engine)
#   make            build the policy engine (C++)
#   make test       policy engine unit tests + attack tests on all five levels
#   make run        the complete framework: policy engine decides, secure IPC engine sends
#   make demo       secure IPC engine alone, every level over pipe and socket
#   make bench      performance of every level, compared with the policy engine's cost model

PY ?= python3

.PHONY: all setup test run demo bench clean

all:
	$(MAKE) -C policy_engine

setup:
	$(PY) -m pip install -r requirements.txt

test: all
	$(MAKE) -C policy_engine test
	$(PY) -m secure_ipc.attacks

run: all
	$(PY) -m secure_ipc.framework

demo:
	$(PY) -m secure_ipc.demo

bench:
	$(PY) -m secure_ipc.benchmark

clean:
	$(MAKE) -C policy_engine clean
	rm -rf secure_ipc/__pycache__ secure_ipc/keys
