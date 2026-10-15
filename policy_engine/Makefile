# Adaptive Security Policy Engine - GNU make build
#
#   make            build the CLI (build/aspe) and the tests (build/aspe_tests)
#   make test       build and run the unit tests
#   make run        build and run every phase (writes data/ and results/)
#   make plots      draw the figures from results/ (needs Python + requirements.txt)
#   make clean      remove build/
#
# Works with GNU make on Linux / macOS / MSYS2 / Git Bash and with
# mingw32-make from cmd or PowerShell on Windows.

CXX      ?= g++
CXXFLAGS ?= -std=c++14 -O2 -Wall -Wextra -Wpedantic -Wshadow
CPPFLAGS += -Iinclude
LDFLAGS  ?=

BUILD_DIR := build
SOURCES   := $(wildcard src/*.cpp)
HEADERS   := $(wildcard include/aspe/*.h)

# Detect whether recipes run in cmd.exe (Windows without a POSIX shell).
ifeq ($(OS),Windows_NT)
  EXE := .exe
  ifneq ($(findstring :\,$(shell echo %CD%)),)
    WINDOWS_CMD := 1
  endif
endif

ifdef WINDOWS_CMD
  RUN_PREFIX  := $(BUILD_DIR)\\
  CLEAN_CMD   := if exist $(BUILD_DIR) rmdir /S /Q $(BUILD_DIR)
  PYTHON      ?= python
else
  RUN_PREFIX  := ./$(BUILD_DIR)/
  CLEAN_CMD   := rm -rf $(BUILD_DIR)
  PYTHON      ?= python3
endif

# Create the build directory at parse time (portable: no mkdir flags needed).
$(if $(wildcard $(BUILD_DIR)),,$(shell mkdir $(BUILD_DIR)))

ASPE  := $(BUILD_DIR)/aspe$(EXE)
TESTS := $(BUILD_DIR)/aspe_tests$(EXE)

.PHONY: all test run plots clean

all: $(ASPE) $(TESTS)

$(ASPE): $(SOURCES) apps/aspe_main.cpp $(HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCES) apps/aspe_main.cpp -o $@ $(LDFLAGS)

$(TESTS): $(SOURCES) tests/test_main.cpp $(HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCES) tests/test_main.cpp -o $@ $(LDFLAGS)

test: $(TESTS)
	$(RUN_PREFIX)aspe_tests$(EXE)

run: $(ASPE)
	$(RUN_PREFIX)aspe$(EXE) all

plots:
	$(PYTHON) scripts/plot_results.py

clean:
	$(CLEAN_CMD)
