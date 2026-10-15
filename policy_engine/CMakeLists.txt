cmake_minimum_required(VERSION 3.10)

project(AdaptiveSecurityPolicyEngine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Core library: everything the partner project links against.
add_library(aspe_core
  src/classifier.cpp
  src/crypto_suite.cpp
  src/dataset.cpp
  src/evaluation.cpp
  src/integration.cpp
  src/parameters.cpp
  src/policy_engine.cpp
  src/risk_model.cpp
  src/runtime_monitor.cpp
  src/simulation.cpp
  src/threat_analysis.cpp
  src/types.cpp
  src/util.cpp
)
target_include_directories(aspe_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
  target_compile_options(aspe_core PRIVATE /W4 /utf-8)
else()
  target_compile_options(aspe_core PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()

add_executable(aspe apps/aspe_main.cpp)
target_link_libraries(aspe PRIVATE aspe_core)

add_executable(aspe_tests tests/test_main.cpp)
target_link_libraries(aspe_tests PRIVATE aspe_core)

enable_testing()
add_test(NAME aspe_tests COMMAND aspe_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
