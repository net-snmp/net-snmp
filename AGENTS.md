# Net-SNMP Agent Guidelines (AGENTS.md)

This document provides essential instructions, architectural guidelines,
development workflows, testing procedures, and coding conventions for AI
agents and human developers working in the Net-SNMP codebase.

______________________________________________________________________

## 1. Project Overview & Architecture

Net-SNMP is a suite of software implementing the Simple Network Management
Protocol (SNMP v1, v2c, and v3) for Unix, Linux, macOS, BSD, and Windows
systems.

### Core Components and Directory Structure

- **`snmplib/`**: contains the core SNMP protocol implementation used by the
  agent and applications (`libnetsnmp`).
- **`agent/`**: The SNMP agent core (`libnetsnmpagent` and `snmpd`).
- **`agent/helpers/`**: High-level MIB implementation helpers
  (`libnetsnmpmibs`).
- **`agent/mibgroup/`**: Standard and enterprise MIB implementations.
- **`apps/`**: CLI utilities and daemons.
  - Daemons: `snmpd` (SNMP agent), `snmptrapd` (SNMP trap receiver daemon).
  - Command-line tools: `snmpget`, `snmpset`, `snmpwalk`, `snmpbulkget`,
    `snmpbulkwalk`, `snmptable`, `snmptranslate`, `snmptrap`, `snmpinform`.
- **`include/net-snmp/`**: Public API headers.
- **`mibs/`**: Standard RFC and Net-SNMP enterprise MIB definition files.
- **`perl/` & `python/`**: Scripting language bindings for Net-SNMP.
- **`testing/`**: Test infrastructure.
  - `testing/RUNFULLTESTS`: Main TAP-based integration test runner.
  - `testing/fulltests/`: Individual test scripts.
  - `testing/fuzzing/`: OSS-Fuzz fuzzers for AgentX, ASN.1, PDUs, security
    models, and transports.
- **`ci/`**: Continuous integration scripts for Linux, Windows (MinGW/MSVC),
  macOS, and BSD.

______________________________________________________________________

## 2. Authoritative Project Documentation

When instructions in this file conflict with the repository's actual build
scripts or documentation, prefer the repository's current implementation.

Useful references include:

- `README`
- `INSTALL`
- `CodingStyle`
- `configure --help`
- `testing/RUNFULLTESTS`
- documentation and README files in the affected subsystem

______________________________________________________________________

## 3. Build and Configuration Workflows

Net-SNMP uses GNU Autotools (`autoconf`, `automake`, `libtool`).

### Standard Developer Build

```bash
export MODE=regular
ci/build.sh
```

### Building with Sanitizers (Recommended for Debugging and Bug Hunting)

When diagnosing memory errors, undefined behavior, or memory leaks, compile
with AddressSanitizer/LeakSanitizer and related sanitizer instrumentation:

```bash
export MODE=asan
ci/build.sh
```

### CI Scripting Standards

Use `set -e` rather than long chains of `&&` in all `ci/*.sh` scripts to ensure
failures trigger immediate exits and accurate status codes.

______________________________________________________________________

## 4. Testing and Verification Procedures

### Running the Integration Test Suite (`testing/RUNFULLTESTS`)

The integration test suite requires Perl's `TAP::Harness`.

#### Prerequisites and Setup

Export necessary test environment variables:

```bash
export NETSNMP_SRC_DIR="$PWD"
export SNMP_NO_RUNTIME_LIMITS=1
export SNMP_VERBOSE=1
```

If testing with AddressSanitizer/LeakSanitizer:

```bash
export ASAN_OPTIONS="malloc_context_size=100:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer"
cat <<EOF > lsan.supp
leak:/usr/bin/
leak:/usr/libexec/
EOF
export LSAN_OPTIONS="suppressions=${NETSNMP_SRC_DIR}/lsan.supp"
```

#### Running Tests

Run the narrowest relevant test first. Run the full suite when practical or
when the change affects shared infrastructure.

```bash
cd testing

# Run the complete test suite
./RUNFULLTESTS -g all

# Run a specific test group
./RUNFULLTESTS -g tls
./RUNFULLTESTS -g unit-tests

# Run a single test case
./RUNFULLTESTS -r T111DtlsServer
./RUNFULLTESTS -r T121DtlsTrap_simple

cd ..
```

When using an instrumented build, inspect the test output for sanitizer
failures and investigate any ASan, LSan, or UBSan reports before submitting
the change.

### Perl Module Tests

Run the Perl tests as follows:

```bash
ci/net-snmp-run-perl-tests
```

### Python Module Tests

Run the Python tests as follows:

```bash
ci/net-snmp-run-python-tests
```

### Fuzzing (`testing/fuzzing/`)

Fuzzing infrastructure is available under testing/fuzzing/. Changes to
protocol parsing, ASN.1 handling, transports, or other security-sensitive
input processing should consider the applicable fuzz targets.

Build fuzz tests:

```bash
make -C testing -s fuzz-tests
```

### Test Script Portability

All test shell script code must be POSIX compliant and must not use GNU
extensions. For example, test scripts must avoid GNU-specific `sed` expressions
(such as `\+`, `\s`, or in-place `-i`). Tests must remain portable across
FreeBSD, macOS, and Linux.

______________________________________________________________________

## 5. Coding Style and Conventions

All code must adhere to the style defined in the [`CodingStyle`](CodingStyle)
file, which specifies the indentation (Berkeley style `indent` options),
bracing, comment formatting, and layout conventions. When modifying existing
files, do not reformat the entire file—only newly added or modified sections
of code should follow this style to keep diffs reviewable.

### Naming Conventions

- **Functions and variables**: `snake_case` (e.g., `calculate_timeout()`,
  `session_list`).
- **Public library APIs**: Must begin with `netsnmp_` (e.g.,
  `netsnmp_get_monotonic_clock()`).
- **Public macros and defines**: Must begin with `NETSNMP_` (e.g.,
  `NETSNMP_USE_ASSERT`, `NETSNMP_MONOTONIC_CLOCK`).
- **Structures**: Typedef names should match structure types (e.g.,
  `typedef struct netsnmp_session_s netsnmp_session;`).

______________________________________________________________________

## 6. Architectural Invariants, Design Patterns, and Best Practices

### Monotonic Clocks and Timeouts

- **Never use `gettimeofday()` for measuring intervals or timeouts**, as
  system clock changes (e.g. NTP adjustments) will cause premature timeouts or
  hangs.
- **Always use `netsnmp_get_monotonic_clock(struct timeval *tv)`**.

### Transport Decoupling and Memory BIOs in TLS/DTLS

- When modifying the TLS-TCP transport (`snmpTLSTCPDomain.c`), preserve the
  existing Memory BIO based separation between OpenSSL and the underlying
  socket transport. In particular, account for pending decrypted data when
  the socket fd set indicates no new network activity.
- **Non-blocking Event Loops**: When `select()` returns `0` (timeout), check
  whether decrypted data is already buffered in OpenSSL Memory BIOs. Ensure
  event loops in `snmpd`, `snmptrapd`, and `snmp_sess_synch_response()` call
  reader routines with empty fd sets if transports report pending data.

### Robustness

- **Assertions**: Use `netsnmp_assert()` to enforce internal state consistency
  and catch programming bugs in developer builds.

### Logging Hygiene

- Internal or high-frequency diagnostic logs must use `DEBUGMSGTL()` rather than
  `snmp_log()`, keeping default syslog/stdout output clean.

### ABI Stability

- The header files in `include/net-snmp/` define an ABI. Any
  backwards-incompatible ABI modifications must be documented in `ChangeLog`.

______________________________________________________________________

## 7. Commit and Contribution Standards

- **Commit Message Format**:
  ```text
  <subsystem>: <concise description of the change>

  <detailed explanation of why the change is necessary, the root cause
   of the issue, and how the fix addresses it>
  ```
- **Common Subsystem Prefixes**:
  - `libsnmp:` Core SNMP library (`snmplib/`).
  - `snmpd:` Agent daemon and request pipeline.
  - `snmptrapd:` Trap daemon.
  - `agentx:` AgentX subagent protocol.
  - `testing:` Integration tests in `testing/fulltests/`.
  - `testing/fuzzing:` Fuzz testing harnesses in `testing/fuzzing/`.
  - `configure:` Build system and Autotools scripts.
  - `ci:` Continuous integration scripts and workflows.
  - `<MIB-NAME>:` MIB module implementations (e.g. `IF-MIB:`, `MIB-II:`,
    `UCD-SNMP:`, `RMON-MIB:`).

______________________________________________________________________

## 8. Pre-Submission Checklist

Before finalizing any changes or submitting a patch/pull request, verify the
following:

- [ ] The appropriate repository build succeeds.
- [ ] Relevant tests pass.
- [ ] Sanitizer tests pass when an instrumented build was used.
- [ ] Modified code follows CodingStyle.
- [ ] No unrelated files or formatting have been changed.
- [ ] Any backwards-incompatible ABI modifications are documented in `ChangeLog`.
