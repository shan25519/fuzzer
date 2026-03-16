# Test Scenario Reference

Complete catalog of all fuzzer test scenarios across **754 tests** in **6 protocols**.

## How to Read This Document

Each test sends crafted protocol data and checks the target's response:

| Term | Meaning |
|------|---------|
| **Expected = DROPPED** | Target SHOULD reject this input (security test) |
| **Expected = PASSED** | Target SHOULD accept this input (compatibility test) |
| **PASS** | Behavior matched expectations |
| **FAIL** | Target accepted malicious input it should have rejected, or crashed |
| **WARN** | Target was stricter than expected (rejected valid input) |
| **INFO** | No expected value set, or scenario errored/aborted |

**Side** indicates who sends the test data:
- **Client → Server** — Fuzzer connects to target and sends malformed data
- **Server → Client** — Fuzzer acts as server and sends malformed responses to connecting client

## Table of Contents

- [**TLS** (445 tests)](#tls-scenarios)
  - [A: Handshake Order Violations (Client) (10)](#a-handshake-order-violations-client)
  - [B: Handshake Order Violations (Server) (5)](#b-handshake-order-violations-server)
  - [C: Parameter Mutation (10)](#c-parameter-mutation)
  - [D: Alert Injection (12)](#d-alert-injection)
  - [E: TCP Manipulation (12)](#e-tcp-manipulation)
  - [F: Record Layer Attacks (22)](#f-record-layer-attacks)
  - [G: ChangeCipherSpec Attacks (8)](#g-changecipherspec-attacks)
  - [H: Extension Fuzzing (10)](#h-extension-fuzzing)
  - [I: Known Vulnerability Detection (CVEs) (32)](#i-known-vulnerability-detection-cves)
  - [J: Post-Quantum Cryptography (PQC) (16)](#j-post-quantum-cryptography-pqc)
  - [K: SNI Evasion & Fragmentation (16)](#k-sni-evasion-fragmentation)
  - [L: ALPN Protocol Confusion (13)](#l-alpn-protocol-confusion)
  - [M: Extension Malformation & Placement (22)](#m-extension-malformation-placement)
  - [N: TCP/TLS Parameter Reneging (20)](#n-tcp-tls-parameter-reneging)
  - [O: TLS 1.3 Early Data & 0-RTT Fuzzing (24)](#o-tls-1-3-early-data-0-rtt-fuzzing)
  - [P: Advanced Handshake Record Fuzzing (26)](#p-advanced-handshake-record-fuzzing)
  - [Q: ClientHello Field Mutations (24)](#q-clienthello-field-mutations)
  - [R: Extension Inner Structure Fuzzing (28)](#r-extension-inner-structure-fuzzing)
  - [S: Record Layer Byte Attacks (16)](#s-record-layer-byte-attacks)
  - [T: Alert & CCS Byte-Level Fuzzing (20)](#t-alert-ccs-byte-level-fuzzing)
  - [U: Handshake Type & Legacy Protocol Fuzzing (20)](#u-handshake-type-legacy-protocol-fuzzing)
  - [V: Cipher Suite & Signature Algorithm Fuzzing (22)](#v-cipher-suite-signature-algorithm-fuzzing)
  - [W: Server Certificate X.509 Field Fuzzing (15)](#w-server-certificate-x-509-field-fuzzing)
  - [X: Client Certificate Abuse (24)](#x-client-certificate-abuse)
  - [Y: Certificate Chain & Message Structure (8)](#y-certificate-chain-message-structure)
  - [Z: Well-behaved Counterparts (10)](#z-well-behaved-counterparts)
- [**TLS Scan** (107 tests)](#tls-scan-scenarios)
  - [SCAN: TLS Compatibility Scanning (107)](#scan-tls-compatibility-scanning)
- [**HTTP/2** (70 tests)](#http-2-scenarios)
  - [AA: HTTP/2 CVE & Rapid Attack (2)](#aa-http-2-cve-rapid-attack)
  - [AB: HTTP/2 Flood / Resource Exhaustion (3)](#ab-http-2-flood-resource-exhaustion)
  - [AC: HTTP/2 Stream & Flow Control Violations (4)](#ac-http-2-stream-flow-control-violations)
  - [AD: HTTP/2 Frame Structure & Header Attacks (5)](#ad-http-2-frame-structure-header-attacks)
  - [AE: HTTP/2 Stream Abuse Extensions (2)](#ae-http-2-stream-abuse-extensions)
  - [AF: HTTP/2 Extended Frame Attacks (7)](#af-http-2-extended-frame-attacks)
  - [AG: HTTP/2 Flow Control Attacks (4)](#ag-http-2-flow-control-attacks)
  - [AH: HTTP/2 Connectivity & TLS Probes (12)](#ah-http-2-connectivity-tls-probes)
  - [AI: HTTP/2 General Frame Mutation (1)](#ai-http-2-general-frame-mutation)
  - [AJ: HTTP/2 Server-to-Client Attacks (10)](#aj-http-2-server-to-client-attacks)
  - [AK: HTTP/2 Server Protocol Violations (9)](#ak-http-2-server-protocol-violations)
  - [AL: HTTP/2 Server Header Violations (11)](#al-http-2-server-header-violations)
- [**QUIC** (33 tests)](#quic-scenarios)
  - [QA: QUIC Handshake & Connection Initial (7)](#qa-quic-handshake-connection-initial)
  - [QB: QUIC Transport Parameters & ALPN (2)](#qb-quic-transport-parameters-alpn)
  - [QC: QUIC Resource Exhaustion & DoS (2)](#qc-quic-resource-exhaustion-dos)
  - [QD: QUIC Flow Control & Stream Errors (6)](#qd-quic-flow-control-stream-errors)
  - [QE: QUIC Connection Migration & Path (2)](#qe-quic-connection-migration-path)
  - [QF: QUIC Frame Structure & Mutation (3)](#qf-quic-frame-structure-mutation)
  - [QL: QUIC Server-to-Client Attacks (11)](#ql-quic-server-to-client-attacks)
- [**QUIC Scan** (46 tests)](#quic-scan-scenarios)
  - [QSCAN: QUIC Compatibility Scanning (46)](#qscan-quic-compatibility-scanning)
- [**Raw TCP** (53 tests)](#raw-tcp-scenarios)
  - [RA: TCP SYN Attacks (5)](#ra-tcp-syn-attacks)
  - [RB: TCP RST Injection (5)](#rb-tcp-rst-injection)
  - [RC: TCP Sequence/ACK Manipulation (4)](#rc-tcp-sequence-ack-manipulation)
  - [RD: TCP Window Attacks (5)](#rd-tcp-window-attacks)
  - [RE: TCP Segment Reordering & Overlap (6)](#re-tcp-segment-reordering-overlap)
  - [RF: TCP Urgent Pointer Attacks (3)](#rf-tcp-urgent-pointer-attacks)
  - [RG: TCP State Machine Fuzzing (7)](#rg-tcp-state-machine-fuzzing)
  - [RH: TCP Option Fuzzing (TLS) (15)](#rh-tcp-option-fuzzing-tls)
  - [RX: Advanced TLS/H2 TCP Fuzzing (3)](#rx-advanced-tls-h2-tcp-fuzzing)

---

## TLS Scenarios

### A: Handshake Order Violations (Client)

> 🟠 high · 10 tests · 10 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `out-of-order-finished-first-small-ch` | → | Send Finished before ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 2 | `out-of-order-finished-first-pqc-ch` | → | Send Finished before ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 3 | `out-of-order-cke-before-hello-small-ch` | → | Send ClientKeyExchange before ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 4 | `out-of-order-cke-before-hello-pqc-ch` | → | Send ClientKeyExchange before ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 5 | `duplicate-client-hello-small-ch` | → | Send ClientHello twice [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 6 | `duplicate-client-hello-pqc-ch` | → | Send ClientHello twice [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 7 | `client-hello-after-finished-small-ch` | → | Send ClientHello, receive ServerHello, then send another ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 8 | `client-hello-after-finished-pqc-ch` | → | Send ClientHello, receive ServerHello, then send another ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 9 | `skip-client-key-exchange-small-ch` | → | ClientHello then jump straight to ChangeCipherSpec + Finished [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 10 | `skip-client-key-exchange-pqc-ch` | → | ClientHello then jump straight to ChangeCipherSpec + Finished [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |

### B: Handshake Order Violations (Server)

> 🟠 high · 5 tests · 5 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `server-hello-before-client-hello` | ← | Server sends ServerHello immediately without waiting for ClientHello | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server handshake order violations (state machine bypass) |
| 2 | `duplicate-server-hello` | ← | Server sends ServerHello twice | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server handshake order violations (state machine bypass) |
| 3 | `skip-server-hello-done` | ← | Server omits ServerHelloDone | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server handshake order violations (state machine bypass) |
| 4 | `certificate-before-server-hello` | ← | Server sends Certificate before ServerHello | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server handshake order violations (state machine bypass) |
| 5 | `double-server-hello-done` | ← | Server sends ServerHelloDone twice | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server handshake order violations (state machine bypass) |

### C: Parameter Mutation

> 🟡 medium · 10 tests · 8 Client → Server, 2 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `version-downgrade-mid-handshake-small-ch` | → | ClientHello says TLS 1.2, then CKE record header says TLS 1.0 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 2 | `version-downgrade-mid-handshake-pqc-ch` | → | ClientHello says TLS 1.2, then CKE record header says TLS 1.0 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 3 | `session-id-mutation-small-ch` | → | Change session ID between handshake messages [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 4 | `session-id-mutation-pqc-ch` | → | Change session ID between handshake messages [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 5 | `sni-mismatch-small-ch` | → | Send ClientHello with SNI "a.com", then another with SNI "b.com" [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 6 | `sni-mismatch-pqc-ch` | → | Send ClientHello with SNI "a.com", then another with SNI "b.com" [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 7 | `random-overwrite-small-ch` | → | Send identical ClientHello but with different random value [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 8 | `random-overwrite-pqc-ch` | → | Send identical ClientHello but with different random value [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 9 | `cipher-suite-mismatch` | ← | Server selects a cipher suite not in client's offered list | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 10 | `compression-method-mismatch` | ← | Server picks DEFLATE compression when client only offered NULL | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |

### D: Alert Injection

> 🟡 medium · 12 tests · 12 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `alert-during-handshake-small-ch` | → | Send warning alert between ClientHello and CKE [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 2 | `alert-during-handshake-pqc-ch` | → | Send warning alert between ClientHello and CKE [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 3 | `fatal-alert-then-continue-small-ch` | → | Send fatal alert then continue handshake as if nothing happened [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 4 | `fatal-alert-then-continue-pqc-ch` | → | Send fatal alert then continue handshake as if nothing happened [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 5 | `close-notify-mid-handshake-small-ch` | → | Send close_notify then continue with more messages [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 6 | `close-notify-mid-handshake-pqc-ch` | → | Send close_notify then continue with more messages [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 7 | `unknown-alert-type-small-ch` | → | Send alert with undefined description code (255) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 8 | `unknown-alert-type-pqc-ch` | → | Send alert with undefined description code (255) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 9 | `alert-flood-small-ch` | → | Rapid-fire 20 warning alerts [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 10 | `alert-flood-pqc-ch` | → | Rapid-fire 20 warning alerts [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 11 | `alert-wrong-level-small-ch` | → | Send handshake_failure with warning level instead of fatal [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 12 | `alert-wrong-level-pqc-ch` | → | Send handshake_failure with warning level instead of fatal [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |

### E: TCP Manipulation

> 🔵 low · 12 tests · 10 Client → Server, 2 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `fin-after-client-hello-small-ch` | → | Send ClientHello, then TCP FIN, then try to continue [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 2 | `fin-after-client-hello-pqc-ch` | → | Send ClientHello, then TCP FIN, then try to continue [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 3 | `rst-mid-handshake-small-ch` | → | Send ClientHello, receive response, then TCP RST [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 4 | `rst-mid-handshake-pqc-ch` | → | Send ClientHello, receive response, then TCP RST [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 5 | `half-close-continue-small-ch` | → | Half-close write side then send more TLS records [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 6 | `half-close-continue-pqc-ch` | → | Half-close write side then send more TLS records [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 7 | `slow-drip-client-hello-small-ch` | → | Send ClientHello 1 byte at a time with delays [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 8 | `slow-drip-client-hello-pqc-ch` | → | Send ClientHello 1 byte at a time with delays [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 9 | `split-record-across-segments-small-ch` | → | Fragment a ClientHello TLS record across 10 TCP segments [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 10 | `split-record-across-segments-pqc-ch` | → | Fragment a ClientHello TLS record across 10 TCP segments [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 11 | `fin-after-server-hello` | ← | Server sends ServerHello then TCP FIN then continues | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |
| 12 | `fin-from-both` | ← | Server sends FIN immediately after ServerHello, simulating simultaneous FIN | DROPPED | ✅ if rejected; ❌ if accepted. Must reject TCP manipulation abuse |

### F: Record Layer Attacks

> 🟠 high · 22 tests · 22 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `tls13-strict-record-version-12-small-ch` | → | TLS 1.3 ClientHello using Record Version 0x0303 (TLS 1.2) instead of 0x0301 (Legacy) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Standard TLS 1.3 servers usually accept 0x0303, though RFC 8446 recommends 0x0301 |
| 2 | `tls13-strict-record-version-12-pqc-ch` | → | TLS 1.3 ClientHello using Record Version 0x0303 (TLS 1.2) instead of 0x0301 (Legacy) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Standard TLS 1.3 servers usually accept 0x0303, though RFC 8446 recommends 0x0301 |
| 3 | `tls13-strict-record-version-13-small-ch` | → | TLS 1.3 ClientHello using Record Version 0x0304 (TLS 1.3) — often dropped by middleboxes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Strict TLS 1.3 servers might accept this, but many drop it for middlebox compatibility reasons |
| 4 | `tls13-strict-record-version-13-pqc-ch` | → | TLS 1.3 ClientHello using Record Version 0x0304 (TLS 1.3) — often dropped by middleboxes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Strict TLS 1.3 servers might accept this, but many drop it for middlebox compatibility reasons |
| 5 | `tls13-record-version-garbage-small-ch` | → | TLS 1.3 ClientHello using undefined Record Version (0x0305) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Undefined protocol versions should be rejected with an alert or connection close |
| 6 | `tls13-record-version-garbage-pqc-ch` | → | TLS 1.3 ClientHello using undefined Record Version (0x0305) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Undefined protocol versions should be rejected with an alert or connection close |
| 7 | `oversized-record-small-ch` | → | Send a TLS record > 16384 bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 8 | `oversized-record-pqc-ch` | → | Send a TLS record > 16384 bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 9 | `zero-length-record-small-ch` | → | Send a TLS record with empty payload [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 10 | `zero-length-record-pqc-ch` | → | Send a TLS record with empty payload [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 11 | `wrong-content-type-small-ch` | → | Send handshake data with application_data content type [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 12 | `wrong-content-type-pqc-ch` | → | Send handshake data with application_data content type [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 13 | `wrong-record-length-small-ch` | → | TLS record length field doesn't match actual payload [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 14 | `wrong-record-length-pqc-ch` | → | TLS record length field doesn't match actual payload [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 15 | `interleaved-content-types-small-ch` | → | Mix handshake and application_data records during handshake [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 16 | `interleaved-content-types-pqc-ch` | → | Mix handshake and application_data records during handshake [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 17 | `record-version-mismatch-small-ch` | → | Record header says TLS 1.0, ClientHello body says TLS 1.2 [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Record version often differs from body version (common compat behavior) |
| 18 | `record-version-mismatch-pqc-ch` | → | Record header says TLS 1.0, ClientHello body says TLS 1.2 [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Record version often differs from body version (common compat behavior) |
| 19 | `multiple-handshakes-one-record-small-ch` | → | Pack ClientHello + ClientKeyExchange in a single TLS record [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 20 | `multiple-handshakes-one-record-pqc-ch` | → | Pack ClientHello + ClientKeyExchange in a single TLS record [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 21 | `garbage-between-records-small-ch` | → | Random garbage bytes between valid TLS records [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 22 | `garbage-between-records-pqc-ch` | → | Random garbage bytes between valid TLS records [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |

### G: ChangeCipherSpec Attacks

> 🟠 high · 8 tests · 8 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `early-ccs-small-ch` | → | Send ChangeCipherSpec before receiving ServerHelloDone [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 2 | `early-ccs-pqc-ch` | → | Send ChangeCipherSpec before receiving ServerHelloDone [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 3 | `multiple-ccs-small-ch` | → | Send ChangeCipherSpec three times in a row [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 4 | `multiple-ccs-pqc-ch` | → | Send ChangeCipherSpec three times in a row [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 5 | `ccs-before-client-hello-small-ch` | → | Send ChangeCipherSpec as the very first message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 6 | `ccs-before-client-hello-pqc-ch` | → | Send ChangeCipherSpec as the very first message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 7 | `ccs-with-payload-small-ch` | → | ChangeCipherSpec record with extra garbage bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 8 | `ccs-with-payload-pqc-ch` | → | ChangeCipherSpec record with extra garbage bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |

### H: Extension Fuzzing

> 🟡 medium · 10 tests · 10 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `duplicate-extensions-small-ch` | → | ClientHello with the same extension type twice [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 2 | `duplicate-extensions-pqc-ch` | → | ClientHello with the same extension type twice [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 3 | `unknown-extensions-small-ch` | → | ClientHello with unregistered extension type IDs [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server should ignore unknown extensions per RFC |
| 4 | `unknown-extensions-pqc-ch` | → | ClientHello with unregistered extension type IDs [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server should ignore unknown extensions per RFC |
| 5 | `oversized-extension-small-ch` | → | ClientHello with a 64KB extension [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 6 | `oversized-extension-pqc-ch` | → | ClientHello with a 64KB extension [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 7 | `empty-sni-small-ch` | → | ClientHello with empty SNI hostname [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Empty SNI is tolerated by most servers (uses default vhost) |
| 8 | `empty-sni-pqc-ch` | → | ClientHello with empty SNI hostname [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Empty SNI is tolerated by most servers (uses default vhost) |
| 9 | `malformed-supported-versions-small-ch` | → | ClientHello with garbage data in supported_versions extension [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 10 | `malformed-supported-versions-pqc-ch` | → | ClientHello with garbage data in supported_versions extension [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |

### I: Known Vulnerability Detection (CVEs)

> 🔴 critical · 32 tests · 32 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `heartbleed-cve-2014-0160-small-ch` | → | Heartbleed: send heartbeat with oversized payload_length to leak memory [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 2 | `heartbleed-cve-2014-0160-pqc-ch` | → | Heartbleed: send heartbeat with oversized payload_length to leak memory [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 3 | `poodle-sslv3-cve-2014-3566-small-ch` | → | POODLE: attempt SSL 3.0 connection with CBC cipher [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 4 | `poodle-sslv3-cve-2014-3566-pqc-ch` | → | POODLE: attempt SSL 3.0 connection with CBC cipher [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 5 | `ccs-injection-cve-2014-0224-small-ch` | → | CCS Injection: send CCS before key exchange to force weak keys [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 6 | `ccs-injection-cve-2014-0224-pqc-ch` | → | CCS Injection: send CCS before key exchange to force weak keys [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 7 | `freak-export-rsa-cve-2015-0204-small-ch` | → | FREAK: offer only RSA export cipher suites (512-bit keys) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 8 | `freak-export-rsa-cve-2015-0204-pqc-ch` | → | FREAK: offer only RSA export cipher suites (512-bit keys) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 9 | `logjam-export-dhe-cve-2015-4000-small-ch` | → | Logjam: offer only DHE export cipher suites (512-bit DH) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 10 | `logjam-export-dhe-cve-2015-4000-pqc-ch` | → | Logjam: offer only DHE export cipher suites (512-bit DH) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 11 | `drown-sslv2-cve-2016-0800-small-ch` | → | DROWN: send SSLv2 ClientHello to check SSLv2 support [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 12 | `drown-sslv2-cve-2016-0800-pqc-ch` | → | DROWN: send SSLv2 ClientHello to check SSLv2 support [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 13 | `sweet32-3des-cve-2016-2183-small-ch` | → | Sweet32: offer only 3DES/64-bit block cipher suites [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 14 | `sweet32-3des-cve-2016-2183-pqc-ch` | → | Sweet32: offer only 3DES/64-bit block cipher suites [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 15 | `crime-compression-cve-2012-4929-small-ch` | → | CRIME: offer DEFLATE TLS compression to check if server accepts [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 16 | `crime-compression-cve-2012-4929-pqc-ch` | → | CRIME: offer DEFLATE TLS compression to check if server accepts [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 17 | `rc4-bias-cve-2013-2566-small-ch` | → | RC4 Bias: offer only RC4 cipher suites [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 18 | `rc4-bias-cve-2013-2566-pqc-ch` | → | RC4 Bias: offer only RC4 cipher suites [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 19 | `beast-cbc-tls10-cve-2011-3389-small-ch` | → | BEAST: offer TLS 1.0 with only CBC cipher suites [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 20 | `beast-cbc-tls10-cve-2011-3389-pqc-ch` | → | BEAST: offer TLS 1.0 with only CBC cipher suites [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 21 | `insecure-renegotiation-cve-2009-3555-small-ch` | → | Test for insecure TLS renegotiation by omitting renegotiation_info [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 22 | `insecure-renegotiation-cve-2009-3555-pqc-ch` | → | Test for insecure TLS renegotiation by omitting renegotiation_info [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 23 | `tls-fallback-scsv-downgrade-small-ch` | → | Downgrade detection: send TLS 1.1 ClientHello with TLS_FALLBACK_SCSV [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 24 | `tls-fallback-scsv-downgrade-pqc-ch` | → | Downgrade detection: send TLS 1.1 ClientHello with TLS_FALLBACK_SCSV [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 25 | `null-cipher-suites-small-ch` | → | Offer only NULL encryption cipher suites (no encryption) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 26 | `null-cipher-suites-pqc-ch` | → | Offer only NULL encryption cipher suites (no encryption) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 27 | `anon-dh-no-auth-small-ch` | → | Offer only anonymous DH cipher suites (no server authentication) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 28 | `anon-dh-no-auth-pqc-ch` | → | Offer only anonymous DH cipher suites (no server authentication) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 29 | `des-weak-cipher-small-ch` | → | Offer only DES cipher (56-bit key, trivially breakable) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 30 | `des-weak-cipher-pqc-ch` | → | Offer only DES cipher (56-bit key, trivially breakable) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 31 | `ticketbleed-cve-2016-9244-small-ch` | → | Ticketbleed: send session ticket with non-standard length to leak memory [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 32 | `ticketbleed-cve-2016-9244-pqc-ch` | → | Ticketbleed: send session ticket with non-standard length to leak memory [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |

### J: Post-Quantum Cryptography (PQC)

> 🔵 low · 16 tests · 16 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `pqc-hybrid-x25519-mlkem768-small-ch` | → | Send ClientHello with X25519+ML-KEM-768 hybrid key share (1216 bytes) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 2 | `pqc-hybrid-x25519-mlkem768-pqc-ch` | → | Send ClientHello with X25519+ML-KEM-768 hybrid key share (1216 bytes) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 3 | `pqc-standalone-mlkem768-small-ch` | → | Send ClientHello with standalone ML-KEM-768 key share (1184 bytes) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 4 | `pqc-standalone-mlkem768-pqc-ch` | → | Send ClientHello with standalone ML-KEM-768 key share (1184 bytes) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 5 | `pqc-kyber-draft-chrome-small-ch` | → | Send ClientHello with X25519Kyber768 draft group ID (Chrome experimental) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 6 | `pqc-kyber-draft-chrome-pqc-ch` | → | Send ClientHello with X25519Kyber768 draft group ID (Chrome experimental) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 7 | `pqc-malformed-key-share-small-ch` | → | Send PQC key share with wrong size (should be 1184, send 100) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid PQC key material |
| 8 | `pqc-malformed-key-share-pqc-ch` | → | Send PQC key share with wrong size (should be 1184, send 100) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid PQC key material |
| 9 | `pqc-oversized-key-share-small-ch` | → | Send enormously oversized PQC key share (10KB) to test buffer handling [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid PQC key material |
| 10 | `pqc-oversized-key-share-pqc-ch` | → | Send enormously oversized PQC key share (10KB) to test buffer handling [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid PQC key material |
| 11 | `pqc-multiple-key-shares-small-ch` | → | Send multiple PQC key shares: hybrid + standalone + classical [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 12 | `pqc-multiple-key-shares-pqc-ch` | → | Send multiple PQC key shares: hybrid + standalone + classical [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 13 | `pqc-unknown-group-ids-small-ch` | → | Advertise only unregistered PQC named group IDs [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid PQC key material |
| 14 | `pqc-unknown-group-ids-pqc-ch` | → | Advertise only unregistered PQC named group IDs [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid PQC key material |
| 15 | `pqc-mlkem1024-large-small-ch` | → | Send ML-KEM-1024 key share (1568 bytes, highest security level) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |
| 16 | `pqc-mlkem1024-large-pqc-ch` | → | Send ML-KEM-1024 key share (1568 bytes, highest security level) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Must reject invalid PQC key material |

### K: SNI Evasion & Fragmentation

> 🟡 medium · 16 tests · 16 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `sni-not-in-first-packet-small-ch` | → | Fragment ClientHello so SNI hostname is in the 2nd TCP segment [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 2 | `sni-not-in-first-packet-pqc-ch` | → | Fragment ClientHello so SNI hostname is in the 2nd TCP segment [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 3 | `sni-split-at-hostname-small-ch` | → | Split the ClientHello right in the middle of the SNI hostname string [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 4 | `sni-split-at-hostname-pqc-ch` | → | Split the ClientHello right in the middle of the SNI hostname string [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 5 | `sni-tiny-fragments-small-ch` | → | Fragment ClientHello into 1-byte TCP segments to evade SNI inspection [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 6 | `sni-tiny-fragments-pqc-ch` | → | Fragment ClientHello into 1-byte TCP segments to evade SNI inspection [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 7 | `sni-multiple-hostnames-small-ch` | → | SNI extension with multiple server_name entries (different hostnames) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 8 | `sni-multiple-hostnames-pqc-ch` | → | SNI extension with multiple server_name entries (different hostnames) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 9 | `sni-ip-address-small-ch` | → | SNI extension with an IP address instead of hostname [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 10 | `sni-ip-address-pqc-ch` | → | SNI extension with an IP address instead of hostname [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 11 | `sni-oversized-hostname-small-ch` | → | SNI with extremely long hostname (500 chars) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 12 | `sni-oversized-hostname-pqc-ch` | → | SNI with extremely long hostname (500 chars) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 13 | `sni-record-header-fragment-small-ch` | → | Send only the 5-byte TLS record header first, then the rest [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 14 | `sni-record-header-fragment-pqc-ch` | → | Send only the 5-byte TLS record header first, then the rest [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 15 | `sni-prepend-garbage-record-small-ch` | → | Send a garbage TLS record before the real ClientHello to confuse parsers [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 16 | `sni-prepend-garbage-record-pqc-ch` | → | Send a garbage TLS record before the real ClientHello to confuse parsers [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |

### L: ALPN Protocol Confusion

> 🟡 medium · 13 tests · 12 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `alpn-unknown-protocols-small-ch` | → | ClientHello with ALPN listing unknown/invented protocol IDs [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 2 | `alpn-unknown-protocols-pqc-ch` | → | ClientHello with ALPN listing unknown/invented protocol IDs [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 3 | `alpn-empty-protocol-small-ch` | → | ClientHello with ALPN containing empty protocol string [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 4 | `alpn-empty-protocol-pqc-ch` | → | ClientHello with ALPN containing empty protocol string [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 5 | `alpn-oversized-list-small-ch` | → | ClientHello with ALPN listing 50 protocol entries [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 6 | `alpn-oversized-list-pqc-ch` | → | ClientHello with ALPN listing 50 protocol entries [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 7 | `alpn-duplicate-protocols-small-ch` | → | ClientHello with ALPN listing "h2" five times [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 8 | `alpn-duplicate-protocols-pqc-ch` | → | ClientHello with ALPN listing "h2" five times [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 9 | `alpn-very-long-name-small-ch` | → | ClientHello with ALPN protocol name of 255 bytes (max) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 10 | `alpn-very-long-name-pqc-ch` | → | ClientHello with ALPN protocol name of 255 bytes (max) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 11 | `alpn-wrong-list-length-small-ch` | → | ALPN extension with protocol_name_list length exceeding actual data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 12 | `alpn-wrong-list-length-pqc-ch` | → | ALPN extension with protocol_name_list length exceeding actual data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 13 | `alpn-mismatch-server` | ← | Server selects ALPN "h2" when client only offered "http/1.1" | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |

### M: Extension Malformation & Placement

> 🟡 medium · 22 tests · 22 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ext-sni-wrong-length-short-small-ch` | → | SNI extension with length field shorter than actual data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 2 | `ext-sni-wrong-length-short-pqc-ch` | → | SNI extension with length field shorter than actual data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 3 | `ext-sni-wrong-length-long-small-ch` | → | SNI extension with length field longer than actual data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 4 | `ext-sni-wrong-length-long-pqc-ch` | → | SNI extension with length field longer than actual data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 5 | `ext-truncated-key-share-small-ch` | → | key_share extension truncated mid-key data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 6 | `ext-truncated-key-share-pqc-ch` | → | key_share extension truncated mid-key data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 7 | `ext-supported-versions-garbage-small-ch` | → | supported_versions with odd-length (invalid version entries) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 8 | `ext-supported-versions-garbage-pqc-ch` | → | supported_versions with odd-length (invalid version entries) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 9 | `ext-sig-algs-zero-length-small-ch` | → | signature_algorithms extension with zero algorithms listed [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 10 | `ext-sig-algs-zero-length-pqc-ch` | → | signature_algorithms extension with zero algorithms listed [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 11 | `ext-extensions-total-length-mismatch-small-ch` | → | Extensions block with total length not matching actual extension data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 12 | `ext-extensions-total-length-mismatch-pqc-ch` | → | Extensions block with total length not matching actual extension data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 13 | `ext-in-cke-message-small-ch` | → | Embed ClientHello extensions inside a ClientKeyExchange message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 14 | `ext-in-cke-message-pqc-ch` | → | Embed ClientHello extensions inside a ClientKeyExchange message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 15 | `ext-nested-malformed-sni-small-ch` | → | SNI extension with valid outer length but corrupted inner structure [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 16 | `ext-nested-malformed-sni-pqc-ch` | → | SNI extension with valid outer length but corrupted inner structure [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 17 | `ext-all-unknown-critical-small-ch` | → | ClientHello with only unregistered extension types and no required ones [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 18 | `ext-all-unknown-critical-pqc-ch` | → | ClientHello with only unregistered extension types and no required ones [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 19 | `ext-groups-mismatch-key-share-small-ch` | → | supported_groups lists X25519 but key_share provides P-384 key [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 20 | `ext-groups-mismatch-key-share-pqc-ch` | → | supported_groups lists X25519 but key_share provides P-384 key [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 21 | `ext-encrypt-then-mac-with-aead-small-ch` | → | Send encrypt_then_mac extension while only offering AEAD ciphers [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 22 | `ext-encrypt-then-mac-with-aead-pqc-ch` | → | Send encrypt_then_mac extension while only offering AEAD ciphers [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |

### N: TCP/TLS Parameter Reneging

> 🟠 high · 20 tests · 20 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ccs-then-plaintext-handshake-small-ch` | → | Send CCS (signaling cipher activated) then send Finished as plaintext [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 2 | `ccs-then-plaintext-handshake-pqc-ch` | → | Send CCS (signaling cipher activated) then send Finished as plaintext [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 3 | `renegotiation-downgrade-version-small-ch` | → | ClientHello with TLS 1.2, then renegotiation ClientHello advertising only TLS 1.0 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 4 | `renegotiation-downgrade-version-pqc-ch` | → | ClientHello with TLS 1.2, then renegotiation ClientHello advertising only TLS 1.0 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 5 | `renegotiation-downgrade-cipher-small-ch` | → | Initial ClientHello with strong ciphers, renegotiation ClientHello only offering weak/export ciphers [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 6 | `renegotiation-downgrade-cipher-pqc-ch` | → | Initial ClientHello with strong ciphers, renegotiation ClientHello only offering weak/export ciphers [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 7 | `renegotiation-drop-extensions-small-ch` | → | Initial ClientHello with all extensions, renegotiation strips renegotiation_info and security extensions [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 8 | `renegotiation-drop-extensions-pqc-ch` | → | Initial ClientHello with all extensions, renegotiation strips renegotiation_info and security extensions [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 9 | `supported-groups-change-retry-small-ch` | → | ClientHello lists X25519+P-256, retry ClientHello lists only FFDHE2048 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 10 | `supported-groups-change-retry-pqc-ch` | → | ClientHello lists X25519+P-256, retry ClientHello lists only FFDHE2048 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 11 | `key-share-group-switch-small-ch` | → | First ClientHello key_share offers X25519, second offers P-384 (mismatched groups) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 12 | `key-share-group-switch-pqc-ch` | → | First ClientHello key_share offers X25519, second offers P-384 (mismatched groups) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 13 | `version-oscillation-across-records-small-ch` | → | Send multiple records alternating version fields (TLS 1.2, TLS 1.0, TLS 1.2, SSL 3.0) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 14 | `version-oscillation-across-records-pqc-ch` | → | Send multiple records alternating version fields (TLS 1.2, TLS 1.0, TLS 1.2, SSL 3.0) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 15 | `cipher-suite-set-mutation-retry-small-ch` | → | First ClientHello offers ECDHE+AES ciphers, second offers completely different set (RSA+CBC only) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 16 | `cipher-suite-set-mutation-retry-pqc-ch` | → | First ClientHello offers ECDHE+AES ciphers, second offers completely different set (RSA+CBC only) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 17 | `record-version-renege-post-hello-small-ch` | → | ClientHello record says TLS 1.0 (normal), all subsequent records say TLS 1.3 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 18 | `record-version-renege-post-hello-pqc-ch` | → | ClientHello record says TLS 1.0 (normal), all subsequent records say TLS 1.3 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 19 | `compression-renege-post-negotiation-small-ch` | → | Offer NULL compression initially, then renegotiation ClientHello offers DEFLATE [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 20 | `compression-renege-post-negotiation-pqc-ch` | → | Offer NULL compression initially, then renegotiation ClientHello offers DEFLATE [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |

### O: TLS 1.3 Early Data & 0-RTT Fuzzing

> 🟠 high · 24 tests · 24 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `tls13-early-data-no-psk-small-ch` | → | ClientHello with early_data extension but WITHOUT pre_shared_key (invalid) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 2 | `tls13-early-data-no-psk-pqc-ch` | → | ClientHello with early_data extension but WITHOUT pre_shared_key (invalid) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 3 | `tls13-garbage-early-data-small-ch` | → | ClientHello with early_data + send random garbage as application_data records [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 4 | `tls13-garbage-early-data-pqc-ch` | → | ClientHello with early_data + send random garbage as application_data records [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 5 | `tls13-early-data-wrong-content-type-small-ch` | → | Send early data using HANDSHAKE content type instead of APPLICATION_DATA [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 6 | `tls13-early-data-wrong-content-type-pqc-ch` | → | Send early data using HANDSHAKE content type instead of APPLICATION_DATA [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 7 | `tls13-fake-psk-binder-small-ch` | → | ClientHello with pre_shared_key extension containing garbage binder hash [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 8 | `tls13-fake-psk-binder-pqc-ch` | → | ClientHello with pre_shared_key extension containing garbage binder hash [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 9 | `tls13-psk-identity-overflow-small-ch` | → | PSK identity with length field claiming more bytes than provided [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 10 | `tls13-psk-identity-overflow-pqc-ch` | → | PSK identity with length field claiming more bytes than provided [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 11 | `tls13-early-data-oversized-small-ch` | → | Send 100KB of garbage as early application data (exceeds typical max_early_data_size) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 12 | `tls13-early-data-oversized-pqc-ch` | → | Send 100KB of garbage as early application data (exceeds typical max_early_data_size) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 13 | `tls13-early-data-before-client-hello-small-ch` | → | Send application data records BEFORE the ClientHello message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 14 | `tls13-early-data-before-client-hello-pqc-ch` | → | Send application data records BEFORE the ClientHello message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 15 | `tls13-multiple-psk-binders-mismatch-small-ch` | → | PSK extension with 2 identities but 3 binders (count mismatch) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 16 | `tls13-multiple-psk-binders-mismatch-pqc-ch` | → | PSK extension with 2 identities but 3 binders (count mismatch) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 17 | `tls13-early-data-wrong-version-small-ch` | → | Early data records with SSL 3.0 version in record header [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 18 | `tls13-early-data-wrong-version-pqc-ch` | → | Early data records with SSL 3.0 version in record header [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 19 | `tls13-psk-with-incompatible-cipher-small-ch` | → | PSK identity (AES-128-GCM) but ClientHello only offers ChaCha20 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 20 | `tls13-psk-with-incompatible-cipher-pqc-ch` | → | PSK identity (AES-128-GCM) but ClientHello only offers ChaCha20 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 21 | `tls13-end-of-early-data-without-early-data-small-ch` | → | Send EndOfEarlyData handshake message without having sent early_data extension [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 22 | `tls13-end-of-early-data-without-early-data-pqc-ch` | → | Send EndOfEarlyData handshake message without having sent early_data extension [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 23 | `tls13-early-data-after-finished-small-ch` | → | Send early data (application data records) AFTER sending Finished message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 24 | `tls13-early-data-after-finished-pqc-ch` | → | Send early data (application data records) AFTER sending Finished message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |

### P: Advanced Handshake Record Fuzzing

> 🟠 high · 26 tests · 26 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `handshake-fragmented-across-records-small-ch` | → | Split one ClientHello handshake message body across two separate TLS handshake records [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 2 | `handshake-fragmented-across-records-pqc-ch` | → | Split one ClientHello handshake message body across two separate TLS handshake records [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 3 | `handshake-length-overflow-small-ch` | → | Handshake message with length field set to 0xFFFFFF (16MB) but only sending tiny body [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 4 | `handshake-length-overflow-pqc-ch` | → | Handshake message with length field set to 0xFFFFFF (16MB) but only sending tiny body [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 5 | `handshake-length-underflow-small-ch` | → | Handshake length field = 10 but body is 200+ bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 6 | `handshake-length-underflow-pqc-ch` | → | Handshake length field = 10 but body is 200+ bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 7 | `handshake-body-zero-length-small-ch` | → | ClientHello with handshake length = 0 (just the 4-byte header, no body) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 8 | `handshake-body-zero-length-pqc-ch` | → | ClientHello with handshake length = 0 (just the 4-byte header, no body) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 9 | `unknown-handshake-type-small-ch` | → | Send handshake message with type 99 (undefined in spec) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 10 | `unknown-handshake-type-pqc-ch` | → | Send handshake message with type 99 (undefined in spec) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 11 | `handshake-trailing-garbage-small-ch` | → | Valid ClientHello handshake record followed by 50 garbage bytes in the same TLS record [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 12 | `handshake-trailing-garbage-pqc-ch` | → | Valid ClientHello handshake record followed by 50 garbage bytes in the same TLS record [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 13 | `handshake-header-only-no-body-small-ch` | → | Send just a 4-byte handshake header (Finished type + length=0) after valid ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 14 | `handshake-header-only-no-body-pqc-ch` | → | Send just a 4-byte handshake header (Finished type + length=0) after valid ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 15 | `handshake-split-at-header-small-ch` | → | First TLS record contains only the 4-byte handshake header, second record contains the body [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 16 | `handshake-split-at-header-pqc-ch` | → | First TLS record contains only the 4-byte handshake header, second record contains the body [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 17 | `triple-handshake-one-record-small-ch` | → | Pack ClientHello + CKE + Finished into a single TLS record [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 18 | `triple-handshake-one-record-pqc-ch` | → | Pack ClientHello + CKE + Finished into a single TLS record [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 19 | `handshake-length-exceeds-record-small-ch` | → | Handshake msg_length > TLS record payload length (claims 500 bytes, record has 100) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 20 | `handshake-length-exceeds-record-pqc-ch` | → | Handshake msg_length > TLS record payload length (claims 500 bytes, record has 100) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 21 | `interleaved-handshake-and-alert-small-ch` | → | Alternate handshake fragments with alert records between them [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 22 | `interleaved-handshake-and-alert-pqc-ch` | → | Alternate handshake fragments with alert records between them [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 23 | `handshake-type-zero-small-ch` | → | Send handshake message with type=0 (HelloRequest in TLS 1.2, unusual as client) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 24 | `handshake-type-zero-pqc-ch` | → | Send handshake message with type=0 (HelloRequest in TLS 1.2, unusual as client) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 25 | `handshake-message-max-type-small-ch` | → | Send handshake message with type=255 (maximum value) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 26 | `handshake-message-max-type-pqc-ch` | → | Send handshake message with type=255 (maximum value) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |

### Q: ClientHello Field Mutations

> 🟡 medium · 24 tests · 24 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ch-session-id-zero-length-small-ch` | → | ClientHello with session_id length = 0 (empty session ID) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 2 | `ch-session-id-zero-length-pqc-ch` | → | ClientHello with session_id length = 0 (empty session ID) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 3 | `ch-session-id-oversized-small-ch` | → | ClientHello with 255-byte session ID (exceeds 32-byte max per RFC) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 4 | `ch-session-id-oversized-pqc-ch` | → | ClientHello with 255-byte session ID (exceeds 32-byte max per RFC) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 5 | `ch-session-id-length-mismatch-small-ch` | → | Session ID length field says 32 but only 8 bytes of data follow [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 6 | `ch-session-id-length-mismatch-pqc-ch` | → | Session ID length field says 32 but only 8 bytes of data follow [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 7 | `ch-cipher-suites-empty-small-ch` | → | ClientHello with cipher_suites length = 0 (no ciphers offered) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 8 | `ch-cipher-suites-empty-pqc-ch` | → | ClientHello with cipher_suites length = 0 (no ciphers offered) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 9 | `ch-cipher-suites-odd-length-small-ch` | → | ClientHello with cipher_suites length = 3 (odd, not multiple of 2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 10 | `ch-cipher-suites-odd-length-pqc-ch` | → | ClientHello with cipher_suites length = 3 (odd, not multiple of 2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 11 | `ch-cipher-suites-length-overflow-small-ch` | → | Cipher suites length claims 1000 but only 26 bytes of data follow [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 12 | `ch-cipher-suites-length-overflow-pqc-ch` | → | Cipher suites length claims 1000 but only 26 bytes of data follow [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 13 | `ch-compression-invalid-methods-small-ch` | → | ClientHello with invalid compression methods [DEFLATE, 0x40, 0xFE, 0xFF] [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 14 | `ch-compression-invalid-methods-pqc-ch` | → | ClientHello with invalid compression methods [DEFLATE, 0x40, 0xFE, 0xFF] [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 15 | `ch-compression-empty-small-ch` | → | ClientHello with compression_methods length = 0 (none offered) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 16 | `ch-compression-empty-pqc-ch` | → | ClientHello with compression_methods length = 0 (none offered) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 17 | `ch-version-undefined-small-ch` | → | ClientHello with client_version = 0x0000 (completely undefined) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 18 | `ch-version-undefined-pqc-ch` | → | ClientHello with client_version = 0x0000 (completely undefined) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 19 | `ch-version-future-small-ch` | → | ClientHello with client_version = 0x0305 (hypothetical TLS 1.4) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 20 | `ch-version-future-pqc-ch` | → | ClientHello with client_version = 0x0305 (hypothetical TLS 1.4) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 21 | `ch-random-all-zeros-small-ch` | → | ClientHello with random field = 32 bytes of 0x00 (deterministic) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 22 | `ch-random-all-zeros-pqc-ch` | → | ClientHello with random field = 32 bytes of 0x00 (deterministic) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 23 | `ch-extensions-length-zero-with-data-small-ch` | → | Extensions total length field = 0 but real extension data follows [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |
| 24 | `ch-extensions-length-zero-with-data-pqc-ch` | → | Extensions total length field = 0 but real extension data follows [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed ClientHello fields (length/value corruption) |

### R: Extension Inner Structure Fuzzing

> 🟡 medium · 28 tests · 28 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ext-sni-name-type-invalid-small-ch` | → | SNI extension with name_type = 0xFF instead of 0x00 (host_name) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 2 | `ext-sni-name-type-invalid-pqc-ch` | → | SNI extension with name_type = 0xFF instead of 0x00 (host_name) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 3 | `ext-sni-list-length-overflow-small-ch` | → | SNI server_name_list_length claims 500 bytes but actual list is ~20 bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 4 | `ext-sni-list-length-overflow-pqc-ch` | → | SNI server_name_list_length claims 500 bytes but actual list is ~20 bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 5 | `ext-sni-hostname-null-bytes-small-ch` | → | SNI hostname with embedded null byte: "exam\x00ple.com" [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 6 | `ext-sni-hostname-null-bytes-pqc-ch` | → | SNI hostname with embedded null byte: "exam\x00ple.com" [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 7 | `ext-supported-groups-empty-list-small-ch` | → | supported_groups extension with list_length = 0 (empty group list) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 8 | `ext-supported-groups-empty-list-pqc-ch` | → | supported_groups extension with list_length = 0 (empty group list) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 9 | `ext-supported-groups-odd-length-small-ch` | → | supported_groups list_length = 3 (odd, not multiple of 2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 10 | `ext-supported-groups-odd-length-pqc-ch` | → | supported_groups list_length = 3 (odd, not multiple of 2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 11 | `ext-sig-algs-odd-length-small-ch` | → | signature_algorithms list_length = 5 (odd, not multiple of 2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 12 | `ext-sig-algs-odd-length-pqc-ch` | → | signature_algorithms list_length = 5 (odd, not multiple of 2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 13 | `ext-key-share-empty-key-small-ch` | → | key_share with group=X25519 but key_exchange_length=0 (empty key) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 14 | `ext-key-share-empty-key-pqc-ch` | → | key_share with group=X25519 but key_exchange_length=0 (empty key) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 15 | `ext-key-share-group-zero-small-ch` | → | key_share with group=0x0000 (unassigned) and 32-byte key [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 16 | `ext-key-share-group-zero-pqc-ch` | → | key_share with group=0x0000 (unassigned) and 32-byte key [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 17 | `ext-supported-versions-empty-small-ch` | → | supported_versions extension with list_length = 0 (empty version list) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 18 | `ext-supported-versions-empty-pqc-ch` | → | supported_versions extension with list_length = 0 (empty version list) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 19 | `ext-supported-versions-draft-small-ch` | → | supported_versions listing draft TLS 1.3 value 0x7f1c [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 20 | `ext-supported-versions-draft-pqc-ch` | → | supported_versions listing draft TLS 1.3 value 0x7f1c [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 21 | `ext-ec-point-formats-invalid-small-ch` | → | ec_point_formats with values [0x01, 0x02, 0xFF] (non-uncompressed) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 22 | `ext-ec-point-formats-invalid-pqc-ch` | → | ec_point_formats with values [0x01, 0x02, 0xFF] (non-uncompressed) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 23 | `ext-reneg-info-nonempty-small-ch` | → | renegotiation_info with 32 bytes of data (should be empty for initial CH) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 24 | `ext-reneg-info-nonempty-pqc-ch` | → | renegotiation_info with 32 bytes of data (should be empty for initial CH) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 25 | `ext-extended-master-secret-with-data-small-ch` | → | extended_master_secret extension with 16-byte body (should be empty) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 26 | `ext-extended-master-secret-with-data-pqc-ch` | → | extended_master_secret extension with 16-byte body (should be empty) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 27 | `ext-session-ticket-garbage-small-ch` | → | session_ticket extension with 512 bytes of random garbage [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 28 | `ext-session-ticket-garbage-pqc-ch` | → | session_ticket extension with 512 bytes of random garbage [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |

### S: Record Layer Byte Attacks

> 🟡 medium · 16 tests · 16 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `record-content-type-zero-small-ch` | → | TLS record with content_type = 0x00 (undefined) wrapping valid CH [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 2 | `record-content-type-zero-pqc-ch` | → | TLS record with content_type = 0x00 (undefined) wrapping valid CH [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 3 | `record-content-type-max-small-ch` | → | TLS record with content_type = 0xFF (max value) wrapping valid CH [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 4 | `record-content-type-max-pqc-ch` | → | TLS record with content_type = 0xFF (max value) wrapping valid CH [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 5 | `record-content-type-25-small-ch` | → | TLS record with content_type = 25 (first undefined after HEARTBEAT=24) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 6 | `record-content-type-25-pqc-ch` | → | TLS record with content_type = 25 (first undefined after HEARTBEAT=24) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 7 | `record-version-zero-small-ch` | → | TLS record with version = 0x0000 wrapping valid ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 8 | `record-version-zero-pqc-ch` | → | TLS record with version = 0x0000 wrapping valid ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 9 | `record-version-max-small-ch` | → | TLS record with version = 0xFFFF wrapping valid ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 10 | `record-version-max-pqc-ch` | → | TLS record with version = 0xFFFF wrapping valid ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 11 | `record-length-one-byte-small-ch` | → | TLS record with 1-byte payload (truncated handshake data) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 12 | `record-length-one-byte-pqc-ch` | → | TLS record with 1-byte payload (truncated handshake data) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 13 | `record-length-boundary-16384-small-ch` | → | TLS record at exact 16384-byte max boundary (spec limit) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 14 | `record-length-boundary-16384-pqc-ch` | → | TLS record at exact 16384-byte max boundary (spec limit) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 15 | `record-length-boundary-16385-small-ch` | → | TLS record at 16385 bytes (1 over max spec limit) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |
| 16 | `record-length-boundary-16385-pqc-ch` | → | TLS record at 16385 bytes (1 over max spec limit) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid record layer headers (content type/version/length) |

### T: Alert & CCS Byte-Level Fuzzing

> 🟡 medium · 20 tests · 20 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `alert-level-zero-small-ch` | → | Alert message with level=0 (undefined, below WARNING=1) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 2 | `alert-level-zero-pqc-ch` | → | Alert message with level=0 (undefined, below WARNING=1) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 3 | `alert-level-max-small-ch` | → | Alert message with level=255 (undefined, above FATAL=2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 4 | `alert-level-max-pqc-ch` | → | Alert message with level=255 (undefined, above FATAL=2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 5 | `alert-descriptions-undefined-small-ch` | → | Send alerts with 5 unused description codes: 1, 23, 55, 72, 200 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 6 | `alert-descriptions-undefined-pqc-ch` | → | Send alerts with 5 unused description codes: 1, 23, 55, 72, 200 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 7 | `alert-record-truncated-small-ch` | → | Alert record with 1-byte payload (missing description byte) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 8 | `alert-record-truncated-pqc-ch` | → | Alert record with 1-byte payload (missing description byte) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 9 | `alert-record-oversized-small-ch` | → | Alert record with 100 bytes (98 trailing garbage bytes) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 10 | `alert-record-oversized-pqc-ch` | → | Alert record with 100 bytes (98 trailing garbage bytes) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 11 | `alert-record-empty-small-ch` | → | Alert record with 0-byte payload (empty alert) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 12 | `alert-record-empty-pqc-ch` | → | Alert record with 0-byte payload (empty alert) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 13 | `ccs-payload-zero-small-ch` | → | CCS with payload byte = 0x00 (must be 0x01 per spec) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 14 | `ccs-payload-zero-pqc-ch` | → | CCS with payload byte = 0x00 (must be 0x01 per spec) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 15 | `ccs-payload-two-small-ch` | → | CCS with payload byte = 0x02 (invalid) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 16 | `ccs-payload-two-pqc-ch` | → | CCS with payload byte = 0x02 (invalid) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 17 | `ccs-payload-ff-small-ch` | → | CCS with payload byte = 0xFF (invalid) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 18 | `ccs-payload-ff-pqc-ch` | → | CCS with payload byte = 0xFF (invalid) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 19 | `ccs-record-empty-small-ch` | → | CCS record with 0-byte payload (empty) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |
| 20 | `ccs-record-empty-pqc-ch` | → | CCS record with 0-byte payload (empty) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed alert and CCS messages (byte-level corruption) |

### U: Handshake Type & Legacy Protocol Fuzzing

> 🟡 medium · 20 tests · 20 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `hs-server-hello-from-client-small-ch` | → | Client sends ServerHello (handshake type 2) as first message — role violation [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 2 | `hs-server-hello-from-client-pqc-ch` | → | Client sends ServerHello (handshake type 2) as first message — role violation [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 3 | `hs-certificate-unrequested-small-ch` | → | Client sends Certificate (handshake type 11) as first message — unrequested [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 4 | `hs-certificate-unrequested-pqc-ch` | → | Client sends Certificate (handshake type 11) as first message — unrequested [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 5 | `hs-key-update-pre-encryption-small-ch` | → | Client sends KeyUpdate (handshake type 24) before encryption is established [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 6 | `hs-key-update-pre-encryption-pqc-ch` | → | Client sends KeyUpdate (handshake type 24) before encryption is established [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 7 | `hs-undefined-types-batch-small-ch` | → | After valid CH, send 5 undefined handshake types: 3, 6, 7, 9, 10 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 8 | `hs-undefined-types-batch-pqc-ch` | → | After valid CH, send 5 undefined handshake types: 3, 6, 7, 9, 10 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 9 | `sslv2-version-zero-small-ch` | → | SSLv2 ClientHello with version = 0x0000 (undefined) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 10 | `sslv2-version-zero-pqc-ch` | → | SSLv2 ClientHello with version = 0x0000 (undefined) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 11 | `sslv2-challenge-empty-small-ch` | → | SSLv2 ClientHello with challenge_length = 0 (empty challenge) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 12 | `sslv2-challenge-empty-pqc-ch` | → | SSLv2 ClientHello with challenge_length = 0 (empty challenge) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 13 | `sslv2-cipher-specs-invalid-small-ch` | → | SSLv2 ClientHello with all-zero cipher specs [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 14 | `sslv2-cipher-specs-invalid-pqc-ch` | → | SSLv2 ClientHello with all-zero cipher specs [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 15 | `heartbeat-response-type-small-ch` | → | Heartbeat message with type=RESPONSE (2) instead of REQUEST (1) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 16 | `heartbeat-response-type-pqc-ch` | → | Heartbeat message with type=RESPONSE (2) instead of REQUEST (1) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 17 | `heartbeat-zero-payload-length-small-ch` | → | Heartbeat request with payload_length=0 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 18 | `heartbeat-zero-payload-length-pqc-ch` | → | Heartbeat request with payload_length=0 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 19 | `heartbeat-no-padding-small-ch` | → | Heartbeat request with payload but 0 bytes padding (RFC requires >=16) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |
| 20 | `heartbeat-no-padding-pqc-ch` | → | Heartbeat request with payload but 0 bytes padding (RFC requires >=16) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid handshake types and legacy protocol abuse |

### V: Cipher Suite & Signature Algorithm Fuzzing

> 🟡 medium · 22 tests · 22 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `cs-grease-values-small-ch` | → | ClientHello offering only GREASE cipher suites (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 2 | `cs-grease-values-pqc-ch` | → | ClientHello offering only GREASE cipher suites (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 3 | `cs-null-null-small-ch` | → | ClientHello offering only cipher suite 0x0000 (TLS_NULL_WITH_NULL_NULL) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 4 | `cs-null-null-pqc-ch` | → | ClientHello offering only cipher suite 0x0000 (TLS_NULL_WITH_NULL_NULL) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 5 | `cs-max-value-small-ch` | → | ClientHello offering only cipher suite 0xFFFF (undefined maximum) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 6 | `cs-max-value-pqc-ch` | → | ClientHello offering only cipher suite 0xFFFF (undefined maximum) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 7 | `cs-scsv-only-small-ch` | → | ClientHello with only TLS_FALLBACK_SCSV (0x5600) as sole cipher [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 8 | `cs-scsv-only-pqc-ch` | → | ClientHello with only TLS_FALLBACK_SCSV (0x5600) as sole cipher [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 9 | `cs-massive-list-small-ch` | → | ClientHello with 200 cipher suites (parser stress test) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 10 | `cs-massive-list-pqc-ch` | → | ClientHello with 200 cipher suites (parser stress test) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 11 | `sig-algs-sha1-only-small-ch` | → | signature_algorithms with only SHA-1 variants (deprecated) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 12 | `sig-algs-sha1-only-pqc-ch` | → | signature_algorithms with only SHA-1 variants (deprecated) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 13 | `sig-algs-zero-small-ch` | → | signature_algorithms with algorithm value 0x0000 (undefined) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 14 | `sig-algs-zero-pqc-ch` | → | signature_algorithms with algorithm value 0x0000 (undefined) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 15 | `sig-algs-grease-small-ch` | → | signature_algorithms with GREASE values (0x0B0B, 0x1B1B) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 16 | `sig-algs-grease-pqc-ch` | → | signature_algorithms with GREASE values (0x0B0B, 0x1B1B) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 17 | `sig-algs-massive-list-small-ch` | → | signature_algorithms with 100 entries (parser stress) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 18 | `sig-algs-massive-list-pqc-ch` | → | signature_algorithms with 100 entries (parser stress) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 19 | `groups-grease-small-ch` | → | supported_groups with GREASE values (0x0A0A, 0x1A1A) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 20 | `groups-grease-pqc-ch` | → | supported_groups with GREASE values (0x0A0A, 0x1A1A) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 21 | `groups-deprecated-small-ch` | → | supported_groups with deprecated curves (sect163k1=0x0001, sect163r2=0x0003) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |
| 22 | `groups-deprecated-pqc-ch` | → | supported_groups with deprecated curves (sect163k1=0x0001, sect163r2=0x0003) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid cipher suite and signature algorithm values |

### W: Server Certificate X.509 Field Fuzzing

> 🟡 medium · 15 tests · 15 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `cert-expired` | ← | Server certificate with notAfter in the past (expired 2001) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 2 | `cert-not-yet-valid` | ← | Server certificate with notBefore in the future (2040) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 3 | `cert-sig-algorithm-mismatch` | ← | Certificate with mismatched signature algorithms: tbsCert=SHA256/RSA, outer=ECDSA/SHA256 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 4 | `cert-signature-all-zeros` | ← | Certificate with signatureValue = 256 bytes of 0x00 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 5 | `cert-signature-truncated` | ← | Certificate with signatureValue = 1 byte only | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 6 | `cert-serial-negative` | ← | Certificate with negative serial number (leading 0xFF byte) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 7 | `cert-serial-zero` | ← | Certificate with serial number = 0 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 8 | `cert-subject-empty` | ← | Certificate with empty subject DN (no RDN sequences) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 9 | `cert-cn-null-byte` | ← | Certificate with CN containing null byte: "evil.com\x00.good.com" | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 10 | `cert-wildcard-bare` | ← | Certificate with CN = "*" (bare wildcard, no domain restriction) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 11 | `cert-san-null-byte` | ← | Certificate with SAN dNSName containing null byte: "evil.com\x00.good.com" | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 12 | `cert-v1-with-extensions` | ← | Certificate version=v1 but includes v3 extensions (invalid per X.509) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 13 | `cert-version-invalid` | ← | Certificate with version=v4 (3) — only v1/v2/v3 are defined | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 14 | `cert-pubkey-zero-length` | ← | Certificate with SubjectPublicKeyInfo containing 0-byte key data | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |
| 15 | `cert-critical-unknown-ext` | ← | Certificate with critical=TRUE unknown extension OID (must reject) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed server certificate fields (middlebox evasion) |

### X: Client Certificate Abuse

> 🟡 medium · 24 tests · 24 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `client-cert-unsolicited-post-hello-small-ch` | → | After CH→SH exchange, client sends Certificate without CertificateRequest [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 2 | `client-cert-unsolicited-post-hello-pqc-ch` | → | After CH→SH exchange, client sends Certificate without CertificateRequest [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 3 | `client-cert-before-hello-small-ch` | → | Client sends Certificate BEFORE ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 4 | `client-cert-before-hello-pqc-ch` | → | Client sends Certificate BEFORE ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 5 | `client-cert-double-small-ch` | → | Client sends two Certificate messages back-to-back [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 6 | `client-cert-double-pqc-ch` | → | Client sends two Certificate messages back-to-back [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 7 | `client-cert-empty-chain-small-ch` | → | Client sends Certificate message with 0 certificates in chain [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 8 | `client-cert-empty-chain-pqc-ch` | → | Client sends Certificate message with 0 certificates in chain [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 9 | `client-cert-garbage-der-small-ch` | → | Client sends Certificate with random garbage as DER cert data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 10 | `client-cert-garbage-der-pqc-ch` | → | Client sends Certificate with random garbage as DER cert data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 11 | `client-cert-oversized-small-ch` | → | Client sends Certificate with 32KB of cert data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 12 | `client-cert-oversized-pqc-ch` | → | Client sends Certificate with 32KB of cert data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 13 | `client-cert-verify-without-cert-small-ch` | → | Client sends CertificateVerify without prior Certificate message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 14 | `client-cert-verify-without-cert-pqc-ch` | → | Client sends CertificateVerify without prior Certificate message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 15 | `client-cert-verify-bad-signature-small-ch` | → | Client sends Certificate + CertificateVerify with random (invalid) signature [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 16 | `client-cert-verify-bad-signature-pqc-ch` | → | Client sends Certificate + CertificateVerify with random (invalid) signature [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 17 | `client-cert-verify-wrong-algorithm-small-ch` | → | CertificateVerify with undefined signature algorithm 0xFFFF [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 18 | `client-cert-verify-wrong-algorithm-pqc-ch` | → | CertificateVerify with undefined signature algorithm 0xFFFF [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 19 | `client-cert-cn-mismatch-small-ch` | → | Client certificate with CN completely unrelated to server hostname [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 20 | `client-cert-cn-mismatch-pqc-ch` | → | Client certificate with CN completely unrelated to server hostname [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 21 | `client-cert-self-signed-ca-small-ch` | → | Client certificate claiming to be CA with basicConstraints cA=TRUE [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 22 | `client-cert-self-signed-ca-pqc-ch` | → | Client certificate claiming to be CA with basicConstraints cA=TRUE [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 23 | `client-cert-and-verify-before-hello-small-ch` | → | Certificate + CertificateVerify both sent before ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |
| 24 | `client-cert-and-verify-before-hello-pqc-ch` | → | Certificate + CertificateVerify both sent before ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject unauthorized client certificate abuse |

### Y: Certificate Chain & Message Structure

> 🟡 medium · 8 tests · 8 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `cert-chain-100-depth` | ← | Certificate chain with 100 small certificates (chain depth attack) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |
| 2 | `cert-chain-length-overflow` | ← | Certificate message with certificates_length claiming 10000, actual ~500 bytes | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |
| 3 | `cert-chain-length-underflow` | ← | Certificate message with certificates_length claiming 10, actual ~500 bytes | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |
| 4 | `cert-entry-zero-length` | ← | Certificate chain with a cert entry whose length field = 0 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |
| 5 | `cert-entry-length-overflow` | ← | Certificate entry with cert_length claiming 5000 but only 200 bytes follow | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |
| 6 | `cert-chain-trailing-garbage` | ← | Valid certificate chain with 100 bytes of trailing garbage in message | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |
| 7 | `cert-chain-single-byte-entries` | ← | 50 certificate entries of 1 byte each (minimal entries) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |
| 8 | `cert-message-max-size` | ← | Certificate message with certificates_length claiming ~16MB (near max handshake length) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed certificate chain/message structure |

### Z: Well-behaved Counterparts

> 🔵 low · 10 tests · 9 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `well-behaved-client` | → | Compliant TLS client handshake — used to interact with a fuzzed server | PASSED | ✅ if accepted; ⚠️ if rejected. Well-behaved counterpart |
| 2 | `well-behaved-server` | ← | Compliant TLS server handshake — used to interact with a fuzzed client | PASSED | ✅ if accepted; ⚠️ if rejected. Well-behaved counterpart |
| 3 | `app-post-64kb` | → | HTTP POST with 64KB body — at default TCP window boundary | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 64KB POST should be accepted |
| 4 | `app-post-128kb` | → | HTTP POST with 128KB body — 2x default TCP receive window | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 128KB POST should be accepted |
| 5 | `app-post-256kb` | → | HTTP POST with 256KB body — 4x default TCP receive window | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 256KB POST should be accepted |
| 6 | `app-post-512kb` | → | HTTP POST with 512KB body — 8x default TCP receive window | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 512KB POST should be accepted |
| 7 | `app-post-1mb` | → | HTTP POST with 1MB body — large transfer spanning many TCP segments | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 1MB POST should be accepted |
| 8 | `app-post-2mb` | → | HTTP POST with 2MB body — very large transfer | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 2MB POST should be accepted |
| 9 | `app-post-10mb` | → | HTTP POST with 10MB body — extreme sustained throughput test | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 10MB POST should be accepted |
| 10 | `app-post-chunked-256kb` | → | HTTP POST with 256KB body using chunked Transfer-Encoding | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate chunked 256KB POST should be accepted |

---

## TLS Scan Scenarios

### SCAN: TLS Compatibility Scanning

> ⚪ info · 107 tests · 107 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `scan-ssl30-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `scan-ssl30-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `scan-ssl30-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `scan-ssl30-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `scan-ssl30-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 6 | `scan-ssl30-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 7 | `scan-ssl30-tls-dhe-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `scan-ssl30-tls-dhe-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `scan-tls10-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 10 | `scan-tls10-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 11 | `scan-tls10-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 12 | `scan-tls10-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 13 | `scan-tls10-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 14 | `scan-tls10-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 15 | `scan-tls10-tls-dhe-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 16 | `scan-tls10-tls-dhe-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 17 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 18 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 19 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 20 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 21 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 22 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 23 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 24 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 25 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 26 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 27 | `scan-tls11-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 28 | `scan-tls11-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 29 | `scan-tls11-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 30 | `scan-tls11-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 31 | `scan-tls11-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 32 | `scan-tls11-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 33 | `scan-tls11-tls-dhe-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 34 | `scan-tls11-tls-dhe-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 35 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 36 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 37 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 38 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 39 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 40 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 41 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 42 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 43 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 44 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 45 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 46 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 47 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 48 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 49 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 50 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 51 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 52 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 53 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 54 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 55 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 56 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 57 | `scan-tls12-tls-rsa-with-aes-128-gcm-sha256` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_128_GCM_SHA256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 58 | `scan-tls12-tls-rsa-with-aes-256-gcm-sha384` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_256_GCM_SHA384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 59 | `scan-tls12-tls-dhe-rsa-with-aes-128-gcm-sha256` | → | Test connectivity (client): TLS 1.2 + TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 60 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 61 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 62 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 63 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 64 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 65 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 66 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 67 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 68 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 69 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 70 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 71 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 72 | `scan-tls12-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 73 | `scan-tls12-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 74 | `scan-tls12-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 75 | `scan-tls12-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 76 | `scan-tls12-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 77 | `scan-tls12-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 78 | `scan-tls13-tls-aes-128-gcm-sha256-x25519` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 79 | `scan-tls13-tls-aes-128-gcm-sha256-secp256r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 80 | `scan-tls13-tls-aes-128-gcm-sha256-secp384r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 81 | `scan-tls13-tls-aes-128-gcm-sha256-secp521r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 82 | `scan-tls13-tls-aes-128-gcm-sha256-mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 83 | `scan-tls13-tls-aes-128-gcm-sha256-mlkem1024` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 84 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 85 | `scan-tls13-tls-aes-128-gcm-sha256-secp256r1_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 86 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_frodokem_640_shake` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 87 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_classic_mceliece_348864` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 88 | `scan-tls13-tls-aes-256-gcm-sha384-x25519` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 89 | `scan-tls13-tls-aes-256-gcm-sha384-secp256r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 90 | `scan-tls13-tls-aes-256-gcm-sha384-secp384r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 91 | `scan-tls13-tls-aes-256-gcm-sha384-secp521r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 92 | `scan-tls13-tls-aes-256-gcm-sha384-mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 93 | `scan-tls13-tls-aes-256-gcm-sha384-mlkem1024` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 94 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 95 | `scan-tls13-tls-aes-256-gcm-sha384-secp256r1_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 96 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_frodokem_640_shake` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 97 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_classic_mceliece_348864` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 98 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 99 | `scan-tls13-tls-chacha20-poly1305-sha256-secp256r1` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 100 | `scan-tls13-tls-chacha20-poly1305-sha256-secp384r1` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 101 | `scan-tls13-tls-chacha20-poly1305-sha256-secp521r1` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 102 | `scan-tls13-tls-chacha20-poly1305-sha256-mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 103 | `scan-tls13-tls-chacha20-poly1305-sha256-mlkem1024` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 104 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 105 | `scan-tls13-tls-chacha20-poly1305-sha256-secp256r1_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 106 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_frodokem_640_shake` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 107 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_classic_mceliece_348864` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

---

## HTTP/2 Scenarios

### AA: HTTP/2 CVE & Rapid Attack

> 🔴 critical · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-rapid-reset-cve-44487` | → | Rapid Reset Attack (CVE-2023-44487) — 100 HEADERS+RST_STREAM pairs in rapid succession | DROPPED | ✅ if rejected; ❌ if accepted. Server should rate-limit or reject rapid stream resets (CVE-2023-44487) |
| 2 | `h2-continuation-flood` | → | CONTINUATION Flood — HEADERS without END_HEADERS followed by 50 CONTINUATION frames | DROPPED | ✅ if rejected; ❌ if accepted. Server should impose limits on CONTINUATION frame count before END_HEADERS |

### AB: HTTP/2 Flood / Resource Exhaustion

> 🟠 high · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-settings-flood` | → | SETTINGS Flood — sends 1000 SETTINGS frames to exhaust server ACK queue | DROPPED | ✅ if rejected; ❌ if accepted. Server should rate-limit SETTINGS frames and not buffer unlimited ACKs |
| 2 | `h2-ping-flood` | → | PING Flood — sends 1000 PING frames to trigger 1000 PING ACK responses | DROPPED | ✅ if rejected; ❌ if accepted. Server should rate-limit PING responses to prevent amplification |
| 3 | `h2-empty-frames-flood` | → | Empty DATA Frames Flood — 50 zero-length DATA frames on a single stream | DROPPED | ✅ if rejected; ❌ if accepted. Server should limit empty DATA frames per stream |

### AC: HTTP/2 Stream & Flow Control Violations

> 🟠 high · 4 tests · 4 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-max-concurrent-streams-bypass` | → | Exceeds SETTINGS_MAX_CONCURRENT_STREAMS — opens 110 streams beyond the default limit of 100 | DROPPED | ✅ if rejected; ❌ if accepted. Server must enforce SETTINGS_MAX_CONCURRENT_STREAMS and send RST_STREAM or GOAWAY |
| 2 | `h2-erratic-window-update` | → | Erratic WINDOW_UPDATE frames — zero increment, update on closed stream, max increment | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject zero-increment WINDOW_UPDATE and updates on closed streams |
| 3 | `h2-flow-control-violation` | → | Flow Control Violation — sends DATA exceeding initial connection flow control window (65535 bytes) | DROPPED | ✅ if rejected; ❌ if accepted. Server must send FLOW_CONTROL_ERROR (code 3) when flow control window is exceeded |
| 4 | `h2-priority-circular-dependency` | → | PRIORITY frame with circular self-dependency — stream depends on itself (RFC 7540 §5.3.1) | DROPPED | ✅ if rejected; ❌ if accepted. Server must send RST_STREAM PROTOCOL_ERROR for self-dependent PRIORITY (RFC §5.3.1) |

### AD: HTTP/2 Frame Structure & Header Attacks

> 🟡 medium · 5 tests · 5 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-protocol-violation` | → | Protocol Violations — SETTINGS on non-zero stream, HEADERS on stream 0, stray CONTINUATION, undefined frame type, DATA on idle stream | DROPPED | ✅ if rejected; ❌ if accepted. Server must send GOAWAY/connection error for each of these protocol violations |
| 2 | `h2-hpack-bomb` | → | HPACK Bomb — 100 unique headers exhausting the HPACK dynamic table | DROPPED | ✅ if rejected; ❌ if accepted. Server should impose limits on HPACK dynamic table size or header count |
| 3 | `h2-invalid-header` | → | Invalid Header Fields — pseudo-header after regular header, invalid characters, oversized name | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject pseudo-header ordering violations and invalid header field names |
| 4 | `h2-invalid-frame-size` | → | Invalid Frame Size — SETTINGS with under-reported length, PING claiming wrong payload size | DROPPED | ✅ if rejected; ❌ if accepted. Server must send FRAME_SIZE_ERROR for frames with incorrect payload sizes |
| 5 | `h2-padding-fuzz` | → | Padding Abuse — HEADERS with PADDED flag where declared length exceeds actual payload | DROPPED | ✅ if rejected; ❌ if accepted. Server must send PROTOCOL_ERROR when padded frame length field is inconsistent |

### AE: HTTP/2 Stream Abuse Extensions

> 🟠 high · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-reset-flood-cve-9514` | → | Reset Flood (CVE-2019-9514) — DATA after END_STREAM on 50 streams to provoke RST_STREAM cascade | DROPPED | ✅ if rejected; ❌ if accepted. Server should RST_STREAM or GOAWAY for DATA sent after END_STREAM (CVE-2019-9514) |
| 2 | `h2-dependency-cycle` | → | Stream Dependency Cycle — self-referencing PRIORITY on 10 streams and an A↔B cross-cycle | DROPPED | ✅ if rejected; ❌ if accepted. Server should detect circular PRIORITY dependencies and send PROTOCOL_ERROR |

### AF: HTTP/2 Extended Frame Attacks

> 🟡 medium · 7 tests · 7 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-malformed-settings-frame` | → | Malformed SETTINGS — SETTINGS frame with invalid identifier 0xFFFF | DROPPED | ✅ if rejected; ❌ if accepted. Server should ignore unknown SETTINGS identifiers per RFC 7540 §6.5.2 (MUST ignore) |
| 2 | `h2-large-headers-frame` | → | Large HEADERS Frame — ~200KB of header data (200 headers × 1KB each) | DROPPED | ✅ if rejected; ❌ if accepted. Server should enforce SETTINGS_MAX_HEADER_LIST_SIZE and reject oversized HEADERS |
| 3 | `h2-zero-length-headers-cve-9516` | → | Zero-Length Headers (CVE-2019-9516) — HEADERS with empty names and empty values | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject zero-length header names per RFC 7540 §8.1.2.6 (CVE-2019-9516) |
| 4 | `h2-continuation-flood-1000` | → | Aggressive CONTINUATION Flood (CVE-2024-27316) — HEADERS without END_HEADERS + 1000 CONTINUATION frames | DROPPED | ✅ if rejected; ❌ if accepted. Server must limit CONTINUATION buffering to prevent memory exhaustion (CVE-2024-27316) |
| 5 | `h2-invalid-frame-types` | → | Unknown Frame Types — frames with type codes 0x0A, 0x0B, 0x0F, 0x42, 0xFF on streams 0 and 1 | DROPPED | ✅ if rejected; ❌ if accepted. Node.js HTTP/2 closes connection on unknown frame types on stream 0 (implementation-specific behavior) |
| 6 | `h2-connection-preface-attack` | → | Malformed Connection Preface — sends a truncated HTTP/2 client preface to test server handshake validation | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject connections that do not begin with the correct 24-byte preface |
| 7 | `h2-goaway-flood` | → | GOAWAY Flood — sends 10 GOAWAY frames with different error codes to test connection shutdown handling | DROPPED | ✅ if rejected; ❌ if accepted. Server should handle repeated GOAWAY gracefully without crashing |

### AG: HTTP/2 Flow Control Attacks

> 🟠 high · 4 tests · 4 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-flow-control-manipulation-cve-9517` | → | Flow Control Manipulation (CVE-2019-9517) — maximize connection and stream windows, open 20 streams, never read responses | DROPPED | ✅ if rejected; ❌ if accepted. Server must not buffer unbounded data when client never reads (CVE-2019-9517) |
| 2 | `h2-window-overflow` | → | Window Overflow — two WINDOW_UPDATE increments of 0x7FFFFFFF on connection and stream 1 to exceed 2^31-1 | DROPPED | ✅ if rejected; ❌ if accepted. Server must send FLOW_CONTROL_ERROR when window size exceeds 2^31-1 (RFC §6.9.1) |
| 3 | `h2-zero-window-size-cve-43622` | → | Zero Window Size (CVE-2023-43622) — SETTINGS with INITIAL_WINDOW_SIZE=0, then sends 20 requests server cannot respond to | DROPPED | ✅ if rejected; ❌ if accepted. Server must enforce response buffering limits when window size is 0 (CVE-2023-43622) |
| 4 | `h2-invalid-stream-states` | → | Invalid Stream States — DATA on idle stream, HEADERS on even stream ID, DATA on closed stream, zero-increment WINDOW_UPDATE | DROPPED | ✅ if rejected; ❌ if accepted. Server must send STREAM_CLOSED / PROTOCOL_ERROR for frames on streams in wrong states |

### AH: HTTP/2 Connectivity & TLS Probes

> ⚪ info · 12 tests · 12 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-ping-tcp` | → | TCP Connectivity Probe — basic TCP connection test to verify host:port is reachable | CONNECTED | ✅ if connected. TCP connection should succeed if host is reachable |
| 2 | `h2-ping-tls-alpn` | → | TLS + ALPN h2 Connectivity Probe — TLS connection test with ALPN h2 to verify HTTP/2 support | CONNECTED | ✅ if connected. TLS connection with ALPN h2 should succeed on an HTTP/2 server |
| 3 | `h2-alpn-correct` | → | Correct ALPN (h2) — connect with correct h2 ALPN; should succeed | CONNECTED | ✅ if connected. Server should accept the standard h2 ALPN protocol |
| 4 | `h2-alpn-incorrect` | → | Incorrect ALPN (http/1.1) — connect with HTTP/1.1 only ALPN; should fail if server requires h2 | CONNECTED | ✅ if connected. Many HTTP/2 servers (including Node.js with allowHTTP1) accept connections with non-h2 ALPN |
| 5 | `h2-alpn-mixed` | → | Mixed ALPN (h2, http/1.1) — connect with both protocols; should succeed via h2 negotiation | CONNECTED | ✅ if connected. Server should select h2 from the offered protocols and accept the connection |
| 6 | `h2-alpn-empty` | → | Empty ALPN — connect with an empty ALPN list; should fail for strict HTTP/2 servers | CONNECTED | ✅ if connected. Many HTTP/2 servers accept connections without ALPN negotiation |
| 7 | `h2-alpn-random` | → | Random/Unknown ALPN — connect with a nonsense ALPN string; should fail | FAILED_CONNECTION | ✅ if failed connection. Server should reject unknown ALPN protocols that are not h2 |
| 8 | `h2-alpn-missing` | → | Missing ALPN Extension — connect without any ALPN extension; should fail for HTTP/2 | CONNECTED | ✅ if connected. Many HTTP/2 servers accept connections without explicit ALPN extension |
| 9 | `h2-tls-v12-only` | → | TLSv1.2 Only — force TLS 1.2; should succeed (HTTP/2 requires TLS 1.2+) | CONNECTED | ✅ if connected. HTTP/2 is defined over TLS 1.2+; a TLS 1.2 connection should be accepted |
| 10 | `h2-tls-v13-only` | → | TLSv1.3 Only — force TLS 1.3; should succeed if server supports it | CONNECTED | ✅ if connected. Modern HTTP/2 servers should support TLS 1.3 |
| 11 | `h2-tls-v11-only` | → | TLSv1.1 Only — force deprecated TLS 1.1; should fail (HTTP/2 requires 1.2+) | FAILED_CONNECTION | ✅ if failed connection. HTTP/2 requires TLS 1.2 minimum per RFC 7540 §9.2; TLS 1.1 must be rejected |
| 12 | `h2-tls-negotiate` | → | TLS Version Negotiation (1.2→1.3) — allow client and server to negotiate; should succeed | CONNECTED | ✅ if connected. Normal TLS negotiation between 1.2 and 1.3 should succeed on any modern server |

### AI: HTTP/2 General Frame Mutation

> 🔵 low · 1 tests · 1 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-random-frame-mutation` | → | Random Frame Mutation — valid preface then mutated frames: unknown type, over-reported length, all flags set, even stream DATA, random garbage | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject or ignore malformed frames without crashing |

### AJ: HTTP/2 Server-to-Client Attacks

> 🟠 high · 10 tests · 10 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-server-push-flood` | ← | Server Push Flood — server sends 100 PUSH_PROMISE frames for a single client request | DROPPED | ✅ if rejected; ❌ if accepted. Client should limit the number of server pushes it accepts and RST_STREAM or GOAWAY |
| 2 | `h2-server-malformed-response-headers` | ← | Malformed Response Headers — server sends HEADERS response without required :status pseudo-header | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject responses missing the :status pseudo-header per RFC 7540 §8.1.2.4 |
| 3 | `h2-server-oversized-response-headers` | ← | Oversized Response Headers — server sends response with ~200KB of custom headers (200 × 1KB) | DROPPED | ✅ if rejected; ❌ if accepted. Client should enforce SETTINGS_MAX_HEADER_LIST_SIZE and reject oversized responses |
| 4 | `h2-server-invalid-status-code` | ← | Invalid Status Code — server sends :status 999 via raw HPACK to test client parsing | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject non-standard :status codes and reset the stream |
| 5 | `h2-server-goaway-abuse` | ← | Server GOAWAY Abuse — sends GOAWAY with misleading last-stream-id values (0 and 0x7FFFFFFF) | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle misleading GOAWAY last-stream-id values gracefully |
| 6 | `h2-server-settings-manipulation` | ← | Server Settings Manipulation — sends extreme SETTINGS: maxConcurrentStreams=0, window limits, disabled HPACK | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle extreme SETTINGS values without crash or undefined behavior |
| 7 | `h2-server-rst-stream-flood` | ← | Server RST_STREAM Flood — server immediately RST_STREAMs every incoming request with rotating error codes | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle RST_STREAM responses without crashing or hanging |
| 8 | `h2-server-continuation-flood` | ← | Server CONTINUATION Flood — server sends fragmented response headers via 500 CONTINUATION frames | DROPPED | ✅ if rejected; ❌ if accepted. Client must limit CONTINUATION buffering to prevent memory exhaustion |
| 9 | `h2-server-data-after-end-stream` | ← | Data After END_STREAM — server sends DATA frames after already ending the stream | DROPPED | ✅ if rejected; ❌ if accepted. Client must send RST_STREAM for DATA received after END_STREAM on a closed stream |
| 10 | `h2-server-window-manipulation` | ← | Server Window Manipulation — server sends zero-increment and overflow WINDOW_UPDATE frames | DROPPED | ✅ if rejected; ❌ if accepted. Client must send FLOW_CONTROL_ERROR for zero or overflowing WINDOW_UPDATE increments |

### AK: HTTP/2 Server Protocol Violations

> 🟠 high · 9 tests · 9 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-server-settings-nonzero-stream` | ← | SETTINGS on Non-Zero Stream — server sends SETTINGS on stream 1; RFC §6.5 requires stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for SETTINGS on non-zero stream (RFC §6.5) |
| 2 | `h2-server-rst-stream-zero` | ← | RST_STREAM on Stream 0 — server sends RST_STREAM on connection stream; RFC §6.4 requires stream ID > 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for RST_STREAM on stream 0 (RFC §6.4) |
| 3 | `h2-server-data-stream-zero` | ← | DATA on Stream 0 — server sends DATA frame on connection stream; only HEADERS/SETTINGS/etc. allowed on stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for DATA received on stream 0 (RFC §6.1) |
| 4 | `h2-server-headers-stream-zero` | ← | HEADERS on Stream 0 — server sends HEADERS on connection stream; only valid on non-zero streams | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for HEADERS on stream 0 (RFC §6.2) |
| 5 | `h2-server-ping-nonzero-stream` | ← | PING on Non-Zero Stream — server sends PING on stream 1; RFC §6.7 requires stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for PING received on non-zero stream (RFC §6.7) |
| 6 | `h2-server-goaway-nonzero-stream` | ← | GOAWAY on Non-Zero Stream — server sends GOAWAY on stream 1; RFC §6.8 requires stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for GOAWAY on non-zero stream (RFC §6.8) |
| 7 | `h2-server-push-promise-odd-stream` | ← | PUSH_PROMISE with Odd Promised Stream ID — server promises stream 1 (odd); RFC §6.6 requires even server-initiated IDs | DROPPED | ✅ if rejected; ❌ if accepted. Client must reject PUSH_PROMISE with odd promised stream ID (RFC §6.6 — server streams must be even) |
| 8 | `h2-server-continuation-no-headers` | ← | Stray CONTINUATION — server sends CONTINUATION without a preceding HEADERS without END_HEADERS (RFC §6.10) | DROPPED | ✅ if rejected; ❌ if accepted. Client must treat unexpected CONTINUATION as PROTOCOL_ERROR (RFC §6.10) |
| 9 | `h2-server-unknown-frames` | ← | Unknown Frame Types from Server — sends frames with undefined types (0x0B, 0x42, 0xFF); RFC §4.1 requires clients to ignore them | PASSED | ✅ if accepted; ⚠️ if rejected. RFC §4.1 — unknown frame types MUST be ignored; client must keep the connection open |

### AL: HTTP/2 Server Header Violations

> 🟡 medium · 11 tests · 10 Server → Client, 1 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-server-uppercase-header` | ← | Uppercase Header Name — server response contains "X-Custom" (uppercase); HTTP/2 requires all header names to be lowercase | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.6 — header names must be lowercase; uppercase names are a PROTOCOL_ERROR |
| 2 | `h2-server-connection-header` | ← | Connection Header in Response — server sends "Connection: keep-alive"; connection-specific headers are forbidden in HTTP/2 | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — Connection header is connection-specific and forbidden in HTTP/2 |
| 3 | `h2-server-transfer-encoding` | ← | Transfer-Encoding in Response — server sends "Transfer-Encoding: chunked"; forbidden in HTTP/2 (§8.1.2.2) | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — Transfer-Encoding must not be used in HTTP/2; PROTOCOL_ERROR |
| 4 | `h2-server-multiple-status` | ← | Multiple :status Pseudo-Headers — server sends ":status 200" then ":status 404" in one HEADERS frame | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.4 — responses must contain exactly one :status pseudo-header; duplicates are PROTOCOL_ERROR |
| 5 | `h2-server-pseudo-after-regular` | ← | Pseudo-Header After Regular Header — server sends a regular header before :status in the response | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.1 — pseudo-headers must precede all regular header fields; violation is PROTOCOL_ERROR |
| 6 | `h2-server-request-pseudoheaders` | ← | Request Pseudo-Headers in Response — server sends :method GET and :path / in a response HEADERS frame | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.4 — :method, :path, :scheme are request-only; using them in a response is PROTOCOL_ERROR |
| 7 | `h2-server-te-non-trailers` | ← | TE: chunked in Response — server sends "TE: chunked"; HTTP/2 only allows "TE: trailers" (RFC §8.1.2.2) | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — TE header must not be present unless value is exactly "trailers"; PROTOCOL_ERROR |
| 8 | `h2-server-empty-status` | ← | Empty :status Value — server sends :status with an empty string instead of a 3-digit code | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.4 — :status must contain a valid 3-digit HTTP status code; empty value is PROTOCOL_ERROR |
| 9 | `h2-server-keep-alive-header` | ← | Keep-Alive Header in Response — server sends "Keep-Alive: timeout=5"; connection-specific header forbidden in HTTP/2 | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — Keep-Alive is a connection-specific header forbidden in HTTP/2; PROTOCOL_ERROR |
| 10 | `well-behaved-h2-server` | ← | Compliant HTTP/2 server — used to interact with a fuzzed client | PASSED | ✅ if accepted; ⚠️ if rejected. Protocol violation in category AL: Unknown |
| 11 | `well-behaved-h2-client` | → | Compliant HTTP/2 client — used to interact with a fuzzed server | PASSED | ✅ if accepted; ⚠️ if rejected. Protocol violation in category AL: Unknown |

---

## QUIC Scenarios

### QA: QUIC Handshake & Connection Initial

> 🟠 high · 7 tests · 7 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-0-rtt-fuzz` | → | 0-RTT Early Data packet with random payload to probe server replay handling | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject unauthenticated 0-RTT data |
| 2 | `quic-pqc-keyshare` | → | QUIC Initial with ML-KEM (Kyber-768) sized CRYPTO frame to test PQC handling | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject unrecognized PQC key share or malformed ClientHello |
| 3 | `quic-packet-coalescing` | → | Two QUIC Initial packets coalesced into a single UDP datagram | DROPPED | ✅ if rejected; ❌ if accepted. Server should handle or reject coalesced packets with mismatched CIDs |
| 4 | `quic-handshake-initial` | → | Basic QUIC Initial packet with random payload | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject random/malformed Initial packet |
| 5 | `quic-version-negotiation` | → | QUIC Version Negotiation trigger — sends version 0 | DROPPED | ✅ if rejected; ❌ if accepted. Server should respond with supported versions or close |
| 6 | `quic-retry-token-fuzz` | → | QUIC Retry packet with random token and tag | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QA: Unknown |
| 7 | `well-behaved-quic-client` | → | Compliant QUIC client handshake baseline | PASSED | ✅ if accepted; ⚠️ if rejected. Protocol violation in category QA: Unknown |

### QB: QUIC Transport Parameters & ALPN

> 🟡 medium · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-transport-params-corrupt` | → | QUIC Handshake packet with corrupted transport parameters | DROPPED | ✅ if rejected; ❌ if accepted. TRANSPORT_PARAMETER_ERROR expected for malformed parameters |
| 2 | `quic-alpn-sni-fuzz` | → | QUIC Initial with oversized ALPN in TLS extensions | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QB: Unknown |

### QC: QUIC Resource Exhaustion & DoS

> 🔴 critical · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-crypto-buffer-gaps` | → | QUIC CRYPTO frame with huge offset to test buffer gap handling | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QC: Unknown |
| 2 | `quic-dos-amplification-padding` | → | QUIC Initial with excessive padding to test amplification limits | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QC: Unknown |

### QD: QUIC Flow Control & Stream Errors

> 🟡 medium · 6 tests · 2 Client → Server, 4 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-ack-range-fuzz` | → | QUIC ACK frame with invalid largest acknowledged and multiple blocks | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QD: Unknown |
| 2 | `quic-stream-overlap` | → | Multiple STREAM frames with overlapping offsets | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QD: Unknown |
| 3 | `quic-stream-reset` | ← | RESET_STREAM frame with 0xdeadbeef error code targeting a random stream | DROPPED | ✅ if rejected; ❌ if accepted. Peer should emit STREAM_STATE_ERROR or silently drop |
| 4 | `quic-stop-sending` | ← | STOP_SENDING frame with garbage error code to abort stream mid-transfer | DROPPED | ✅ if rejected; ❌ if accepted. Peer should respond with RESET_STREAM or ignore unknown stream |
| 5 | `quic-connection-close` | ← | CONNECTION_CLOSE with corrupted UTF-8 in reason phrase | DROPPED | ✅ if rejected; ❌ if accepted. Peer should handle invalid reason phrase without crashing |
| 6 | `quic-flow-control` | ← | MAX_DATA and MAX_STREAM_DATA frames with zero-window to exhaust flow control | DROPPED | ✅ if rejected; ❌ if accepted. Peer should detect FLOW_CONTROL_ERROR or stall gracefully |

### QE: QUIC Connection Migration & Path

> 🟡 medium · 2 tests · 1 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-path-validation-fuzz` | → | Spamming PATH_CHALLENGE and PATH_RESPONSE frames | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QE: Unknown |
| 2 | `quic-cid-migration` | ← | PATH_CHALLENGE frame to trigger CID migration probing | DROPPED | ✅ if rejected; ❌ if accepted. Peer should respond with PATH_RESPONSE or ignore unsolicited challenge |

### QF: QUIC Frame Structure & Mutation

> 🔵 low · 3 tests · 1 Client → Server, 2 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-undefined-frames` | → | QUIC packet containing undefined frame types (0x40-0xff) | DROPPED | ✅ if rejected; ❌ if accepted. Protocol violation in category QF: Unknown |
| 2 | `quic-middlebox-evasion` | ← | GREASE version number in long header to probe middlebox and firewall behavior | DROPPED | ✅ if rejected; ❌ if accepted. Middleboxes and servers should drop unrecognized QUIC versions |
| 3 | `quic-random-payload` | ← | Short-header packet with entirely random payload bytes | DROPPED | ✅ if rejected; ❌ if accepted. Server should silently discard undecryptable short-header packets |

### QL: QUIC Server-to-Client Attacks

> 🟠 high · 11 tests · 11 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-server-retry-flood` | ← | Flood client with 50 Retry packets to overwhelm retry logic | DROPPED | ✅ if rejected; ❌ if accepted. Client should limit Retry processing and detect flood |
| 2 | `quic-server-version-negotiation-invalid` | ← | Version Negotiation listing only invalid/unknown versions | DROPPED | ✅ if rejected; ❌ if accepted. Client should abort when no supported version is offered |
| 3 | `quic-server-initial-flood` | ← | Flood client with Initial packets containing garbage ServerHello | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject malformed ServerHello in CRYPTO frame |
| 4 | `quic-server-handshake-invalid-cert` | ← | Handshake packet with corrupt certificate data in CRYPTO frame | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject malformed certificate and close connection |
| 5 | `quic-server-connection-close-abuse` | ← | Rapid CONNECTION_CLOSE frames with misleading error codes | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle rapid CONNECTION_CLOSE without crashing |
| 6 | `quic-server-stateless-reset-flood` | ← | Flood with packets resembling Stateless Reset tokens | DROPPED | ✅ if rejected; ❌ if accepted. Client should validate Stateless Reset tokens and not crash on flood |
| 7 | `quic-server-malformed-transport-params` | ← | Initial response with corrupt transport parameters in CRYPTO frame | DROPPED | ✅ if rejected; ❌ if accepted. Client should detect TRANSPORT_PARAMETER_ERROR and close |
| 8 | `quic-server-amplification-exploit` | ← | Response exceeding 3x client Initial size (violates anti-amplification) | DROPPED | ✅ if rejected; ❌ if accepted. Client should detect server violating anti-amplification limit |
| 9 | `quic-server-zero-length-cid` | ← | Response packets with zero-length connection IDs | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle zero-length CIDs per RFC 9000 or reject gracefully |
| 10 | `quic-server-path-challenge-flood` | ← | Flood PATH_CHALLENGE frames to exhaust client resources | DROPPED | ✅ if rejected; ❌ if accepted. Client should rate-limit PATH_RESPONSE and not exhaust resources |
| 11 | `well-behaved-quic-server` | ← | Compliant QUIC server handshake baseline | PASSED | ✅ if accepted; ⚠️ if rejected. Protocol violation in category QL: Unknown |

---

## QUIC Scan Scenarios

### QSCAN: QUIC Compatibility Scanning

> ⚪ info · 46 tests · 46 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `qscan-quicv1-tls-aes-128-gcm-sha256-x25519` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `qscan-quicv1-tls-aes-128-gcm-sha256-p-256` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `qscan-quicv1-tls-aes-128-gcm-sha256-p-384` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `qscan-quicv1-tls-aes-128-gcm-sha256-p-521` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `qscan-quicv1-tls-aes-128-gcm-sha256-x25519-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 6 | `qscan-quicv1-tls-aes-128-gcm-sha256-p256-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P256_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 7 | `qscan-quicv1-tls-aes-128-gcm-sha256-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `qscan-quicv1-tls-aes-256-gcm-sha384-x25519` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `qscan-quicv1-tls-aes-256-gcm-sha384-p-256` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 10 | `qscan-quicv1-tls-aes-256-gcm-sha384-p-384` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 11 | `qscan-quicv1-tls-aes-256-gcm-sha384-p-521` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 12 | `qscan-quicv1-tls-aes-256-gcm-sha384-x25519-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 13 | `qscan-quicv1-tls-aes-256-gcm-sha384-p256-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P256_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 14 | `qscan-quicv1-tls-aes-256-gcm-sha384-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 15 | `qscan-quicv1-tls-chacha20-poly1305-sha256-x25519` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 16 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p-256` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 17 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p-384` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 18 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p-521` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 19 | `qscan-quicv1-tls-chacha20-poly1305-sha256-x25519-mlkem768` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 20 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p256-mlkem768` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P256_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 21 | `qscan-quicv1-tls-chacha20-poly1305-sha256-mlkem768` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 22 | `qscan-quicv2-tls-aes-128-gcm-sha256-x25519` | → | QUIC scan: QUICv2 + TLS_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 23 | `qscan-quicv2-tls-aes-128-gcm-sha256-p-256` | → | QUIC scan: QUICv2 + TLS_AES_128_GCM_SHA256 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 24 | `qscan-quicv2-tls-aes-128-gcm-sha256-p-384` | → | QUIC scan: QUICv2 + TLS_AES_128_GCM_SHA256 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 25 | `qscan-quicv2-tls-aes-128-gcm-sha256-p-521` | → | QUIC scan: QUICv2 + TLS_AES_128_GCM_SHA256 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 26 | `qscan-quicv2-tls-aes-128-gcm-sha256-x25519-mlkem768` | → | QUIC scan: QUICv2 + TLS_AES_128_GCM_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 27 | `qscan-quicv2-tls-aes-128-gcm-sha256-p256-mlkem768` | → | QUIC scan: QUICv2 + TLS_AES_128_GCM_SHA256 + P256_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 28 | `qscan-quicv2-tls-aes-128-gcm-sha256-mlkem768` | → | QUIC scan: QUICv2 + TLS_AES_128_GCM_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 29 | `qscan-quicv2-tls-aes-256-gcm-sha384-x25519` | → | QUIC scan: QUICv2 + TLS_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 30 | `qscan-quicv2-tls-aes-256-gcm-sha384-p-256` | → | QUIC scan: QUICv2 + TLS_AES_256_GCM_SHA384 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 31 | `qscan-quicv2-tls-aes-256-gcm-sha384-p-384` | → | QUIC scan: QUICv2 + TLS_AES_256_GCM_SHA384 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 32 | `qscan-quicv2-tls-aes-256-gcm-sha384-p-521` | → | QUIC scan: QUICv2 + TLS_AES_256_GCM_SHA384 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 33 | `qscan-quicv2-tls-aes-256-gcm-sha384-x25519-mlkem768` | → | QUIC scan: QUICv2 + TLS_AES_256_GCM_SHA384 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 34 | `qscan-quicv2-tls-aes-256-gcm-sha384-p256-mlkem768` | → | QUIC scan: QUICv2 + TLS_AES_256_GCM_SHA384 + P256_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 35 | `qscan-quicv2-tls-aes-256-gcm-sha384-mlkem768` | → | QUIC scan: QUICv2 + TLS_AES_256_GCM_SHA384 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 36 | `qscan-quicv2-tls-chacha20-poly1305-sha256-x25519` | → | QUIC scan: QUICv2 + TLS_CHACHA20_POLY1305_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 37 | `qscan-quicv2-tls-chacha20-poly1305-sha256-p-256` | → | QUIC scan: QUICv2 + TLS_CHACHA20_POLY1305_SHA256 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 38 | `qscan-quicv2-tls-chacha20-poly1305-sha256-p-384` | → | QUIC scan: QUICv2 + TLS_CHACHA20_POLY1305_SHA256 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 39 | `qscan-quicv2-tls-chacha20-poly1305-sha256-p-521` | → | QUIC scan: QUICv2 + TLS_CHACHA20_POLY1305_SHA256 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 40 | `qscan-quicv2-tls-chacha20-poly1305-sha256-x25519-mlkem768` | → | QUIC scan: QUICv2 + TLS_CHACHA20_POLY1305_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 41 | `qscan-quicv2-tls-chacha20-poly1305-sha256-p256-mlkem768` | → | QUIC scan: QUICv2 + TLS_CHACHA20_POLY1305_SHA256 + P256_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 42 | `qscan-quicv2-tls-chacha20-poly1305-sha256-mlkem768` | → | QUIC scan: QUICv2 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 43 | `qscan-alpn-h3` | → | QUIC scan: ALPN h3 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 44 | `qscan-alpn-h3-29` | → | QUIC scan: ALPN h3-29 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 45 | `qscan-alpn-h3-32` | → | QUIC scan: ALPN h3-32 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 46 | `qscan-version-negotiation` | → | QUIC scan: Version Negotiation probe — sends unknown version to discover supported versions | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with Version Negotiation listing supported versions |

---

## Raw TCP Scenarios

### RA: TCP SYN Attacks

> 🟠 high · 5 tests · 5 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `syn-flood-100` | → | Send 100 SYN packets with random source ports to test SYN flood resilience | PASSED | ✅ if accepted; ⚠️ if rejected. Target should remain operational under small SYN flood |
| 2 | `syn-flood-1000-spoofed` | → | Send 1000 SYN packets with spoofed random source IPs | PASSED | ✅ if accepted; ⚠️ if rejected. Target should use SYN cookies or equivalent defense |
| 3 | `syn-with-payload` | → | SYN packet carrying TLS ClientHello payload (TCP Fast Open style) | DROPPED | ✅ if rejected; ❌ if accepted. Most stacks should SYN-ACK and buffer or discard the payload |
| 4 | `syn-with-zero-window` | → | SYN with zero advertised window to test resource exhaustion handling | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle zero-window SYN gracefully |
| 5 | `syn-with-large-mss` | → | SYN with maximum sequence number to test wraparound handling | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle sequence number wraparound correctly |

### RB: TCP RST Injection

> 🟠 high · 5 tests · 4 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `rst-with-wrong-seq` | → | Establish connection, then send RST with wrong sequence number | PASSED | ✅ if accepted; ⚠️ if rejected. RFC 5961: RST with out-of-window seq should be ignored |
| 2 | `rst-with-valid-seq` | → | Establish connection, then send RST with valid in-window sequence number | DROPPED | ✅ if rejected; ❌ if accepted. RST with valid seq should reset the connection |
| 3 | `rst-during-handshake` | → | Send RST immediately after receiving SYN-ACK (before completing handshake) | PASSED | ✅ if accepted; ⚠️ if rejected. Target should clean up the half-open connection promptly |
| 4 | `rst-ack-injection` | → | Send RST+ACK with forged acknowledgment number | DROPPED | ✅ if rejected; ❌ if accepted. Target should validate RST against receive window |
| 5 | `server-rst-injection` | ← | Server accepts connection then sends RST with wrong seq to test client behavior | DROPPED | ✅ if rejected; ❌ if accepted. Client should ignore RST with out-of-window seq |

### RC: TCP Sequence/ACK Manipulation

> 🟠 high · 4 tests · 4 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ack-with-future-seq` | → | ACK a sequence number far beyond what server has sent | DROPPED | ✅ if rejected; ❌ if accepted. Target should send a corrective ACK or ignore |
| 2 | `data-with-past-seq` | → | Send ClientHello with sequence number in the past (already ACKed range) | DROPPED | ✅ if rejected; ❌ if accepted. Target should ignore or ACK with correct expected seq |
| 3 | `data-with-future-seq` | → | Send data with sequence number ahead of expected (gap in stream) | DROPPED | ✅ if rejected; ❌ if accepted. Target should buffer out-of-order segment and ACK expected seq |
| 4 | `dup-ack-storm` | → | Send 50 duplicate ACKs to trigger fast retransmit behavior | DROPPED | ✅ if rejected; ❌ if accepted. Target may retransmit after 3 dup ACKs (RFC 5681) |

### RD: TCP Window Attacks

> 🟡 medium · 5 tests · 4 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `zero-window-then-update` | → | Advertise zero window during handshake, then send window update | DROPPED | ✅ if rejected; ❌ if accepted. Target should resume sending after window opens |
| 2 | `window-shrink` | → | Shrink the window to 1 byte after connection is established | DROPPED | ✅ if rejected; ❌ if accepted. Target should respect small window and segment accordingly |
| 3 | `window-oscillation` | → | Rapidly oscillate window between 0 and 65535 (Sockstress variant) | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle rapid window changes without resource leak |
| 4 | `zero-window-probe-flood` | → | Send ClientHello, then flood server with 20 zero-window probes to test persist timer | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle persist timer and zero-window probes per RFC 9293 |
| 5 | `server-window-zero` | ← | Server advertises zero window to test client persist timer behavior | DROPPED | ✅ if rejected; ❌ if accepted. Client should use persist timer and resume when window opens |

### RE: TCP Segment Reordering & Overlap

> 🟡 medium · 6 tests · 6 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `overlapping-segments-conflicting` | → | Send overlapping TCP segments with conflicting data in the overlap region | DROPPED | ✅ if rejected; ❌ if accepted. Target should reassemble consistently (first or last wins, but consistent) |
| 2 | `reverse-order-segments` | → | Send TLS ClientHello split into 4 segments delivered in reverse order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble out-of-order segments correctly |
| 3 | `random-order-segments` | → | Send TLS ClientHello split into 6 segments delivered in random order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble randomly ordered segments |
| 4 | `interleaved-segments` | → | Send segments in interleaved order (even offsets first, then odd) | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble interleaved segments |
| 5 | `client-hello-random-drops` | → | Send ClientHello in 15 segments but randomly drop 3 of them | DROPPED | ✅ if rejected; ❌ if accepted. Target should retransmit missing segments or time out the connection |
| 6 | `oversized-client-hello-massive-reorder` | → | Send a 6KB padded ClientHello in 20 segments with random delivery order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should correctly reassemble large out-of-order handshake records |

### RF: TCP Urgent Pointer Attacks

> 🔵 low · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `urgent-pointer-past-data` | → | Set URG flag with urgent pointer beyond payload length | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle invalid urgent pointer gracefully |
| 2 | `urgent-pointer-zero` | → | Set URG flag with zero urgent pointer | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle URG with zero pointer |
| 3 | `urg-without-data` | → | Send URG flag on an empty segment (no payload) | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle URG with no data gracefully |

### RG: TCP State Machine Fuzzing

> 🟠 high · 7 tests · 7 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `data-before-handshake` | → | Send application data without completing TCP handshake | DROPPED | ✅ if rejected; ❌ if accepted. Target should RST or ignore data without established connection |
| 2 | `fin-before-handshake` | → | Send FIN without ever completing TCP handshake | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle unexpected FIN in SYN_RCVD state |
| 3 | `simultaneous-open` | → | Simulate TCP simultaneous open by sending SYN to a listening port | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle simultaneous open per RFC 793 |
| 4 | `ack-before-syn` | → | Send ACK to a listening port without prior SYN (ACK scan) | DROPPED | ✅ if rejected; ❌ if accepted. Target should RST in response to unsolicited ACK |
| 5 | `double-syn` | → | Send two SYN packets with different sequence numbers before completing handshake | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle duplicate SYN (RFC 793 §3.4) |
| 6 | `xmas-tree-packet` | → | Send a Christmas tree packet (all flags set: SYN\|FIN\|RST\|PSH\|ACK\|URG) | DROPPED | ✅ if rejected; ❌ if accepted. Target should reject or RST — invalid flag combination |
| 7 | `null-packet` | → | Send a TCP packet with no flags set (NULL scan) | DROPPED | ✅ if rejected; ❌ if accepted. Open port should drop; closed port should RST (RFC 793) |

### RH: TCP Option Fuzzing (TLS)

> 🟡 medium · 15 tests · 13 Client → Server, 2 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ts-negotiated-then-dropped` | → | Negotiate TCP timestamps in SYN, then send TLS ClientHello without timestamps | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject or reset when timestamps disappear after negotiation (RFC 7323 §3.2) |
| 2 | `ts-negotiated-then-zero-tsval` | → | Negotiate TCP timestamps in SYN, then send TLS data with TSval=0 | DROPPED | ✅ if rejected; ❌ if accepted. TSval of 0 after negotiating timestamps should be treated as invalid (RFC 7323 §5.5) |
| 3 | `ts-negotiated-then-backwards` | → | Negotiate TCP timestamps, then send TLS data with TSval going backwards | DROPPED | ✅ if rejected; ❌ if accepted. PAWS (Protection Against Wrapped Sequences) should reject segments with old timestamps (RFC 7323 §5.5) |
| 4 | `ts-not-negotiated-then-injected` | → | SYN without timestamps, then inject timestamps on TLS data segments | PASSED | ✅ if accepted; ⚠️ if rejected. Unexpected timestamps on data should be silently ignored per RFC 7323 §3.2 |
| 5 | `mss-negotiated-then-exceeded` | → | Negotiate small MSS in SYN, then send TLS ClientHello exceeding it | PASSED | ✅ if accepted; ⚠️ if rejected. MSS is advisory for sender; receiver should accept oversized segments (RFC 9293 §3.7.1) |
| 6 | `mss-zero` | → | Negotiate MSS=0 in SYN, then send TLS ClientHello | DROPPED | ✅ if rejected; ❌ if accepted. MSS=0 is invalid and should cause connection rejection |
| 7 | `sack-negotiated-then-bogus-sack-blocks` | → | Negotiate SACK in SYN, then send TLS data with bogus SACK option blocks | PASSED | ✅ if accepted; ⚠️ if rejected. Bogus SACK blocks from client should be ignored by server (RFC 2018 §4) |
| 8 | `ws-negotiated-then-oversized-window` | → | Negotiate window scale in SYN, then advertise impossibly large window on TLS data | PASSED | ✅ if accepted; ⚠️ if rejected. Large scaled windows are valid; server should process normally (RFC 7323 §2.3) |
| 9 | `ts-negotiated-tls-fragmented-different-ts` | → | Negotiate timestamps, then send TLS ClientHello in 2 segments with different TSvals | DROPPED | ✅ if rejected; ❌ if accepted. Second fragment has TSval going backwards — PAWS should reject it (RFC 7323 §5.5) |
| 10 | `unknown-tcp-options-with-tls` | → | Send TLS ClientHello with unknown/experimental TCP options | PASSED | ✅ if accepted; ⚠️ if rejected. Unknown TCP options should be silently ignored (RFC 9293 §3.1) |
| 11 | `ts-negotiated-then-huge-jump` | → | Negotiate timestamps then jump TSval forward by ~2^31 (near wraparound) | DROPPED | ✅ if rejected; ❌ if accepted. PAWS treats TSval jumps near 2^31 as going backwards due to signed comparison (RFC 7323 §5.5) |
| 12 | `malformed-tcp-option-length-with-tls` | → | Send TLS ClientHello with malformed TCP option (length exceeds packet) | DROPPED | ✅ if rejected; ❌ if accepted. Malformed TCP option with invalid length should cause segment rejection |
| 13 | `ts-negotiated-tls-data-then-no-ts` | → | Full TLS handshake start with timestamps, then drop timestamps mid-stream | DROPPED | ✅ if rejected; ❌ if accepted. Dropping timestamps after negotiation violates RFC 7323 — server should reject subsequent segments |
| 14 | `server-ts-static` | ← | Server sends the exact same TCP timestamp (TSval) in every packet after negotiation | DROPPED | ✅ if rejected; ❌ if accepted. Stagnant timestamps for new data may be tolerated or cause issues depending on client clock resolution |
| 15 | `server-ts-backwards` | ← | Server sends a valid timestamp, then a subsequent packet with an older timestamp | DROPPED | ✅ if rejected; ❌ if accepted. Client PAWS (RFC 7323) should drop the packet with the older timestamp |

### RX: Advanced TLS/H2 TCP Fuzzing

> 🟠 high · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `tls-client-hello-overlapping-tcp` | → | Send TLS ClientHello in overlapping TCP segments | PASSED | ✅ if accepted; ⚠️ if rejected. Target should correctly reassemble overlapping TCP segments |
| 2 | `h2-preface-out-of-order` | → | Send H2 connection preface in reverse TCP order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble out-of-order TCP segments before H2 parsing |
| 3 | `tls-handshake-zero-window-stall` | → | Send ClientHello, receive response, then advertise zero window and stall | PASSED | ✅ if accepted; ⚠️ if rejected. Target should handle zero-window stall during handshake gracefully |

---

*Generated from scenario definitions on 2026-03-16. 754 scenarios across 6 protocols.*