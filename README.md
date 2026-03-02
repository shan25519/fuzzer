# TLS/TCP Protocol Fuzzer

A protocol-level fuzzer that tests middlebox, firewall, and TLS/HTTP/QUIC implementation behavior by sending crafted packets over raw TCP and UDP. No actual TLS encryption is performed — every byte of every handshake message is constructed manually, giving full control over protocol violations, malformations, and edge cases.

**528 fuzzing scenarios** across **49 categories** covering TLS handshakes, HTTP/2 frames, QUIC packets, certificate fuzzing, CVE detection, and more.

| Protocol | Categories | Scenarios |
|----------|------------|-----------|
| TLS/TCP  | 26 (A–Z)  | 435       |
| HTTP/2   | 12 (AA–AL)| 71        |
| QUIC     | 11 (QA–QK)| 22        |

---

## Requirements

- **Node.js** 18 or later
- **Electron** 33+ (only needed for the GUI — CLI works without it)

```bash
git clone <repo-url>
cd fuzzer
npm install
```

---

## Quick Start

### Fuzz a remote server (client mode)

```bash
node client.js example.com 443 --scenario all
```

### Run a fuzzed server (server mode)

```bash
node server.js 4433 --hostname evil.test --scenario all --verbose
```

### Launch the GUI

```bash
npm start
```

---

## CLI Reference

### `node client.js <host> <port> [options]`

| Option | Description | Default |
|--------|-------------|---------|
| `--scenario <name\|all>` | Run a specific scenario or all client scenarios | required |
| `--category <A-Z\|AA-AL\|QA-QK>` | Run all client scenarios in a category | — |
| `--delay <ms>` | Delay between actions | 100 |
| `--timeout <ms>` | Connection timeout | 5000 |
| `--verbose` | Show hex dumps of all packets | off |
| `--json` | Output results as NDJSON | off |
| `--pcap <file>` | Record packets to PCAP file | — |
| `--agent` | Run as a distributed agent (starts HTTP control server) | off |
| `--control-port <port>` | Agent management port | 9100 |
| `--token <string>` | Bearer token for agent authentication | — |

### `node server.js <port> [options]`

| Option | Description | Default |
|--------|-------------|---------|
| `--scenario <name\|all>` | Run a specific scenario or all server scenarios | required |
| `--category <A-Z\|AA-AL\|QA-QK>` | Run all server scenarios in a category | — |
| `--hostname <name>` | Certificate CN and SAN | localhost |
| `--delay <ms>` | Delay between actions | 100 |
| `--timeout <ms>` | Connection timeout | 10000 |
| `--verbose` | Show hex dumps of all packets | off |
| `--json` | Output results as NDJSON | off |
| `--pcap <file>` | Record packets to PCAP file | — |
| `--agent` | Run as a distributed agent (starts HTTP control server) | off |
| `--control-port <port>` | Agent management port | 9101 |
| `--token <string>` | Bearer token for agent authentication | — |

### `node cli.js <command> [options]`

Unified CLI with both modes:

```bash
node cli.js list                                          # List all scenarios
node cli.js client <host> <port> --scenario all           # Client mode
node cli.js server <port> --hostname x --scenario all     # Server mode
```

---

## Verbose Mode

The `--verbose` flag enables detailed hex dumps of every packet sent and received. This is useful for debugging protocol behavior and understanding exactly what bytes are on the wire.

**What it shows:**

- Color-coded packet direction (cyan = sent, yellow = received)
- Timestamps with millisecond precision
- Full hex dump (16 bytes per line with ASCII sidebar)
- Protocol annotations (TLS record type, handshake message type, alert descriptions)
- TCP events (FIN, RST, connection close)
- Health probe results

```bash
# Client with verbose output
node client.js example.com 443 --scenario all --verbose

# Server with verbose output
node server.js 4433 --hostname evil.test --category W --verbose
```

Verbose mode also works in distributed mode — agent event streams include packet-level data that the GUI displays in the Packet Log tab.

Can be combined with `--json` for machine-readable verbose output, or `--pcap` to capture traffic for Wireshark analysis.

---

## Distributed Mode

Distributed mode lets you orchestrate fuzzing across multiple machines from a central controller (the Electron GUI). Remote agents run on separate hosts and communicate back to the controller via HTTP.

### Architecture

```
  Controller (Electron UI)
       |
       +--- HTTP control ---+
       |                    |
  Client Agent          Server Agent
  (port 9100)           (port 9101)
       |                    |
       +--- test traffic ---+
            (TLS/HTTP2/QUIC)
```

Two separate communication channels:

- **Management (control):** HTTP between controller and agents for configuration, commands, and event streaming.
- **Datapath (test traffic):** The actual fuzzed protocol traffic between the client agent and its target, or between external clients and the server agent.

### Starting Agents Manually

On each remote machine, start an agent process:

```bash
# Client agent on machine A
node client.js --agent --control-port 9100 --token secret123

# Server agent on machine B
node server.js --agent --control-port 9101 --token secret123
```

The `--token` flag is optional but recommended. When set, all API requests require an `Authorization: Bearer <token>` header.

### Using the GUI

1. Enable the **Distributed** checkbox in the toolbar.
2. Click the gear icon next to each agent to open the configuration modal.
3. Fill in:
   - **Management:** Agent host/IP, port (9100/9101), and optional auth token.
   - **Datapath:** Target IP and port for test traffic (e.g., the server to fuzz).
4. Click **CONNECT** to verify both agents are reachable.
5. Select scenarios and click **RUN SELECTED**.
6. Monitor results in real-time as events stream back from both agents.

### Agent REST API

Agents expose an HTTP API on their control port:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Agent role, state, scenario count |
| `/configure` | POST | Push scenarios and config |
| `/run` | POST | Start fuzzing |
| `/stop` | POST | Abort fuzzing |
| `/events` | GET | NDJSON event stream (real-time) |
| `/results` | GET | Fetch final results and report |

### SSH Auto-Deployment

Instead of manually starting agents, the GUI can deploy and start them over SSH. The deployment uses `sudo` for privileged operations, automatically detects and installs missing dependencies, and produces a detailed readiness report.

1. In the agent configuration modal, enable **Auto-Deploy**.
2. Enter the **SSH User** and **Remote Path** (e.g., `/opt/fuzzer`).
3. Click **COMMIT & DEPLOY**.

The SSH user should have passwordless `sudo` access on the remote machine for package installation and privileged directory creation.

**Deployment steps performed:**

| Step | Uses sudo | Description |
|------|-----------|-------------|
| SSH connectivity | no | Verify the remote host is reachable |
| OS detection | no | Detect Linux distro and package manager (apt/dnf/yum/apk/brew) |
| Node.js check | yes | Check for Node.js 18+; if missing or outdated, install via NodeSource + package manager |
| npm check | yes | Check for npm; install if missing |
| Create directory | yes | `sudo mkdir -p` + `chown` to handle privileged paths like `/opt/` |
| Copy files | no | SCP client.js, server.js, cli.js, package.json, lib/ to remote |
| Install dependencies | no | `npm install --production` on the remote host |
| Stop old agent | yes | `sudo pkill` any previously running agent process |
| Firewall port | yes | Best-effort: open the control port via `ufw` or `firewalld` (skipped if neither is present) |
| Start agent | no | Launch the agent with `nohup` in the background |
| Agent readiness | no | Poll the HTTP `/status` endpoint until the agent responds (up to 30s) |

**Deployment report:** Each step's result (OK, INSTALLED, SKIPPED, WARNING, FAILED) is logged to the Packet Log tab in the GUI, giving a full picture of what was checked, what was installed, and the final readiness state.

---

## Firewall / DUT Monitoring

The GUI integrates with Palo Alto Networks PAN-OS firewalls for testing middlebox behavior during fuzzing.

### Setup

1. Enable the **DUT** checkbox in the toolbar.
2. Enter the firewall management IP and authentication credentials (username/password or API key).
3. Click **MONITOR** to open a dedicated firewall monitoring window.

### Features

- Real-time session, threat, and traffic log monitoring
- System info display (model, OS version, serial number)
- Operational command execution against the PAN-OS API
- Auto-clears previous output when running a new command
- Automatically closes when the main window closes

This lets you observe how the firewall reacts to each fuzzing scenario — whether it blocks, alerts, passes through, or crashes.

---

## Running Client and Server on Different Hosts

The fuzzer separates cleanly into two standalone components that can run on different machines. The **server** acts as a malicious TLS endpoint (with a baked-in self-signed certificate) and the **client** sends crafted TLS messages to a target.

### Use Case 1: Test how a client/middlebox handles malicious server responses

```
  Host A (Attacker)                    Host B (Target)
  ┌──────────────────┐                ┌──────────────────┐
  │  node server.js  │◄──── TCP ─────│  client app /    │
  │  port 4433       │                │  middlebox /     │
  │  (fuzzed server) │────── TLS ────►│  browser         │
  └──────────────────┘  malformed     └──────────────────┘
                        responses
```

**Host A** (fuzzer server):

```bash
node server.js 4433 --hostname target.example.com --scenario all --verbose
```

**Host B** (target):

```bash
openssl s_client -connect <host-a-ip>:4433
```

Each connection triggers the next scenario in the queue.

### Use Case 2: Test how a server handles malicious client messages

```
  Host A (Attacker)                    Host B (Target)
  ┌──────────────────┐                ┌──────────────────┐
  │  node client.js  │────── TCP ────►│  TLS server      │
  │  (fuzzed client) │                │  (nginx, etc.)   │
  │                  │◄──── TLS ─────│                  │
  └──────────────────┘  responses     └──────────────────┘
```

```bash
node client.js <host-b-ip> 443 --scenario all
```

### Use Case 3: Test a middlebox (IDS/WAF/proxy)

Run the fuzzer on both sides with the middlebox in the path:

```
  Host A                Middlebox              Host B
  ┌────────────┐      ┌────────────┐      ┌────────────┐
  │ client.js  │─────►│  IDS/WAF/  │─────►│ server.js  │
  │            │◄─────│  Proxy     │◄─────│            │
  └────────────┘      └────────────┘      └────────────┘
```

```bash
# Host B
node server.js 4433 --hostname test.internal --category B --verbose

# Host A
node client.js <middlebox-ip> 4433 --scenario all --verbose
```

---

## Fuzzing Categories

### TLS/TCP (A–Z)

| Cat | Name | Side | Scenarios | Severity |
|-----|------|------|-----------|----------|
| A | Handshake Order Violations (Client) | client | 5 | high |
| B | Handshake Order Violations (Server) | server | 5 | high |
| C | Parameter Mutation | mixed | 6 | medium |
| D | Alert Injection | client | 6 | medium |
| E | TCP Manipulation | mixed | 7 | low |
| F | Record Layer Attacks | client | 6 | high |
| G | ChangeCipherSpec Attacks | client | 4 | high |
| H | Extension Fuzzing | client | 8 | medium |
| I | Known CVE Detection | client | 5 | critical |
| J | Post-Quantum Cryptography | client | 3 | low |
| K | SNI Evasion & Fragmentation | client | 6 | medium |
| L | ALPN Protocol Confusion | mixed | 5 | medium |
| M | Extension Malformation | client | 8 | medium |
| N | Parameter Reneging | client | 8 | high |
| O | TLS 1.3 Early Data & 0-RTT | client | 5 | high |
| P | Advanced Handshake Record Fuzzing | client | 13 | high |
| Q | ClientHello Field Mutations | client | 12 | medium |
| R | Extension Inner Structure | client | 14 | medium |
| S | Record Layer Byte Attacks | client | 8 | medium |
| T | Alert & CCS Byte-Level | client | 10 | medium |
| U | Handshake Type & Legacy Protocol | client | 10 | medium |
| V | Cipher Suite & Signature Algorithm | client | 11 | medium |
| W | Server Certificate X.509 Fuzzing | server | 15 | medium |
| X | Client Certificate Abuse | client | 12 | medium |
| Y | Certificate Chain & Message Structure | server | 8 | medium |
| Z | TLS Application Layer — Large POST | client | 1 | low |

Categories **W** and **Y** are **opt-in** — they require server mode and are skipped by `--scenario all`. Use `--category W` or `--category Y` to run them explicitly.

### HTTP/2 (AA–AL)

| Cat | Name | Scenarios | Severity |
|-----|------|-----------|----------|
| AA | CVE & Rapid Attack | — | critical |
| AB | Flood / Resource Exhaustion | — | high |
| AC | Stream & Flow Control Violations | — | high |
| AD | Frame Structure & Header Attacks | — | medium |
| AE | Stream Abuse Extensions | — | high |
| AF | Extended Frame Attacks | — | medium |
| AG | Flow Control Attacks | — | high |
| AH | Connectivity & TLS Probes | — | info |
| AI | General Frame Mutation | — | low |
| AJ | Server-to-Client Attacks | — | high |
| AK | Server Protocol Violations | — | high |
| AL | Server Header Violations | — | medium |

### QUIC (QA–QK)

| Cat | Name | Scenarios | Severity |
|-----|------|-----------|----------|
| QA | Handshake & Connection Initial | — | high |
| QB | Transport Parameters & ALPN | — | medium |
| QC | Resource Exhaustion & DoS | — | critical |
| QD | Flow Control & Stream Errors | — | medium |
| QE | Connection Migration & Path | — | medium |
| QF | Frame Structure & Mutation | — | low |
| QG | QUIC-TLS Handshake Order & State | — | high |
| QH | QUIC-TLS Parameter & Extension | — | medium |
| QI | QUIC-TLS Record & Alert | — | high |
| QJ | QUIC-TLS Known CVEs & PQC | — | critical |
| QK | QUIC-TLS Certificate Fuzzing | — | medium |

---

## Output and Grading

Each scenario produces a result:

| Status | Meaning |
|--------|---------|
| **DROPPED** | Server/client closed or reset the connection |
| **PASSED** | Server/client accepted the fuzzed message |
| **TIMEOUT** | No response within timeout period |
| **ERROR** | Connection or execution error |

Results are compared against expected outcomes to produce a verdict (**AS EXPECTED** or **UNEXPECTED**) and an overall grade from **A** (all tests passed) to **F** (critical failures).

### Health Probing

After each scenario the fuzzer runs health checks against the target:

- **TCP probe:** Can the host still accept connections?
- **HTTPS probe:** Is the service responding normally? (captures TLS version, cipher suite, latency)

If a previously healthy service becomes unreachable, the scenario is flagged as **UNEXPECTED** — indicating a potential crash or denial of service.

### PCAP Capture

The `--pcap` flag records all traffic to a PCAP file for analysis in Wireshark:

```bash
node client.js target.com 443 --scenario all --pcap capture.pcap
```

### JSON Output

The `--json` flag produces machine-readable NDJSON output, suitable for CI/CD pipelines or scripted analysis:

```bash
node client.js target.com 443 --scenario all --json | jq '.status'
```

### Loop Count (GUI)

The GUI supports running the selected scenario set 1–1000 times to detect flaky behavior and intermittent crashes.

---

## Server Certificate

When running in server mode, the fuzzer automatically generates a self-signed RSA 2048-bit certificate at startup:

- **Subject CN**: set via `--hostname` (default: `localhost`)
- **SAN**: dNSName matching the hostname
- **Validity**: 2024-01-01 to 2035-01-01
- **Signature**: SHA256withRSA (properly signed)
- **Issuer**: "TLS Fuzzer CA"

The SHA256 fingerprint is displayed on startup. Category W scenarios replace this certificate with specifically malformed variants (expired, wrong CN, null bytes, etc.) to test certificate validation.

---

## Notable Scenario Highlights

**CVE detection** (categories I, AA, QJ):
- Heartbleed (CVE-2014-0160)
- FREAK (CVE-2015-0204)
- Logjam (CVE-2015-4000)
- HTTP/2 Rapid Reset (CVE-2023-44487)
- HPACK Bomb (CVE-2019-9516)

**Post-quantum cryptography** (categories J, QH, QJ):
- ML-KEM (Kyber-768) key shares (FIPS 203)
- X25519-MLKEM768 hybrid groups

**HTTP/2 attacks** (categories AA–AL):
- Rapid Reset floods
- CONTINUATION floods
- SETTINGS floods
- Stream limit bypass
- Flow control violations
- HPACK dynamic table exhaustion

**QUIC attacks** (categories QA–QK):
- 0-RTT early data fuzzing
- Packet coalescing attacks
- Connection migration abuse
- Transport parameter mutations

---

## Examples

```bash
# Fuzz a TLS server with all client scenarios
node client.js google.com 443 --scenario all

# Verbose output with PCAP capture
node client.js example.com 443 --scenario all --verbose --pcap capture.pcap

# Test certificate validation on a middlebox
node server.js 4433 --hostname evil.test --category W --verbose

# Run a specific CVE detection scenario
node client.js target.com 443 --scenario heartbleed-test --verbose

# Run HTTP/2 scenarios
node client.js target.com 443 --category AA --verbose

# Run QUIC scenarios
node client.js target.com 443 --category QA --verbose

# Start a distributed client agent
node client.js --agent --control-port 9100 --token mytoken

# Start a distributed server agent
node server.js --agent --control-port 9101 --token mytoken

# List all available scenarios
node cli.js list

# JSON output for scripting
node client.js target.com 443 --scenario all --json > results.json
```
