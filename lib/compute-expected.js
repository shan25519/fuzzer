// Auto-compute expected outcome for fuzzing scenarios
//
// Three-layer decision system:
//   Layer 1: Explicit overrides for known PASSED scenarios
//   Layer 2: Action-based heuristics (detects valid TCP behavior patterns)
//   Layer 3: Category default (DROPPED for all violation categories)

const { CATEGORIES } = require('./scenarios');

// Layer 1: Scenarios where valid data is sent in unusual ways — server should accept
const EXPLICIT_PASSED = {
  'record-version-mismatch': 'Record version often differs from body version (common compat behavior)',
  'unknown-extensions': 'Server should ignore unknown extensions per RFC',
  'empty-sni': 'Empty SNI is tolerated by most servers (uses default vhost)',
};

// Layer 3: Category defaults — all default to DROPPED (secure expectation)
const CATEGORY_REASONS = {
  A: 'Must reject handshake order violations (protocol state machine bypass)',
  B: 'Must reject server handshake order violations (state machine bypass)',
  C: 'Must reject parameter mutation (downgrade/mismatch attacks)',
  D: 'Must reject alert injection (protocol confusion)',
  E: 'Must reject TCP manipulation abuse',
  F: 'Must reject record layer violations (fundamental protocol violations)',
  G: 'Must reject CCS attacks (CVE-2014-0224 vector)',
  H: 'Must reject extension fuzzing (parser robustness)',
  I: 'Must reject known vulnerability vectors (CVE detection)',
  J: 'Must reject invalid PQC key material',
  K: 'Must reject SNI evasion and fragmentation attacks',
  L: 'Must reject ALPN protocol confusion',
  M: 'Must reject extension malformation (parser crash/memory corruption)',
  N: 'Must reject parameter reneging (mid-stream downgrade/confusion attacks)',
  O: 'Must reject invalid TLS 1.3 early data and PSK abuse',
  P: 'Must reject advanced handshake record malformation',
  Q: 'Must reject malformed ClientHello fields (length/value corruption)',
  R: 'Must reject malformed extension inner structures (sub-field corruption)',
  S: 'Must reject invalid record layer headers (content type/version/length)',
  T: 'Must reject malformed alert and CCS messages (byte-level corruption)',
  U: 'Must reject invalid handshake types and legacy protocol abuse',
  V: 'Must reject invalid cipher suite and signature algorithm values',
  W: 'Must reject malformed server certificate fields (middlebox evasion)',
  X: 'Must reject unauthorized client certificate abuse',
  Y: 'Must reject malformed certificate chain/message structure',
  // Raw TCP categories (RA–RG)
  RA: 'Must withstand TCP SYN flood attacks without service degradation',
  RB: 'Must reject TCP RST injection with invalid sequence numbers',
  RC: 'Must reject TCP segments with manipulated sequence/ACK numbers',
  RD: 'Must handle TCP window size attacks (zero window, shrinking window)',
  RE: 'Must correctly reassemble or reject reordered/overlapping TCP segments',
  RF: 'Must handle TCP urgent pointer abuse without crashes',
  RG: 'Must enforce TCP state machine transitions and reject invalid states',
  RH: 'Must handle TCP option negotiation violations during TLS sessions (timestamps, MSS, SACK)',
};

/**
 * Analyze scenario actions to detect valid-behavior patterns
 * Returns { isValidBehavior: bool, reason: string } if a pattern is detected
 */
function analyzeActions(scenario) {
  let actions;
  try {
    actions = scenario.actions({ hostname: 'probe.test' });
  } catch (_) {
    return null;
  }

  const types = actions.map(a => a.type);
  const labels = actions.map(a => (a.label || '').toLowerCase());

  const hasSlowDrip = types.includes('slowDrip');
  const hasFragment = types.includes('fragment');
  const hasRST = types.includes('rst');
  const hasFIN = types.includes('fin');

  // Check if fuzz labels indicate violations
  const violationLabels = labels.some(l =>
    l.includes('[cve-') || l.includes('[vuln]') || l.includes('[malform]') ||
    l.includes('[sni-evasion]') || l.includes('[alpn]') || l.includes('[pqc]') ||
    l.includes('garbage') || l.includes('malformed') || l.includes('oversized') ||
    l.includes('duplicate') || l.includes('truncated') || l.includes('corrupted')
  );

  if (violationLabels) return null;

  // Note: TCP reassembly (slowDrip/fragment) and RST-after-exchange patterns
  // are implementation-dependent. Real servers may reassemble correctly (PASSED),
  // but Node.js TLS server may not. Scenarios that should be PASSED must set
  // expected explicitly rather than relying on heuristics.

  return null;
}

/**
 * Compute the expected outcome for a scenario
 * Returns { expected: 'DROPPED'|'PASSED', reason: string }
 */
function computeExpected(scenario) {
  // Layer 1: Explicit overrides
  // Strip variant suffixes (-small-ch, -pqc-ch) to match base scenario names
  const baseName = scenario.name.replace(/-(small|pqc)-ch$/, '');
  const explicitReason = EXPLICIT_PASSED[scenario.name] || EXPLICIT_PASSED[baseName];
  if (explicitReason || scenario.category === 'SCAN' || scenario.category === 'Z') {
    return {
      expected: 'PASSED',
      reason: scenario.category === 'SCAN' ? 'Baseline connectivity scan' : (explicitReason || 'Well-behaved counterpart'),
    };
  }

  // Layer 2: Action-based heuristics
  const heuristic = analyzeActions(scenario);
  if (heuristic) {
    return heuristic;
  }

  // Layer 3: Category default — DROPPED (secure expectation)
  const reason = CATEGORY_REASONS[scenario.category] ||
    `Protocol violation in category ${scenario.category}: ${CATEGORIES[scenario.category] || 'Unknown'}`;
  return {
    expected: 'DROPPED',
    reason,
  };
}

module.exports = { computeExpected, EXPLICIT_PASSED };
