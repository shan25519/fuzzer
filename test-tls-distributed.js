#!/usr/bin/env node
// Test TLS scenarios in distributed mode with 1 worker.
// Batch 1: Key categories (FV, Z well-behaved, FW virus, SB sandbox)
// Batch 2: Core fuzzing (A-Y)
// Batch 3: Scans (SCAN, PAN, PAN-PQC)

const http = require('http');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { getClientScenarios } = require('./lib/scenarios');

const SERVER_PORT = 4435;
const AGENT_PORT = 9252;

function httpPost(port, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ hostname: 'localhost', port, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function httpGet(port, path) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: 'localhost', port, path }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    }).on('error', reject);
  });
}

async function waitForDone(port, total, timeout = 1800000) {
  const start = Date.now();
  let lastCount = -1;
  while (Date.now() - start < timeout) {
    const status = await httpGet(port, '/status');
    if (status.completedCount !== lastCount) {
      const pct = Math.floor((status.completedCount / total) * 100);
      console.log(`  Progress: ${status.completedCount}/${total} (${pct}%)`);
      lastCount = status.completedCount;
    }
    if (status.status === 'done') return;
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error(`Timed out after ${Math.round((Date.now() - start)/1000)}s`);
}

async function runBatch(agentPort, serverPort, scenarioNames) {
  if (scenarioNames.length === 0) return [];
  try { await httpPost(agentPort, '/stop', {}); } catch {}
  await new Promise(r => setTimeout(r, 500));
  const configResult = await httpPost(agentPort, '/configure', {
    config: { host: 'localhost', port: serverPort, protocol: 'tls', workers: 10, timeout: 1000, delay: 10, baseline: false },
    scenarios: scenarioNames,
  });
  if (configResult.scenarioCount === 0) throw new Error('No scenarios resolved');
  await httpPost(agentPort, '/run', {});
  await waitForDone(agentPort, configResult.scenarioCount);
  return await httpGet(agentPort, '/results');
}

async function run() {
  const allScenarios = getClientScenarios();
  const expectedMap = {};
  const categoryMap = {};
  for (const s of allScenarios) {
    expectedMap[s.name] = s.expected || 'DROPPED';
    categoryMap[s.name] = s.category;
  }

  const byCategory = {};
  for (const s of allScenarios) {
    if (!byCategory[s.category]) byCategory[s.category] = [];
    byCategory[s.category].push(s.name);
  }

  console.log(`Total TLS client scenarios: ${allScenarios.length}`);

  const server = new WellBehavedServer({ hostname: 'localhost', port: SERVER_PORT, logger: null });
  await server.startTLS();
  const actualPort = server._actualPort || SERVER_PORT;
  console.log(`Server on port ${actualPort}`);

  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  const allResults = [];

  try {
    // ── Batch 1: FV + Z + FW + SB (key categories) ──
    const keyCats = ['FV', 'Z', 'FW', 'SB'];
    const keyNames = keyCats.flatMap(c => byCategory[c] || []);
    console.log(`\n── BATCH 1: Well-behaved + Virus + Sandbox (${keyNames.length} scenarios) ──`);
    const r1 = await runBatch(AGENT_PORT, actualPort, keyNames);
    allResults.push(...r1);
    console.log(`  Done: ${r1.length} results`);

    // ── Batch 2: Native TLS fuzzing (A-Y) ──
    const nativeCats = ['A','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y'];
    const nativeNames = nativeCats.flatMap(c => byCategory[c] || []);
    console.log(`\n── BATCH 2: Native TLS fuzz categories (${nativeNames.length} scenarios) ──`);
    const r2 = await runBatch(AGENT_PORT, actualPort, nativeNames);
    allResults.push(...r2);
    console.log(`  Done: ${r2.length} results`);

    // ── Batch 3: Scan / PAN / PAN-PQC ──
    const scanCats = ['SCAN', 'PAN', 'PAN-PQC'];
    const scanNames = scanCats.flatMap(c => byCategory[c] || []);
    console.log(`\n── BATCH 3: Scan/probe categories (${scanNames.length} scenarios) ──`);
    const r3 = await runBatch(AGENT_PORT, actualPort, scanNames);
    allResults.push(...r3);
    console.log(`  Done: ${r3.length} results`);

    // ═══════════════════════════════════════════════════
    // ANALYSIS
    // ═══════════════════════════════════════════════════
    console.log(`\n\nTotal results: ${allResults.length}`);

    const catResults = {};
    const suspicious = [];
    for (const r of allResults) {
      const cat = categoryMap[r.scenario] || 'unknown';
      if (!catResults[cat]) catResults[cat] = [];
      catResults[cat].push(r);
      const expected = expectedMap[r.scenario];
      if (expected && r.status !== expected) suspicious.push(r);
      if (r.status === 'ERROR') suspicious.push(r);
    }

    // Per-category summary
    console.log('\n══════════════════════════════════════════════════');
    console.log('  PER-CATEGORY SUMMARY');
    console.log('══════════════════════════════════════════════════');
    for (const [cat, items] of Object.entries(catResults).sort()) {
      const counts = {};
      for (const r of items) counts[r.status] = (counts[r.status] || 0) + 1;
      const parts = Object.entries(counts).sort().map(([k,v]) => `${k}:${v}`).join(' ');
      console.log(`  ${cat.padEnd(8)} ${String(items.length).padStart(4)} total | ${parts}`);
    }

    // ── Well-behaved (FV / Z) ──
    console.log('\n══════════════════════════════════════════════════');
    console.log('  WELL-BEHAVED SCENARIOS (FV / Z)');
    console.log('══════════════════════════════════════════════════');
    for (const cat of ['FV', 'Z']) {
      for (const r of (catResults[cat] || [])) {
        const expected = expectedMap[r.scenario];
        const ok = r.status === expected;
        console.log(`  ${ok ? '✓' : '✗ UNEXPECTED'} ${r.scenario}: ${r.status} (expected ${expected})`);
        console.log(`      response: ${(r.response || '').substring(0, 150)}`);
      }
    }

    // ── Virus (FW) ──
    console.log('\n══════════════════════════════════════════════════');
    console.log('  VIRUS / FIREWALL SCENARIOS (FW)');
    console.log('══════════════════════════════════════════════════');
    for (const r of (catResults.FW || [])) {
      const expected = expectedMap[r.scenario];
      const ok = r.status === expected;
      console.log(`  ${ok ? '✓' : '✗'} ${r.scenario}: ${r.status} (expected ${expected})`);
      console.log(`      response: ${(r.response || '').substring(0, 150)}`);
    }

    // ── Sandbox (SB) ──
    console.log('\n══════════════════════════════════════════════════');
    console.log('  SANDBOX SCENARIOS (SB)');
    console.log('══════════════════════════════════════════════════');
    for (const r of (catResults.SB || [])) {
      const expected = expectedMap[r.scenario];
      const ok = r.status === expected;
      console.log(`  ${ok ? '✓' : '✗'} ${r.scenario}: ${r.status} (expected ${expected})`);
      console.log(`      response: ${(r.response || '').substring(0, 150)}`);
    }

    // ── Suspicious ──
    const seen = new Set();
    const unique = suspicious.filter(r => { if (seen.has(r.scenario)) return false; seen.add(r.scenario); return true; });
    console.log('\n══════════════════════════════════════════════════');
    console.log('  SUSPICIOUS / UNEXPECTED FAILURES');
    console.log('══════════════════════════════════════════════════');
    if (unique.length === 0) {
      console.log('  None! All scenarios matched expected outcomes.');
    } else {
      console.log(`  ${unique.length} suspicious results:`);
      for (const r of unique) {
        console.log(`  - ${r.scenario} [${categoryMap[r.scenario]}]: got ${r.status}, expected ${expectedMap[r.scenario] || '?'}`);
        console.log(`    ${(r.response || '').substring(0, 200)}`);
      }
    }

    // ── Final ──
    const byStatus = {};
    for (const r of allResults) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    console.log('\n══════════════════════════════════════════════════');
    console.log('  FINAL SUMMARY');
    console.log('══════════════════════════════════════════════════');
    console.log(`  Total:      ${allResults.length}`);
    for (const [s,c] of Object.entries(byStatus).sort()) console.log(`  ${s.padEnd(10)}  ${c}`);
    console.log(`  Suspicious: ${unique.length}`);
    console.log('══════════════════════════════════════════════════');

  } finally {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
    setTimeout(() => process.exit(0), 2000);
  }
}

run().catch(err => { console.error('Test failed:', err); process.exit(1); });
