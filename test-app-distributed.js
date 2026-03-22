#!/usr/bin/env node
// Test Application Protocol (APP) scenarios in distributed mode.
// Covers SMTP, FTP, LDAP (Implicit & STARTTLS) + CVE-2011-0411 variants.

const http = require('http');
const { startAgent } = require('./lib/agent');
const { UnifiedServer } = require('./lib/unified-server');
const { getScenariosByCategory } = require('./lib/scenarios');

const SERVER_PORT = 4437;
const AGENT_PORT = 9253;

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

async function waitForDone(port, total, timeout = 300000) {
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
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Timed out after ${Math.round((Date.now() - start)/1000)}s`);
}

async function run() {
  const scenarios = getScenariosByCategory('APP').filter(s => s.side === 'client');
  const scenarioNames = scenarios.map(s => s.name);
  
  console.log(`Running ${scenarioNames.length} Application Protocol client scenarios...`);

  // We start a UnifiedServer which can handle our custom server handlers.
  // However, for a distributed run, the Agent normally talks to a static target.
  // Since these tests involve complex multi-protocol handshakes (SMTP/FTP/LDAP),
  // they require the corresponding server-side scenario to be running.
  // Distributed mode usually expects a single long-lived DUT. 
  // To test the logic, we will run them sequentially against their own well-behaved server counterparts.
  
  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  const results = [];

  for (const clientScenario of scenarios) {
    const serverScenarioName = clientScenario.name + '-server';
    // SMTP implicit has a slightly different naming convention in my previous write_file but let's check
    let srvName = serverScenarioName;
    if (clientScenario.name === 'smtp-implicit-tls-well-behaved') srvName = 'smtp-implicit-tls-well-behaved-server';
    if (clientScenario.name === 'smtp-starttls-well-behaved') srvName = 'smtp-starttls-well-behaved-server';
    if (clientScenario.name === 'ftp-implicit-tls-well-behaved') srvName = 'ftp-implicit-tls-well-behaved-server';
    if (clientScenario.name === 'ftp-starttls-well-behaved') srvName = 'ftp-starttls-well-behaved-server';
    if (clientScenario.name === 'ldap-implicit-tls-well-behaved') srvName = 'ldap-implicit-tls-well-behaved-server';
    if (clientScenario.name === 'ldap-starttls-well-behaved') srvName = 'ldap-starttls-well-behaved-server';
    
    // For CVE tests, we run them against the well-behaved STARTTLS server
    if (clientScenario.name.includes('command-injection')) {
        if (clientScenario.name.includes('smtp')) srvName = 'smtp-starttls-well-behaved-server';
        if (clientScenario.name.includes('ftp')) srvName = 'ftp-starttls-well-behaved-server';
        if (clientScenario.name.includes('ldap')) srvName = 'ldap-starttls-well-behaved-server';
    }

    const { getScenario } = require('./lib/scenarios');
    const srvScenario = getScenario(srvName);

    if (!srvScenario) {
        console.log(`Skipping ${clientScenario.name} (no server counterpart ${srvName})`);
        continue;
    }

    console.log(`\nTesting ${clientScenario.name} against ${srvName}...`);
    
    const server = new UnifiedServer({ hostname: 'localhost', port: SERVER_PORT, logger: null });
    
    // Start server in background
    const srvPromise = server.runScenario(srvScenario);
    await new Promise(r => setTimeout(r, 500)); // wait for listen

    try {
        await httpPost(AGENT_PORT, '/configure', {
            config: { host: 'localhost', port: SERVER_PORT, protocol: 'tls', workers: 1, timeout: 5000, delay: 50, baseline: false },
            scenarios: [clientScenario.name],
        });
        await httpPost(AGENT_PORT, '/run', {});
        await waitForDone(AGENT_PORT, 1);
        const batchResults = await httpGet(AGENT_PORT, '/results');
        results.push(...batchResults);
    } finally {
        await srvPromise;
        server.close();
    }
  }

  console.log('\n══════════════════════════════════════════════════');
  console.log('  APPLICATION PROTOCOLS PASS/FAIL SUMMARY');
  console.log('══════════════════════════════════════════════════');
  
  let passed = 0;
  let failed = 0;

  for (const r of results) {
    const { getScenario } = require('./lib/scenarios');
    const meta = getScenario(r.scenario);
    const expected = meta.expected || 'PASSED';
    const isOk = r.status === expected;
    
    if (isOk) passed++; else failed++;

    console.log(`  ${isOk ? '✓ PASS' : '✗ FAIL'} ${r.scenario.padEnd(45)} | Got: ${r.status.padEnd(10)} | Expected: ${expected}`);
    if (!isOk || r.status === 'ERROR') {
        console.log(`           Response: ${r.response}`);
    }
  }

  console.log('══════════════════════════════════════════════════');
  console.log(`  TOTAL: ${results.length} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('══════════════════════════════════════════════════');

  try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
  try { agent.close(); } catch {}
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => { console.error(err); process.exit(1); });
