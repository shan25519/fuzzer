#!/usr/bin/env node
// Test all HTTP/2 scenarios in distributed mode
// Launches client + server agents, a well-behaved counterpart for each,
// and drives them through the Controller.

const { startAgent } = require('./lib/agent');
const { Controller } = require('./lib/controller');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { WellBehavedClient } = require('./lib/well-behaved-client');
const { HTTP2_SCENARIOS } = require('./lib/http2-scenarios');

const CLIENT_CONTROL_PORT = 19200;
const SERVER_CONTROL_PORT = 19201;
const FUZZ_PORT = 14433;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  const verbose = process.argv.includes('--verbose');

  const clientScenarios = HTTP2_SCENARIOS.filter(s => s.side === 'client');
  const serverScenarios = HTTP2_SCENARIOS.filter(s => s.side === 'server');

  console.log('');
  console.log('  \x1b[1m\x1b[36mHTTP/2 Distributed Mode Test\x1b[0m');
  console.log('');
  console.log(`  Client-side scenarios: ${clientScenarios.length}`);
  console.log(`  Server-side scenarios: ${serverScenarios.length}`);
  console.log('');

  // ── Phase 1: Client-side scenarios ──────────────────────────────────────
  // Client agent sends fuzzed H2 frames → well-behaved H2 server receives them
  if (clientScenarios.length > 0) {
    console.log('  \x1b[1m── Phase 1: Client-side H2 scenarios ──\x1b[0m');
    console.log('  Starting well-behaved H2 server as target...');

    const wbServer = new WellBehavedServer({ port: FUZZ_PORT, hostname: 'localhost' });
    await wbServer.startH2();
    console.log(`  Well-behaved H2 server on port ${wbServer.actualPort}`);

    console.log('  Starting client agent...');
    const clientAgent = startAgent('client', { controlPort: CLIENT_CONTROL_PORT });
    await sleep(500);

    const controller = new Controller();
    await controller.connect('client', 'localhost', CLIENT_CONTROL_PORT);
    console.log('  Controller connected to client agent');

    const scenarioNames = clientScenarios.map(s => s.name);
    await controller.configure('client', scenarioNames, {
      host: 'localhost',
      port: wbServer.actualPort,
      protocol: 'h2',
      timeout: 5000,
      delay: 50,
    });
    console.log(`  Configured ${scenarioNames.length} client scenarios`);

    // Collect results via event stream
    const results = [];
    let done = false;
    const errors = [];

    controller.onEvent((role, event) => {
      if (event.type === 'result') {
        const r = event.result;
        const icon = r.verdict === 'AS EXPECTED' ? '\x1b[32m✓\x1b[0m'
          : r.status === 'TIMEOUT' ? '\x1b[33m⏱\x1b[0m'
          : '\x1b[31m✗\x1b[0m';
        console.log(`    ${icon} ${r.scenario} → ${r.status} (${r.verdict})`);
        results.push(r);
      } else if (event.type === 'error') {
        errors.push(event.message);
        console.log(`    \x1b[31mERROR: ${event.message}\x1b[0m`);
      } else if (event.type === 'done') {
        done = true;
      } else if (event.type === 'report') {
        console.log('');
        console.log(`  \x1b[1mClient Phase Report:\x1b[0m`);
        const s = event.report.stats;
        console.log(`    Pass: ${s.pass}  Fail: ${s.fail}  Warn: ${s.warn}  Skip: ${s.skip}`);
        console.log(`    Grade: ${event.report.grade}`);
      } else if (verbose && event.type === 'logger') {
        const e = event.event;
        if (e.type === 'error') console.log(`    \x1b[90m[${e.type}] ${e.message}\x1b[0m`);
      }
    });

    await controller.runAll();
    console.log('  Running client scenarios...');
    console.log('');

    // Wait for completion
    const deadline = Date.now() + 300000; // 5 min max
    while (!done && Date.now() < deadline) {
      await sleep(500);
    }
    if (!done) console.log('  \x1b[33mWarning: client phase timed out\x1b[0m');

    controller.disconnect();
    clientAgent.close();
    wbServer.stop();
    await sleep(500);

    console.log('');
    console.log(`  Client phase complete: ${results.length}/${clientScenarios.length} scenarios ran`);
    if (errors.length > 0) console.log(`  \x1b[31mErrors: ${errors.length}\x1b[0m`);
    console.log('');
  }

  // ── Phase 2: Server-side scenarios ──────────────────────────────────────
  // Server agent acts as malicious H2 server → well-behaved H2 client connects
  if (serverScenarios.length > 0) {
    console.log('  \x1b[1m── Phase 2: Server-side H2 scenarios ──\x1b[0m');
    console.log('  Starting server agent...');

    const serverAgent = startAgent('server', { controlPort: SERVER_CONTROL_PORT });
    await sleep(500);

    const controller = new Controller();
    await controller.connect('server', 'localhost', SERVER_CONTROL_PORT);
    console.log('  Controller connected to server agent');

    const scenarioNames = serverScenarios.map(s => s.name);
    await controller.configure('server', scenarioNames, {
      hostname: 'localhost',
      port: FUZZ_PORT,
      protocol: 'h2',
      timeout: 10000,
      delay: 50,
    });
    console.log(`  Configured ${scenarioNames.length} server scenarios`);

    // Collect results via event stream
    const results = [];
    let done = false;
    const errors = [];
    let currentScenario = null;

    controller.onEvent((role, event) => {
      if (event.type === 'progress') {
        currentScenario = event.scenario;
      } else if (event.type === 'result') {
        const r = event.result;
        const icon = r.verdict === 'AS EXPECTED' ? '\x1b[32m✓\x1b[0m'
          : r.status === 'TIMEOUT' ? '\x1b[33m⏱\x1b[0m'
          : '\x1b[31m✗\x1b[0m';
        console.log(`    ${icon} ${r.scenario} → ${r.status} (${r.verdict})`);
        results.push(r);
      } else if (event.type === 'error') {
        errors.push(event.message);
        console.log(`    \x1b[31mERROR: ${event.message}\x1b[0m`);
      } else if (event.type === 'done') {
        done = true;
      } else if (event.type === 'report') {
        console.log('');
        console.log(`  \x1b[1mServer Phase Report:\x1b[0m`);
        const s = event.report.stats;
        console.log(`    Pass: ${s.pass}  Fail: ${s.fail}  Warn: ${s.warn}  Skip: ${s.skip}`);
        console.log(`    Grade: ${event.report.grade}`);
      }
    });

    await controller.runAll();
    console.log('  Running server scenarios...');
    console.log('  (A well-behaved H2 client will connect for each scenario)');
    console.log('');

    // For server-side scenarios, we need to connect a well-behaved client
    // for each scenario as it waits for a client connection
    const wbClient = new WellBehavedClient({ host: 'localhost', port: FUZZ_PORT });

    const connectClient = async () => {
      for (let i = 0; i < serverScenarios.length; i++) {
        if (done) break;
        // Wait a moment for the server scenario to start listening
        await sleep(1500);
        if (done) break;
        try {
          await wbClient.connectH2();
        } catch (e) {
          // Expected — server sends malformed data
        }
        await sleep(500);
      }
    };

    // Run client connections in parallel with scenario execution
    const clientTask = connectClient();

    // Wait for completion
    const deadline = Date.now() + 600000; // 10 min max
    while (!done && Date.now() < deadline) {
      await sleep(500);
    }
    if (!done) console.log('  \x1b[33mWarning: server phase timed out\x1b[0m');

    wbClient.stop();
    await clientTask.catch(() => {});
    controller.disconnect();
    serverAgent.close();
    await sleep(500);

    console.log('');
    console.log(`  Server phase complete: ${results.length}/${serverScenarios.length} scenarios ran`);
    if (errors.length > 0) console.log(`  \x1b[31mErrors: ${errors.length}\x1b[0m`);
    console.log('');
  }

  console.log('  \x1b[1m\x1b[32mAll HTTP/2 distributed tests complete.\x1b[0m');
  console.log('');
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  console.error(err.stack);
  process.exit(1);
});
