const { connect, createSecureServer } = require('@currentspace/http3');
const { WellBehavedClient } = require('./lib/well-behaved-client');
const { WellBehavedServer } = require('./lib/well-behaved-server');

const results = [];

function log(msg) { console.log(msg); }

async function testPublicTarget(host) {
  log(`\n--- ${host} (HTTP/3, 2 concurrent streams) ---`);
  return new Promise((resolve) => {
    const session = connect(`https://${host}:443`, { rejectUnauthorized: false });

    session.on('connect', () => {
      log(`[${host}] HTTP/3 connected`);

      let done = 0;
      const paths = ['/', '/robots.txt'];
      const streamResults = [];

      paths.forEach((p, i) => {
        const req = session.request({ ':method': 'GET', ':path': p, ':scheme': 'https', ':authority': host });
        let buf = Buffer.alloc(0);
        let status = '';
        req.on('response', (h) => { status = h[':status'] || '?'; });
        req.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        const finish = () => {
          streamResults.push({ path: p, status, bytes: buf.length });
          log(`[${host}] Stream ${i + 1} (${p}): status=${status}, ${buf.length} bytes`);
          done++;
          if (done >= paths.length) {
            const ok = streamResults.every(r => r.bytes > 0);
            log(`[${host}] ${ok ? 'PASS' : 'FAIL'} - ${done} streams`);
            results.push({ target: host, pass: ok });
            try { session.close(); } catch (_) {}
            resolve();
          }
        };
        req.on('end', finish);
        req.on('error', finish);
        req.end();
      });
    });

    session.on('error', (e) => {
      log(`[${host}] ERROR: ${e.message}`);
      results.push({ target: host, pass: false });
      resolve();
    });

    setTimeout(() => {
      log(`[${host}] TIMEOUT`);
      results.push({ target: host, pass: false });
      try { session.close(); } catch (_) {}
      resolve();
    }, 10000);
  });
}

async function testLocalServerClient() {
  log('\n--- Local server <-> client (HTTP/3, 3 streams) ---');

  const server = new WellBehavedServer({ port: 0, logger: { info: (m) => log(`  ${m}`), error: (m) => log(`  ERR: ${m}`) } });
  await server.startQuic();
  const port = server.actualPort;
  log(`  Server started on port ${port}`);

  const client = new WellBehavedClient({
    host: 'localhost',
    port,
    logger: { info: (m) => log(`  ${m}`), error: (m) => log(`  ERR: ${m}`) },
  });

  await client.connectQuic({ streams: 3 });
  log('  Client finished');

  client.stop();
  server.stop();

  // Mark pass if we got this far without errors
  results.push({ target: 'local (3 streams)', pass: true });
  log('  Local test: PASS');
}

(async () => {
  log('QUIC/HTTP3 End-to-End Test');
  log(`Node ${process.version} | ${process.platform}-${process.arch}\n`);

  await testPublicTarget('google.com');
  await testPublicTarget('cloudflare.com');
  await testLocalServerClient();

  log(`\n${'='.repeat(50)}`);
  log('RESULTS');
  log('='.repeat(50));
  for (const r of results) {
    log(`  ${r.target}: ${r.pass ? 'PASS' : 'FAIL'}`);
  }

  const allPass = results.every(r => r.pass);
  log(`\nOverall: ${allPass ? 'ALL PASS' : 'SOME FAILED'}`);
  process.exit(allPass ? 0 : 1);
})();
