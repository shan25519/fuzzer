const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const { generateServerCert } = require('./cert-gen');
const { FuzzerClient } = require('./fuzzer-client');
const { UnifiedClient } = require('./unified-client');
const { QuicFuzzerClient } = require('./quic-fuzzer-client');
const { Http2FuzzerClient } = require('./http2-fuzzer-client');
const { FuzzerServer } = require('./fuzzer-server');
const { UnifiedServer } = require('./unified-server');
const { QuicFuzzerServer } = require('./quic-fuzzer-server');
const { Http2FuzzerServer } = require('./http2-fuzzer-server');
const fs = require('fs');

class DummyLogger {
  verbose = false;
  json = true;
  events = [];
  onEvent() { return () => {}; }
  _emit() {}
  timestamp() { return ''; }
  scenario() {}
  sent() {}
  received() {}
  info() {}
  warn() {}
  error() {}
  fuzz() {}
  tcpEvent() {}
  healthProbe() {}
  hostDown() {}
  result() {}
}

const certPath = path.join(os.tmpdir(), 'fuzzer-openssl-cert.pem');
const keyPath = path.join(os.tmpdir(), 'fuzzer-openssl-key.pem');

// Helper to spawn OpenSSL Server
function startOpenSSLServer(port) {
  try {
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${keyPath} -out ${certPath} -days 1 -subj '/CN=localhost'`, { stdio: 'ignore' });
    }
  } catch (e) {
    return null;
  }

  const server = spawn('openssl', [
    's_server',
    '-cert', certPath,
    '-key', keyPath,
    '-accept', port.toString(),
    '-www',
    '-alpn', 'h2,http/1.1',
    '-ign_eof'
  ]);

  return new Promise((resolve) => {
    let started = false;
    server.stdout.on('data', (data) => {
      if (!started && data.toString().includes('ACCEPT')) {
        started = true;
        resolve(server);
      }
    });
    server.on('error', () => { if (!started) resolve(null); });
    setTimeout(() => { if (!started) resolve(server); }, 500); // fallback timeout
  });
}

  // Helper to run OpenSSL Client
function runOpenSSLClient(port, protocol) {
  const args = ['s_client', '-connect', `localhost:${port}`, '-ign_eof'];
  if (protocol === 'h2') args.push('-alpn', 'h2');
  if (protocol === 'quic') args.push('-quic');
  
  const client = spawn('openssl', args);
  // Send some dummy data to keep it alive or trigger server reaction
  client.stdin.write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
  
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(client);
    }, 200); // give it time to connect
  });
}

async function runBaseline(scenario, protocol = 'tls') {
  const port = 44333 + Math.floor(Math.random() * 1000); // random port to avoid collisions
  const useRawTcp = protocol === 'raw-tcp';
  const dummyLogger = new DummyLogger();

  if (scenario.side === 'client') {
    // Target is an OpenSSL server
    if (protocol === 'quic') return { response: 'QUIC not supported in baseline OpenSSL server', command: 'N/A' };
    const sslServer = await startOpenSSLServer(port);
    if (!sslServer) return { response: 'Failed to start OpenSSL baseline server', command: 'openssl s_server ...' };

    const command = `openssl s_server -cert ${certPath} -key ${keyPath} -accept ${port} -www -alpn h2,http/1.1 -ign_eof`;

    let client;
    if (useRawTcp || protocol === 'h2' || protocol === 'quic') {
      client = new UnifiedClient({ host: '127.0.0.1', port, timeout: 2000, delay: 50, logger: dummyLogger });
    } else {
      client = new FuzzerClient({ host: '127.0.0.1', port, timeout: 2000, delay: 50, logger: dummyLogger });
    }

    try {
      const res = await client.runScenario(scenario);
      return { response: res.response || res.status, command };
    } catch (e) {
      return { response: 'Baseline Error: ' + e.message, command };
    } finally {
      sslServer.kill('SIGKILL');
      if (client.close) client.close();
    }
  } else {
    // Server scenario: Target is an OpenSSL client
    let server;
    if (useRawTcp || protocol === 'h2' || protocol === 'quic') {
      server = new UnifiedServer({ port, timeout: 2000, delay: 50, logger: dummyLogger });
    } else {
      server = new FuzzerServer({ port, timeout: 2000, delay: 50, logger: dummyLogger });
    }

    const args = ['s_client', '-connect', `localhost:${port}`, '-ign_eof'];
    if (protocol === 'h2') args.push('-alpn', 'h2');
    if (protocol === 'quic') args.push('-quic');
    const command = `openssl ${args.join(' ')}`;

    // Spawn openssl client in background shortly after server starts listening
    // runScenario binds the port, so give it 50ms to bind before spawning s_client
    let sslClient;
    setTimeout(async () => {
      sslClient = await runOpenSSLClient(port, protocol);
    }, 50);

    try {
      const res = await server.runScenario(scenario);
      return { response: res.response || res.status, command };
    } catch (e) {
      return { response: 'Baseline Error: ' + e.message, command };
    } finally {
      if (sslClient) sslClient.kill('SIGKILL');
      if (server.close) server.close();
      if (server.stop) await server.stop();
      if (server.server) server.server.close();
    }
  }
}

module.exports = { runBaseline };
