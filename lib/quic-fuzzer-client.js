// QUIC Fuzzing Client — connects to a target QUIC server via UDP and runs scenarios
const dgram = require('dgram');
const crypto = require('crypto');
const { Logger } = require('./logger');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { QUIC_CATEGORY_SEVERITY } = require('./quic-scenarios');

class QuicFuzzerClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.dut = opts.dut || null;
    this.aborted = false;
    this.socket = null;
  }

  abort() {
    this.aborted = true;
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };
    if (scenario.side === 'server') {
      this.logger.error(`Skipping server-side scenario "${scenario.name}" in client mode`);
      return { scenario: scenario.name, status: 'SKIPPED', response: 'Server-side scenario cannot run in client mode' };
    }

    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let receivedAny = false;

    try {
      this.socket = dgram.createSocket('udp4');
      
      const recvBuffer = [];
      this.socket.on('message', (msg, rinfo) => {
        receivedAny = true;
        recvBuffer.push(msg);
        this.logger.received(msg, `UDP from ${rinfo.address}:${rinfo.port}`);
      });

      this.socket.on('error', (err) => {
        this.logger.error(`Socket error: ${err.message}`);
      });

      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'send': {
            try {
              await this._sendUDP(action.data);
              this.logger.sent(action.data, action.label);
            } catch (e) {
              this.logger.error(`UDP send failed: ${e.message}`);
              status = 'ERROR';
            }
            break;
          }

          case 'recv': {
            const recvTimeout = action.timeout || this.timeout;
            const data = await this._waitForUDP(recvBuffer, recvTimeout);
            if (data) {
              lastResponse = `QUIC response (${data.length} bytes)`;
              rawResponse = data;
            } else {
              lastResponse = 'No UDP response (timeout)';
              status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': {
            await this._sleep(action.ms);
            break;
          }
        }

        if (action.type !== 'delay' && action.type !== 'recv') {
          await this._sleep(this.delay);
        }
      }

    } catch (e) {
      this.logger.error(`Scenario failed: ${e.message}`);
      status = 'ERROR';
      lastResponse = e.message;
    } finally {
      if (this.socket) {
        this.socket.close();
        this.socket = null;
      }
    }

    // UDP doesn't have "DROPPED" (connection closed) in the same way, 
    // but if we got nothing and it's not a success, we'll call it TIMEOUT/DROPPED
    if (status === 'PASSED' && !receivedAny) {
        // Many fuzz scenarios expect the server to drop the packet silently
        status = 'TIMEOUT'; 
    }

    // Health probe after failures — QUIC runs over UDP, so we send a
    // minimal QUIC Initial packet and check for any UDP response.
    let hostDown = false;
    let probe = null;
    if (['TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host, this.port);
      hostDown = !probe.udp.alive;
      if (hostDown) this.logger.hostDown(this.host, this.port, scenario.name);
      this.logger.healthProbe(this.host, this.port, probe);
    }

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    const verdict = this._computeVerdict(status, expected);
    const severity = QUIC_CATEGORY_SEVERITY[scenario.category] || 'medium';
    
    const result = {
      scenario: scenario.name, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, null);
    return result;
  }

  async runScenarios(scenarios) {
    const results = [];
    let hostWentDown = false;

    for (const scenario of scenarios) {
      if (this.aborted) break;

      if (hostWentDown) {
        this.logger.info(`Re-checking ${this.host}:${this.port} before next scenario...`);
        const recheck = await this._runHealthProbes(this.host, this.port);
        this.logger.healthProbe(this.host, this.port, recheck);
        if (!recheck.tcp.alive && !recheck.https.alive) {
          this.logger.hostDown(this.host, this.port, 'still unreachable — stopping batch');
          break;
        }
        this.logger.info('Host is back up — continuing');
        hostWentDown = false;
      }

      const result = await this.runScenario(scenario);
      results.push(result);
      if (result.hostDown) hostWentDown = true;
      await this._sleep(500);
    }

    const report = computeOverallGrade(results);
    this.logger.summary(results, report);
    return { results, report };
  }

  _sendUDP(data) {
    return new Promise((resolve, reject) => {
      this.socket.send(data, this.port, this.host, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  _waitForUDP(recvBuffer, timeout) {
    return new Promise((resolve) => {
      if (recvBuffer.length > 0) return resolve(recvBuffer.shift());
      
      const timer = setTimeout(() => {
        this.socket.removeListener('message', onMsg);
        resolve(null);
      }, timeout);

      const onMsg = (msg) => {
        clearTimeout(timer);
        this.socket.removeListener('message', onMsg);
        resolve(msg);
      };

      this.socket.on('message', onMsg);
    });
  }

  _computeVerdict(status, expected) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    // For UDP, we often treat TIMEOUT as DROPPED (server ignored)
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    const expectedEffective = expected === 'TIMEOUT' ? 'DROPPED' : expected;
    return effective === expectedEffective ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  /**
   * UDP health probe — send a minimal QUIC Initial packet and check for
   * any response.  QUIC servers listen on UDP only; TCP/HTTPS probes are
   * not meaningful here.
   */
  _checkUDPAlive(host, port, timeout = 2000) {
    const start = Date.now();
    return new Promise((resolve) => {
      const socket = dgram.createSocket('udp4');
      let resolved = false;
      const done = (result) => {
        if (resolved) return;
        resolved = true;
        try { socket.close(); } catch (_) {}
        resolve(result);
      };

      // Minimal QUIC long-header Initial packet (padded to 1200 bytes per RFC 9000 §14.1)
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      const hdrLen = 1 + 4 + 1 + dcid.length + 1 + scid.length;
      const header = Buffer.alloc(hdrLen);
      header[0] = 0xc0; // Long header, Initial type
      header.writeUInt32BE(0x00000001, 1); // QUIC v1
      header[5] = dcid.length;
      dcid.copy(header, 6);
      header[6 + dcid.length] = scid.length;
      scid.copy(header, 7 + dcid.length);
      const padding = Buffer.alloc(Math.max(0, 1200 - hdrLen));
      const packet = Buffer.concat([header, padding]);

      socket.on('message', () => {
        done({ alive: true, latency: Date.now() - start });
      });
      socket.on('error', (err) => {
        done({ alive: false, error: err.code || err.message });
      });
      socket.send(packet, port, host, (err) => {
        if (err) done({ alive: false, error: err.code || err.message });
      });

      setTimeout(() => done({ alive: false, error: 'timeout' }), timeout);
    });
  }

  async _runHealthProbes(host, port) {
    const udp = await this._checkUDPAlive(host, port);
    return { udp };
  }

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  close() {}
}

module.exports = { QuicFuzzerClient };
