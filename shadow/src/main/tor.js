'use strict';
/**
 * Tor integration and proxy management.
 *
 * What this actually is, stated plainly so nobody is misled:
 *
 *  - Tor is real anonymity and it is free. Shadow launches a local Tor
 *    process and points the whole browser session at its SOCKS5 port. Your
 *    traffic then goes through three relays run by different people, and no
 *    single one of them knows both who you are and what you asked for.
 *
 *  - Shadow does NOT ship a "free VPN". Anyone offering one is paying for
 *    servers somehow, and the usual way is by selling your traffic. Tor is
 *    the free option that does not have that problem. If you already pay for
 *    a VPN, point Shadow at it with proxy.mode = "manual".
 *
 *  - Tor is not a magic cloak. If you log into an account, that account is
 *    still you. Shadow's fingerprint hardening exists to cover the other half.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const DEFAULT_SOCKS = 9150;
const DEFAULT_CONTROL = 9151;

function which(bin) {
  return new Promise((resolve) => {
    execFile(process.platform === 'win32' ? 'where' : 'which', [bin], (err, stdout) => {
      resolve(err ? null : String(stdout).split(/\r?\n/)[0].trim() || null);
    });
  });
}

function portOpen(port, host = '127.0.0.1', timeout = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (v) => { socket.destroy(); resolve(v); };
    socket.setTimeout(timeout);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

class TorManager {
  constructor({ settings, events, dataDir } = {}) {
    this.settings = settings;
    this.events = events;
    this.dataDir = dataDir || path.join(os.homedir(), '.shadow', 'tor');
    this.process = null;
    this.state = 'stopped';   // stopped | starting | running | failed | external
    this.bootstrap = 0;
    this.lastError = null;
    this.log = [];
  }

  socksPort() { return (this.settings && this.settings.get('tor.socksPort')) || DEFAULT_SOCKS; }
  controlPort() { return (this.settings && this.settings.get('tor.controlPort')) || DEFAULT_CONTROL; }

  /** Find a tor binary: explicit setting, then PATH, then common locations. */
  async findBinary() {
    const configured = this.settings && this.settings.get('tor.binaryPath');
    if (configured && fs.existsSync(configured)) return configured;

    const onPath = await which('tor');
    if (onPath) return onPath;

    const candidates = process.platform === 'darwin'
      ? ['/opt/homebrew/bin/tor', '/usr/local/bin/tor',
         '/Applications/Tor Browser.app/Contents/MacOS/Tor/tor']
      : process.platform === 'win32'
        ? ['C:\\Program Files\\Tor\\tor.exe',
           path.join(os.homedir(), 'Desktop', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe')]
        : ['/usr/bin/tor', '/usr/sbin/tor', '/usr/local/bin/tor', '/snap/bin/tor'];
    for (const c of candidates) if (fs.existsSync(c)) return c;
    return null;
  }

  /**
   * Start Tor. If something is already listening on the SOCKS port (a running
   * Tor Browser, or a system tor service), Shadow uses that instead of
   * starting a second one.
   */
  async start() {
    if (this.state === 'running' || this.state === 'external') return this.status();
    this.state = 'starting';
    this.lastError = null;

    const socks = this.socksPort();
    if (await portOpen(socks)) {
      this.state = 'external';
      this.bootstrap = 100;
      this._event('tor-attached', { port: socks, note: 'used an already-running Tor' });
      return this.status();
    }

    const binary = await this.findBinary();
    if (!binary) {
      this.state = 'failed';
      this.lastError =
        'Tor is not installed. Install it and try again:\n' +
        '  Debian/Ubuntu:  sudo apt install tor\n' +
        '  Fedora:         sudo dnf install tor\n' +
        '  macOS:          brew install tor\n' +
        '  Windows:        install the Tor Browser bundle, or set tor.binaryPath\n' +
        'Shadow will not silently fall back to a direct connection, because you\n' +
        'would think you were anonymous when you were not.';
      this._event('tor-failed', { reason: 'binary-not-found' });
      return this.status();
    }

    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    const torrc = path.join(this.dataDir, 'torrc');
    const bridges = (this.settings && this.settings.get('tor.bridges')) || [];
    const lines = [
      `SocksPort 127.0.0.1:${socks} IsolateDestAddr IsolateDestPort`,
      `ControlPort 127.0.0.1:${this.controlPort()}`,
      'CookieAuthentication 1',
      `DataDirectory ${this.dataDir}`,
      'AvoidDiskWrites 1',
      'ClientOnly 1',
      // Never act as a relay or exit for anyone else.
      'ORPort 0',
      'ExitRelay 0',
      'SocksPolicy accept 127.0.0.1',
      'SocksPolicy reject *',
    ];
    if (bridges.length) {
      lines.push('UseBridges 1');
      lines.push('ClientTransportPlugin obfs4 exec obfs4proxy');
      for (const b of bridges) lines.push(`Bridge ${b}`);
    }
    fs.writeFileSync(torrc, `${lines.join('\n')}\n`, { mode: 0o600 });

    return new Promise((resolve) => {
      this.process = spawn(binary, ['-f', torrc], { stdio: ['ignore', 'pipe', 'pipe'] });
      let settled = false;

      const finish = () => { if (!settled) { settled = true; resolve(this.status()); } };
      const timer = setTimeout(() => {
        if (this.state !== 'running') {
          this.lastError = `Tor did not finish bootstrapping in 90 seconds (reached ${this.bootstrap}%). If you are on a network that blocks Tor, add bridges in Settings.`;
          this.state = 'failed';
          this._event('tor-failed', { reason: 'bootstrap-timeout', bootstrap: this.bootstrap });
        }
        finish();
      }, 90000);

      this.process.stdout.on('data', (chunk) => {
        const text = String(chunk);
        this.log.push(text);
        if (this.log.length > 200) this.log.shift();
        const m = text.match(/Bootstrapped (\d+)%/);
        if (m) {
          this.bootstrap = Number(m[1]);
          this._event('tor-bootstrap', { percent: this.bootstrap });
          if (this.bootstrap >= 100) {
            this.state = 'running';
            clearTimeout(timer);
            this._event('tor-running', { port: socks });
            finish();
          }
        }
        if (/Could not bind|Address already in use/i.test(text)) {
          this.lastError = `Port ${socks} is already in use by something else.`;
          this.state = 'failed';
          clearTimeout(timer);
          finish();
        }
      });

      this.process.stderr.on('data', (chunk) => {
        this.log.push(String(chunk));
        if (this.log.length > 200) this.log.shift();
      });

      this.process.on('error', (err) => {
        this.state = 'failed';
        this.lastError = `Could not start Tor: ${err.message}`;
        clearTimeout(timer);
        this._event('tor-failed', { reason: err.message });
        finish();
      });

      this.process.on('exit', (code) => {
        if (this.state !== 'failed') {
          this.state = 'stopped';
          this._event('tor-stopped', { code });
        }
        this.process = null;
        clearTimeout(timer);
        finish();
      });
    });
  }

  stop() {
    if (this.process) {
      try { this.process.kill('SIGTERM'); } catch { /* already gone */ }
      this.process = null;
    }
    this.state = 'stopped';
    this.bootstrap = 0;
    this._event('tor-stopped', {});
    return this.status();
  }

  /** Ask Tor for a fresh circuit (a new exit relay, so a new apparent IP). */
  async newIdentity() {
    const cookiePath = path.join(this.dataDir, 'control_auth_cookie');
    return new Promise((resolve) => {
      const socket = net.connect(this.controlPort(), '127.0.0.1');
      let cookieHex = '';
      try { cookieHex = fs.readFileSync(cookiePath).toString('hex'); } catch { /* no cookie */ }
      let stage = 0;
      socket.setTimeout(5000);
      socket.on('connect', () => socket.write(`AUTHENTICATE ${cookieHex}\r\n`));
      socket.on('data', (d) => {
        const line = String(d);
        if (stage === 0) {
          if (!line.startsWith('250')) { socket.end(); return resolve({ ok: false, error: line.trim() }); }
          stage = 1;
          socket.write('SIGNAL NEWNYM\r\n');
        } else {
          socket.end();
          const ok = line.startsWith('250');
          this._event('tor-new-identity', { ok });
          resolve({ ok, response: line.trim() });
        }
      });
      socket.on('timeout', () => { socket.destroy(); resolve({ ok: false, error: 'control port timeout' }); });
      socket.on('error', (e) => resolve({ ok: false, error: e.message }));
    });
  }

  /**
   * The proxy configuration to hand to an Electron session.
   * Returns null when the browser should connect directly.
   */
  proxyConfig() {
    const s = this.settings;
    const mode = s ? s.get('proxy.mode') : 'direct';
    const torOn = s ? s.get('tor.enabled') : false;

    if (torOn) {
      const running = this.state === 'running' || this.state === 'external';
      if (!running) {
        // Fail closed. Better a browser that will not load than one that
        // silently leaks outside Tor while claiming to be anonymous.
        return { mode: 'fixed_servers', proxyRules: 'socks5://127.0.0.1:1', // dead port
          proxyBypassRules: '<-loopback>', failClosed: true };
      }
      return {
        mode: 'fixed_servers',
        proxyRules: `socks5://127.0.0.1:${this.socksPort()}`,
        proxyBypassRules: '<-loopback>',
      };
    }

    if (mode === 'manual' && s.get('proxy.url')) {
      return {
        mode: 'fixed_servers',
        proxyRules: s.get('proxy.url'),
        proxyBypassRules: s.get('proxy.bypassList') || '<local>',
      };
    }
    if (mode === 'system') return { mode: 'system' };
    return { mode: 'direct' };
  }

  /** Confirm we are really exiting through Tor. */
  async verify(session) {
    if (!session) return { ok: false, error: 'no session' };
    try {
      const res = await session.fetch('https://check.torproject.org/api/ip');
      const body = await res.json();
      const ok = Boolean(body && body.IsTor);
      this._event('tor-verified', { ok, ip: body && body.IP });
      return { ok, ip: body && body.IP, raw: body };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  status() {
    return {
      state: this.state,
      bootstrap: this.bootstrap,
      socksPort: this.socksPort(),
      controlPort: this.controlPort(),
      error: this.lastError,
      enabled: this.settings ? this.settings.get('tor.enabled') : false,
      proxy: this.proxyConfig(),
    };
  }

  _event(type, data) {
    if (this.events) this.events.record({ type, ...data });
  }
}

module.exports = { TorManager, portOpen, DEFAULT_SOCKS, DEFAULT_CONTROL };
