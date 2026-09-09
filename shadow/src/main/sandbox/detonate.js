'use strict';
/**
 * Optional dynamic analysis ("detonation").
 *
 * Static scanning cannot see what a packed binary does once it runs. This
 * module opens the file inside a throwaway container with no network and no
 * access to your files, watches what it touches, then destroys the container.
 *
 * Deliberate limits, stated plainly:
 *  - It is OFF by default. It requires Docker or Podman to be installed.
 *  - A Linux container cannot meaningfully run a Windows .exe. For PE files
 *    Shadow does deeper static work instead and says so, rather than
 *    pretending to have detonated it.
 *  - Real malware detects sandboxes. Treat a clean detonation as "nothing
 *    obvious happened", never as "this file is safe".
 */

const { spawn, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const IMAGE = process.env.SHADOW_SANDBOX_IMAGE || 'debian:stable-slim';
const RUN_TIMEOUT_MS = 25000;

function signal(id, score, severity, title, detail) {
  return { id, score, severity, title, detail };
}

function which(bin) {
  return new Promise((resolve) => {
    execFile(process.platform === 'win32' ? 'where' : 'which', [bin], (err, stdout) => {
      resolve(err ? null : String(stdout).split(/\r?\n/)[0].trim() || null);
    });
  });
}

class Detonator {
  constructor({ settings, events } = {}) {
    this.settings = settings;
    this.events = events;
    this.runtime = null;
    this.checked = false;
  }

  /** Find a container runtime once and remember the answer. */
  async runtimeBinary() {
    if (this.checked) return this.runtime;
    this.checked = true;
    this.runtime = (await which('podman')) ? 'podman' : ((await which('docker')) ? 'docker' : null);
    return this.runtime;
  }

  async available() {
    return Boolean(await this.runtimeBinary());
  }

  /**
   * @param {string} filePath quarantined file
   * @param {object} meta     { originalName }
   */
  async run(filePath, meta = {}) {
    const runtime = await this.runtimeBinary();
    if (!runtime) {
      return {
        available: false,
        reason: 'No container runtime found. Install Docker or Podman to enable detonation.',
        signals: [],
      };
    }

    const name = meta.originalName || path.basename(filePath);
    const ext = path.extname(name).toLowerCase();

    // Be honest about what a Linux container can and cannot execute.
    const windowsOnly = ['.exe', '.dll', '.msi', '.scr', '.bat', '.cmd', '.ps1', '.hta', '.vbs', '.lnk', '.cpl'];
    if (windowsOnly.includes(ext) && process.platform !== 'win32') {
      return {
        available: true,
        executed: false,
        reason: `${ext} is a Windows program. Shadow will not pretend a Linux container ran it. The static report is the authoritative result for this file.`,
        signals: [],
      };
    }

    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-detonate-'));
    const staged = path.join(workDir, 'sample');
    fs.copyFileSync(filePath, staged);
    fs.chmodSync(staged, 0o500);

    // The command run inside the container. It never has network access and
    // never sees anything but a copy of the sample.
    const script = [
      'set -u',
      'cd /sample',
      'ls -la > /report/listing.txt 2>&1 || true',
      'timeout 12 strace -f -e trace=file,network,process -o /report/strace.txt ./sample >/report/stdout.txt 2>/report/stderr.txt || true',
      'find / -xdev -newer /sample/sample -type f 2>/dev/null | grep -v "^/proc\\|^/sys\\|^/report\\|^/tmp" | head -200 > /report/touched.txt || true',
    ].join('\n');

    const reportDir = path.join(workDir, 'report');
    fs.mkdirSync(reportDir, { mode: 0o700 });

    const args = [
      'run', '--rm',
      '--network', 'none',
      '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--pids-limit', '128',
      '--memory', '512m',
      '--cpus', '1',
      '-v', `${workDir}:/sample:ro`,
      '-v', `${reportDir}:/report:rw`,
      '--workdir', '/sample',
      IMAGE,
      '/bin/sh', '-c', script,
    ];

    const started = Date.now();
    const result = await new Promise((resolve) => {
      const child = spawn(runtime, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = ''; let err = '';
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, RUN_TIMEOUT_MS);
      child.stdout.on('data', (d) => { out += d; });
      child.stderr.on('data', (d) => { err += d; });
      child.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); });
      child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, out, err: e.message }); });
    });

    const read = (f) => {
      try { return fs.readFileSync(path.join(reportDir, f), 'utf8'); } catch { return ''; }
    };
    const strace = read('strace.txt');
    const touched = read('touched.txt');
    const stdout = read('stdout.txt');
    const stderr = read('stderr.txt');

    const signals = [];
    const behaviours = [];

    const noteIf = (re, id, score, severity, title, detail) => {
      if (re.test(strace) || re.test(stdout)) {
        behaviours.push(id);
        signals.push(signal(`detonation.${id}`, score, severity, title, detail));
      }
    };

    noteIf(/\b(?:connect|socket|sendto|getaddrinfo)\(/, 'network-attempt', 55, 'high',
      'The file tried to reach the network',
      'It attempted outbound connections in a container that has no network at all.');
    noteIf(/execve\("\/(?:bin|usr\/bin)\/(?:sh|bash|curl|wget|nc|python[\d.]*)"/, 'spawned-shell', 60, 'high',
      'The file launched a shell or downloader',
      'It started another program instead of just doing its own work.');
    noteIf(/openat\([^)]*"\/etc\/(?:passwd|shadow|ssh)/, 'credential-read', 65, 'high',
      'The file read system credential files',
      'It opened /etc/passwd, /etc/shadow, or SSH material.');
    noteIf(/(?:chmod|fchmodat)\([^)]*07[0-7][0-7]/, 'permission-change', 30, 'medium',
      'The file changed permissions on something',
      'It made a file executable or world-writable.');
    noteIf(/unlink(?:at)?\(/, 'file-deletion', 25, 'medium',
      'The file deleted things', 'It removed files while running.');
    noteIf(/ptrace\(|process_vm_writev\(/, 'process-injection', 70, 'critical',
      'The file tried to attach to other processes',
      'ptrace or cross-process memory writes are how code gets injected into other programs.');

    const touchedFiles = touched.split('\n').map((s) => s.trim()).filter(Boolean);
    const persistence = touchedFiles.filter((f) => /\/(?:etc\/(?:cron|systemd|init|rc\.local|profile)|\.bashrc|\.profile|autostart|LaunchAgents)/.test(f));
    if (persistence.length) {
      behaviours.push('persistence');
      signals.push(signal('detonation.persistence', 70, 'critical', 'The file installed itself to run again later',
        `It wrote to ${persistence.slice(0, 3).join(', ')}. That is how malware survives a reboot.`));
    }

    fs.rmSync(workDir, { recursive: true, force: true });

    const report = {
      available: true,
      executed: true,
      runtime,
      image: IMAGE,
      durationMs: Date.now() - started,
      exitCode: result.code,
      behaviours,
      filesTouched: touchedFiles.slice(0, 40),
      stdout: stdout.slice(0, 4000),
      stderr: stderr.slice(0, 2000),
      signals,
    };

    if (this.events) {
      this.events.record({
        type: 'detonation',
        file: name,
        behaviours,
        signalCount: signals.length,
        durationMs: report.durationMs,
      });
    }
    return report;
  }
}

module.exports = { Detonator };
