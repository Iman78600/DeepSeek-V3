'use strict';
/**
 * Static file analysis. Runs on every download before you are allowed to
 * touch it. No execution happens here - this is the "look at it through
 * glass" stage. Detonation (optional, container-based) lives in detonate.js.
 *
 * Pure Node, no Electron, so `npm run scan -- <file>` and the tests use the
 * exact same code path the browser does.
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const zlib = require('zlib');

const { DANGEROUS_EXTENSIONS, ARCHIVE_EXTENSIONS, entropy } = require('../soc/heuristics/url-heuristics');

function signal(id, score, severity, title, detail) {
  return { id, score, severity, title, detail };
}

// ---------------------------------------------------------------------------
// File type identification by content, not by name
// ---------------------------------------------------------------------------

const MAGIC = [
  { type: 'pe',     ext: ['.exe', '.dll', '.scr', '.sys', '.cpl', '.ocx', '.msi'], test: (b) => b[0] === 0x4d && b[1] === 0x5a },
  { type: 'elf',    ext: ['.elf', '.so', '.bin', '.o', ''], test: (b) => b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 },
  { type: 'macho',  ext: ['.dylib', '.bundle', ''], test: (b) => [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe].includes(b.readUInt32BE(0)) || b.readUInt32LE(0) === 0xfeedfacf },
  { type: 'zip',    ext: ['.zip', '.jar', '.apk', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.epub', '.ipa', '.xpi', '.war', '.aar', '.crx'], test: (b) => b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05 || b[2] === 0x07) },
  { type: 'ole',    ext: ['.doc', '.xls', '.ppt', '.msg', '.msi'], test: (b) => b.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) },
  { type: 'rar',    ext: ['.rar'], test: (b) => b.subarray(0, 6).toString('binary') === 'Rar!\x1a\x07' },
  { type: '7z',     ext: ['.7z'], test: (b) => b.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) },
  { type: 'gzip',   ext: ['.gz', '.tgz', '.svgz'], test: (b) => b[0] === 0x1f && b[1] === 0x8b },
  { type: 'bzip2',  ext: ['.bz2'], test: (b) => b.subarray(0, 3).toString() === 'BZh' },
  { type: 'xz',     ext: ['.xz'], test: (b) => b.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) },
  { type: 'cab',    ext: ['.cab'], test: (b) => b.subarray(0, 4).toString() === 'MSCF' },
  { type: 'pdf',    ext: ['.pdf'], test: (b) => b.subarray(0, 5).toString() === '%PDF-' },
  { type: 'rtf',    ext: ['.rtf'], test: (b) => b.subarray(0, 5).toString() === '{\\rtf' },
  { type: 'iso',    ext: ['.iso'], test: (b, buf) => buf.length > 32774 && buf.subarray(32769, 32774).toString() === 'CD001' },
  { type: 'lnk',    ext: ['.lnk'], test: (b) => b.readUInt32LE(0) === 0x0000004c && b.subarray(4, 8).equals(Buffer.from([0x01, 0x14, 0x02, 0x00])) },
  { type: 'class',  ext: ['.class'], test: (b) => b.readUInt32BE(0) === 0xcafebabe },
  { type: 'dmg',    ext: ['.dmg'], test: (b) => b.subarray(0, 4).toString() === 'koly' },
  { type: 'deb',    ext: ['.deb'], test: (b) => b.subarray(0, 8).toString() === '!<arch>\n' },
  { type: 'rpm',    ext: ['.rpm'], test: (b) => b.subarray(0, 4).equals(Buffer.from([0xed, 0xab, 0xee, 0xdb])) },
  { type: 'png',    ext: ['.png'], test: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  { type: 'jpeg',   ext: ['.jpg', '.jpeg'], test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { type: 'gif',    ext: ['.gif'], test: (b) => b.subarray(0, 3).toString() === 'GIF' },
  { type: 'webp',   ext: ['.webp'], test: (b) => b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP' },
  { type: 'mp4',    ext: ['.mp4', '.m4v', '.mov'], test: (b) => b.subarray(4, 8).toString() === 'ftyp' },
  { type: 'wasm',   ext: ['.wasm'], test: (b) => b.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d])) },
];

function identify(buf) {
  const head = buf.subarray(0, 64);
  if (head.length < 8) return { type: 'unknown', ext: [] };
  for (const m of MAGIC) {
    try { if (m.test(head, buf)) return m; } catch { /* short buffer */ }
  }
  // Text-ish?
  const sample = buf.subarray(0, 4096);
  let printable = 0;
  for (const byte of sample) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127)) printable++;
  }
  if (sample.length && printable / sample.length > 0.9) return { type: 'text', ext: [] };
  return { type: 'unknown', ext: [] };
}

// ---------------------------------------------------------------------------
// Filename tricks
// ---------------------------------------------------------------------------

const RTL_OVERRIDE = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;

function checkFilename(filename) {
  const signals = [];
  const name = path.basename(String(filename || ''));
  const lower = name.toLowerCase();

  if (RTL_OVERRIDE.test(name)) {
    const cleaned = name.replace(RTL_OVERRIDE, '');
    signals.push(signal('file.rtl-override', 85, 'critical', 'Filename uses a right-to-left override character',
      `The name is displayed one way and stored another. Without the trick characters it is "${cleaned}". This is used to make "invoice[U+202E]gpj.exe" look like "invoice.jpg".`));
  }

  // Double extension: report.pdf.exe
  const segments = lower.split('.');
  if (segments.length >= 3) {
    const last = `.${segments[segments.length - 1]}`;
    const prior = `.${segments[segments.length - 2]}`;
    const docLike = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', '.csv', '.zip'];
    if (DANGEROUS_EXTENSIONS.includes(last) && docLike.includes(prior)) {
      signals.push(signal('file.double-extension', 80, 'critical', `Double extension "${prior}${last}"`,
        `The file pretends to be a ${prior.slice(1).toUpperCase()} but the real extension is ${last}, which runs as a program.`));
    }
  }

  if (name.length > 100) {
    signals.push(signal('file.long-name', 20, 'low', 'Very long filename',
      `${name.length} characters. Long names push the real extension off the end of the screen.`));
  }
  if (/\s{5,}\.[a-z0-9]{2,4}$/i.test(name)) {
    signals.push(signal('file.space-padding', 60, 'high', 'Filename padded with spaces',
      'A run of spaces before the extension hides the real file type in most file managers.'));
  }

  const ext = (lower.match(/\.[a-z0-9]{1,8}$/) || [''])[0];
  if (DANGEROUS_EXTENSIONS.includes(ext)) {
    signals.push(signal('file.executable-extension', 35, 'medium', `Executable file type (${ext})`,
      'Opening this runs code with your account\'s permissions.'));
  }
  return { signals, ext, name };
}

// ---------------------------------------------------------------------------
// Format-specific inspection
// ---------------------------------------------------------------------------

const SUSPICIOUS_STRINGS = [
  { re: /powershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc|ncodedcommand)?\s/i, score: 70, label: 'PowerShell encoded command' },
  { re: /-nop\b|-noprofile\b|-windowstyle\s+hidden|-w\s+hidden/i, score: 45, label: 'hidden PowerShell window flags' },
  { re: /Invoke-(?:Expression|WebRequest|RestMethod|Mimikatz|Shellcode)/i, score: 55, label: 'PowerShell download/execute cmdlet' },
  { re: /\bIEX\s*\(/i, score: 45, label: 'IEX (Invoke-Expression) shorthand' },
  { re: /DownloadString|DownloadFile|Net\.WebClient/i, score: 50, label: 'in-process file download' },
  { re: /certutil(?:\.exe)?\s+-(?:urlcache|decode|encode)/i, score: 60, label: 'certutil abused as a downloader' },
  { re: /bitsadmin(?:\.exe)?\s+\/transfer/i, score: 60, label: 'bitsadmin transfer' },
  { re: /regsvr32(?:\.exe)?\s+.*(?:scrobj|\/i:http)/i, score: 65, label: 'regsvr32 remote scriptlet (Squiblydoo)' },
  { re: /mshta(?:\.exe)?\s+(?:https?|javascript|vbscript)/i, score: 65, label: 'mshta executing remote content' },
  { re: /rundll32(?:\.exe)?\s+.*,\s*\w+/i, score: 35, label: 'rundll32 export call' },
  { re: /wmic\s+process\s+call\s+create/i, score: 55, label: 'WMIC process creation' },
  { re: /schtasks(?:\.exe)?\s+\/create/i, score: 45, label: 'scheduled task creation (persistence)' },
  { re: /reg(?:\.exe)?\s+add\s+.*(?:\\Run\b|CurrentVersion\\Run)/i, score: 55, label: 'Run-key persistence' },
  { re: /vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no/i, score: 90, label: 'shadow-copy destruction (ransomware behaviour)' },
  { re: /cipher\s+\/w|format\s+[a-z]:\s*\/|del\s+\/[sf]\s+\/q\s+[a-z]:\\\*/i, score: 70, label: 'mass file destruction command' },
  { re: /(?:curl|wget)\s+[^\n|]{0,120}\|\s*(?:ba)?sh/i, score: 70, label: 'download piped straight into a shell' },
  { re: /chmod\s+\+x\b[\s\S]{0,80}\.\//i, score: 40, label: 'make-executable-then-run' },
  { re: /base64\s+(?:-d|--decode)[\s\S]{0,40}\|\s*(?:ba)?sh/i, score: 70, label: 'base64 decoded into a shell' },
  { re: /nc\s+-e\s+\/bin\/(?:ba)?sh|bash\s+-i\s*>&\s*\/dev\/tcp\//i, score: 85, label: 'reverse shell' },
  { re: /CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection|QueueUserAPC/i, score: 60, label: 'process-injection API' },
  { re: /SetWindowsHookEx|GetAsyncKeyState|GetKeyboardState/i, score: 50, label: 'keylogging API' },
  { re: /IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString/i, score: 35, label: 'anti-debugging API' },
  { re: /(?:VMware|VirtualBox|QEMU|Xen|Sandboxie|Wine)\b[\s\S]{0,60}(?:detect|check|present)/i, score: 40, label: 'virtual-machine detection' },
  { re: /(?:bcrypt|CryptEncrypt|AES_set_encrypt_key|CryptGenKey)[\s\S]{0,200}(?:\.locked|\.encrypted|README.*DECRYPT)/i, score: 80, label: 'ransomware encryption pattern' },
  { re: /(?:your files (?:have been|are) encrypted|pay(?:ment)? (?:in )?bitcoin to (?:decrypt|recover))/i, score: 95, label: 'ransom note text' },
  { re: /\.onion\b/i, score: 30, label: 'Tor hidden-service address' },
  { re: /(?:api\.telegram\.org\/bot|discord(?:app)?\.com\/api\/webhooks)/i, score: 55, label: 'Telegram/Discord exfiltration channel' },
  { re: /(?:Local\\Google\\Chrome\\User Data|Login Data|cookies\.sqlite|key4\.db|logins\.json)/i, score: 65, label: 'browser credential store path (infostealer)' },
  { re: /(?:wallet\.dat|exodus|electrum|metamask|keystore)/i, score: 45, label: 'cryptocurrency wallet path' },
];

function scanStrings(buf, limitBytes = 8 * 1024 * 1024) {
  const slice = buf.subarray(0, limitBytes);
  const ascii = slice.toString('latin1');
  // Also pull UTF-16LE strings, where Windows malware hides its commands.
  const utf16 = slice.toString('utf16le');
  const haystack = `${ascii}\n${utf16}`;
  const hits = [];
  for (const s of SUSPICIOUS_STRINGS) {
    const m = haystack.match(s.re);
    if (m) hits.push({ ...s, sample: m[0].slice(0, 160) });
  }
  return hits;
}

function findEmbeddedNetworkIndicators(buf, limit = 4 * 1024 * 1024) {
  const text = buf.subarray(0, limit).toString('latin1');
  const urls = [...new Set((text.match(/https?:\/\/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,200}/g) || []))];
  const ips = [...new Set((text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))]
    .filter((ip) => ip.split('.').every((o) => Number(o) <= 255))
    .filter((ip) => !/^(?:0\.|255\.|1\.0\.0\.|127\.0\.0\.1$)/.test(ip));
  const onion = [...new Set((text.match(/\b[a-z2-7]{16,56}\.onion\b/g) || []))];
  return { urls: urls.slice(0, 40), ips: ips.slice(0, 40), onion: onion.slice(0, 10) };
}

function inspectPe(buf) {
  const signals = [];
  const info = { sections: [], imports: [] };
  try {
    const peOffset = buf.readUInt32LE(0x3c);
    if (peOffset <= 0 || peOffset + 24 > buf.length) return { signals, info };
    if (buf.readUInt32LE(peOffset) !== 0x00004550) return { signals, info }; // "PE\0\0"

    const machine = buf.readUInt16LE(peOffset + 4);
    const numSections = buf.readUInt16LE(peOffset + 6);
    const timestamp = buf.readUInt32LE(peOffset + 8);
    const optSize = buf.readUInt16LE(peOffset + 20);
    const characteristics = buf.readUInt16LE(peOffset + 22);
    info.machine = { 0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'arm', 0xaa64: 'arm64' }[machine] || `0x${machine.toString(16)}`;
    info.isDll = Boolean(characteristics & 0x2000);
    info.compiledAt = timestamp ? new Date(timestamp * 1000).toISOString() : null;

    if (timestamp) {
      const ageDays = (Date.now() - timestamp * 1000) / 86400000;
      if (ageDays < 3 && ageDays > -1) {
        signals.push(signal('pe.fresh-build', 30, 'medium', 'Compiled in the last few days',
          `The compile timestamp is ${info.compiledAt}. Freshly built binaries have no reputation anywhere yet.`));
      }
      if (ageDays < -1) {
        signals.push(signal('pe.future-timestamp', 40, 'medium', 'Compile timestamp is in the future',
          'The header was tampered with to defeat reputation systems.'));
      }
    }

    const sectionTable = peOffset + 24 + optSize;
    for (let i = 0; i < Math.min(numSections, 32); i++) {
      const off = sectionTable + i * 40;
      if (off + 40 > buf.length) break;
      const name = buf.subarray(off, off + 8).toString('latin1').replace(/\0+$/, '');
      const virtualSize = buf.readUInt32LE(off + 8);
      const rawSize = buf.readUInt32LE(off + 16);
      const rawPtr = buf.readUInt32LE(off + 20);
      const flags = buf.readUInt32LE(off + 36);
      const writable = Boolean(flags & 0x80000000);
      const executable = Boolean(flags & 0x20000000);
      let sectionEntropy = null;
      if (rawSize > 0 && rawPtr + rawSize <= buf.length && rawSize < 20 * 1024 * 1024) {
        sectionEntropy = entropy(buf.subarray(rawPtr, rawPtr + Math.min(rawSize, 262144)).toString('latin1'));
      }
      info.sections.push({ name, virtualSize, rawSize, entropy: sectionEntropy, writable, executable });

      if (executable && writable) {
        signals.push(signal('pe.wx-section', 45, 'high', `Section "${name}" is writable and executable`,
          'Code that rewrites itself at runtime is the defining trait of a packer or unpacking stub.'));
      }
      if (sectionEntropy !== null && sectionEntropy > 7.2 && rawSize > 4096) {
        signals.push(signal('pe.high-entropy-section', 40, 'medium', `Section "${name}" looks packed or encrypted`,
          `Entropy ${sectionEntropy.toFixed(2)} of a maximum 8.0. Normal code sits around 6. This content is compressed or encrypted so scanners cannot read it.`));
      }
      if (rawSize === 0 && virtualSize > 65536) {
        signals.push(signal('pe.virtual-only-section', 35, 'medium', `Section "${name}" is empty on disk but large in memory`,
          'The real payload is written into that space at runtime. Classic unpacking stub layout.'));
      }
      if (/^(?:UPX|\.aspack|\.themida|\.vmp|\.enigma|\.petite|\.mpress|\.nsp)/i.test(name)) {
        signals.push(signal('pe.known-packer', 45, 'high', `Packed with ${name}`,
          'The real code is compressed and only revealed while running, which prevents static inspection.'));
      }
    }

    const overlayStart = info.sections.reduce((max, s) => Math.max(max, s.rawSize ? 0 : 0), 0);
    void overlayStart;

    // Import hints: look for the import table's DLL name strings.
    const asciiHead = buf.subarray(0, Math.min(buf.length, 2 * 1024 * 1024)).toString('latin1');
    const dlls = [...new Set((asciiHead.match(/[A-Za-z0-9_.-]{3,30}\.dll/gi) || []).map((s) => s.toLowerCase()))];
    info.imports = dlls.slice(0, 40);
    const spooky = dlls.filter((d) => ['wininet.dll', 'winhttp.dll', 'ws2_32.dll', 'urlmon.dll', 'advapi32.dll', 'crypt32.dll', 'bcrypt.dll', 'psapi.dll', 'dbghelp.dll'].includes(d));
    if (dlls.length > 0 && dlls.length <= 3 && spooky.length) {
      signals.push(signal('pe.thin-imports', 35, 'medium', 'Almost no imports',
        `Only ${dlls.length} DLL(s) referenced (${dlls.join(', ')}). Packed binaries resolve their real imports at runtime to stay invisible.`));
    }
    if (!/\bMicrosoft\b/i.test(asciiHead) && /wsock32|ws2_32/i.test(asciiHead) && /CreateRemoteThread|VirtualAlloc/i.test(asciiHead)) {
      signals.push(signal('pe.network-injector', 50, 'high', 'Networking plus process injection',
        'The binary both talks to the network and writes into other processes.'));
    }
    if (!/\.rsrc/.test(info.sections.map((s) => s.name).join(' '))) {
      signals.push(signal('pe.no-resources', 15, 'low', 'No resource section',
        'Legitimate Windows applications almost always carry icons and version information.'));
    }
  } catch { /* malformed PE, other signals will cover it */ }
  return { signals, info };
}

function inspectZip(buf, filename) {
  const signals = [];
  const info = { entries: [], encrypted: false };
  // Walk the central directory from the End of Central Directory record.
  try {
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 66000); i--) {
      if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) return { signals, info };
    const count = buf.readUInt16LE(eocd + 10);
    let off = buf.readUInt32LE(eocd + 16);

    for (let i = 0; i < Math.min(count, 3000); i++) {
      if (off + 46 > buf.length || buf.readUInt32LE(off) !== 0x02014b50) break;
      const flags = buf.readUInt16LE(off + 8);
      const compSize = buf.readUInt32LE(off + 20);
      const uncompSize = buf.readUInt32LE(off + 24);
      const nameLen = buf.readUInt16LE(off + 28);
      const extraLen = buf.readUInt16LE(off + 30);
      const commentLen = buf.readUInt16LE(off + 32);
      const name = buf.subarray(off + 46, off + 46 + nameLen).toString('utf8');
      const encrypted = Boolean(flags & 0x1);
      if (encrypted) info.encrypted = true;
      info.entries.push({ name, compSize, uncompSize, encrypted });
      off += 46 + nameLen + extraLen + commentLen;
    }
  } catch { /* truncated archive */ }

  const names = info.entries.map((e) => e.name);
  const lower = names.map((n) => n.toLowerCase());

  if (info.encrypted) {
    signals.push(signal('zip.encrypted', 45, 'high', 'Password-protected archive',
      'Shadow cannot look inside an encrypted archive, and neither can any antivirus. Attackers put the password in the email body for exactly this reason.'));
  }

  // Office macro documents
  const isOfficeExt = /\.(?:docx?m?|xlsx?m?|pptx?m?|dotm|xltm|potm)$/i.test(filename || '');
  if (lower.some((n) => n.includes('vbaproject.bin'))) {
    signals.push(signal('zip.macro', 75, 'critical', 'Document contains VBA macros',
      'This Office file carries embedded code (vbaProject.bin). Macro documents are the most common way business machines get infected.'));
  }
  if (lower.some((n) => n.endsWith('.xlm') || n.includes('macrosheet'))) {
    signals.push(signal('zip.xl4-macro', 80, 'critical', 'Excel 4.0 macro sheet',
      'XLM macros are an obsolete format kept alive almost entirely by malware.'));
  }
  if (isOfficeExt && lower.some((n) => n.includes('externallink') || n.includes('oleobject'))) {
    signals.push(signal('zip.external-link', 40, 'medium', 'Document links to external content',
      'Opening it fetches remote data, which is how template-injection attacks pull down a payload.'));
  }

  // Executables inside archives
  const exeInside = names.filter((n) => DANGEROUS_EXTENSIONS.includes(path.extname(n).toLowerCase()));
  if (exeInside.length) {
    signals.push(signal('zip.executable-inside', 55, 'high', `Archive contains ${exeInside.length} executable file(s)`,
      `Including: ${exeInside.slice(0, 5).join(', ')}. Archives are used to get executables past mail and web filters.`));
  }
  const lnkInside = names.filter((n) => n.toLowerCase().endsWith('.lnk'));
  if (lnkInside.length) {
    signals.push(signal('zip.lnk-inside', 70, 'critical', 'Archive contains a Windows shortcut (.lnk)',
      'Shortcuts look like documents but run whatever command is hidden inside them. This is a top malware delivery method.'));
  }

  // Zip-slip path traversal
  const traversal = names.filter((n) => n.includes('../') || n.includes('..\\') || /^([a-z]:)?[\\/]/i.test(n));
  if (traversal.length) {
    signals.push(signal('zip.path-traversal', 75, 'critical', 'Archive writes outside its own folder',
      `Entries like "${traversal[0]}" escape the extraction directory and can overwrite system files ("Zip Slip").`));
  }

  // Zip bomb
  const totalComp = info.entries.reduce((s, e) => s + (e.compSize || 0), 0);
  const totalUncomp = info.entries.reduce((s, e) => s + (e.uncompSize || 0), 0);
  if (totalComp > 0 && totalUncomp / totalComp > 200 && totalUncomp > 50 * 1024 * 1024) {
    signals.push(signal('zip.bomb', 60, 'high', 'Decompression bomb',
      `Expands ${Math.round(totalUncomp / totalComp)}x to ${(totalUncomp / 1048576).toFixed(0)} MB. Designed to exhaust disk or memory.`));
  }

  // Nested archives hide payloads from scanners
  const nested = names.filter((n) => ARCHIVE_EXTENSIONS.includes(path.extname(n).toLowerCase()));
  if (nested.length >= 1 && info.entries.length <= 3) {
    signals.push(signal('zip.nested-archive', 35, 'medium', 'Archive inside an archive',
      `Contains ${nested.join(', ')}. Layering archives is done to blind scanners that only look one level deep.`));
  }

  // JAR/APK with an obviously wrong extension
  if (lower.includes('meta-inf/manifest.mf') && !/\.(?:jar|war|apk|aar)$/i.test(filename || '')) {
    signals.push(signal('zip.hidden-jar', 55, 'high', 'This is really a Java archive',
      `"${path.basename(filename || '')}" is a runnable JAR wearing a different extension.`));
  }
  if (lower.includes('androidmanifest.xml')) {
    info.android = true;
  }

  return { signals, info };
}

function inspectOle(buf) {
  const signals = [];
  const text = buf.toString('latin1');
  // OLE compound files store the VBA project in a stream literally named that.
  if (/V\0?B\0?A\0?P\0?r\0?o\0?j\0?e\0?c\0?t/i.test(text) || /\bAttribute VB_Name\b/i.test(text)) {
    signals.push(signal('ole.macro', 75, 'critical', 'Legacy Office document with macros',
      'The file embeds a VBA project. Old .doc/.xls formats run macros with very little friction.'));
  }
  if (/Auto_?Open|AutoExec|Document_Open|Workbook_Open|Auto_Close/i.test(text)) {
    signals.push(signal('ole.auto-exec', 85, 'critical', 'Macro runs the moment you open the file',
      'An auto-execute macro entry point (AutoOpen / Document_Open) is present. Just opening the document is enough.'));
  }
  if (/Shell\s*\(|WScript\.Shell|Scripting\.FileSystemObject|CreateObject\s*\(/i.test(text)) {
    signals.push(signal('ole.shell', 80, 'critical', 'Macro launches external programs',
      'The embedded code calls Shell / WScript.Shell, which starts other programs on your machine.'));
  }
  if (/Equation\.3|Package\b|OLE2Link|\x00E\x00q\x00u\x00a\x00t\x00i\x00o\x00n/i.test(text)) {
    signals.push(signal('ole.embedded-object', 50, 'high', 'Embedded OLE object',
      'Embedded objects (especially Equation Editor) are used to trigger memory-corruption exploits.'));
  }
  return { signals, info: {} };
}

function inspectPdf(buf) {
  const signals = [];
  let text = buf.toString('latin1');
  // Try to inflate object streams so obfuscated actions are visible.
  try {
    const streams = [...text.matchAll(/stream\r?\n([\s\S]{20,200000}?)\r?\nendstream/g)].slice(0, 40);
    for (const s of streams) {
      const raw = Buffer.from(s[1], 'latin1');
      if (raw[0] === 0x78) {
        try { text += `\n${zlib.inflateSync(raw).toString('latin1')}`; } catch { /* not flate */ }
      }
    }
  } catch { /* best effort */ }

  const has = (re) => re.test(text);
  if (has(/\/JavaScript|\/JS\b/)) {
    signals.push(signal('pdf.javascript', 55, 'high', 'PDF contains JavaScript',
      'PDFs are documents. Embedded scripts exist to exploit the reader or to fetch a second stage.'));
  }
  if (has(/\/OpenAction|\/AA\b/)) {
    signals.push(signal('pdf.auto-action', 60, 'high', 'PDF runs an action on open',
      '/OpenAction fires as soon as the document is displayed, with no click from you.'));
  }
  if (has(/\/Launch\b/)) {
    signals.push(signal('pdf.launch', 85, 'critical', 'PDF tries to launch a program',
      'A /Launch action starts an external executable from inside the document.'));
  }
  if (has(/\/EmbeddedFile|\/Filespec/)) {
    signals.push(signal('pdf.embedded-file', 50, 'high', 'PDF carries an embedded file',
      'Another file is hidden inside the PDF and can be extracted and run.'));
  }
  if (has(/\/RichMedia|\/Flash\b|\/3D\b/)) {
    signals.push(signal('pdf.rich-media', 40, 'medium', 'PDF embeds rich media',
      'Flash/3D annotations are a well-worn exploitation path.'));
  }
  if (has(/\/SubmitForm|\/URI\s*\(\s*https?:/)) {
    const uris = [...new Set((text.match(/\/URI\s*\(\s*(https?:\/\/[^)]{4,150})\)/g) || []).map((m) => m.replace(/^\/URI\s*\(\s*/, '').replace(/\)$/, '')))];
    if (uris.length) {
      signals.push(signal('pdf.external-link', 20, 'low', `PDF links out to ${uris.length} URL(s)`,
        `First: ${uris[0]}. Phishing PDFs are often nothing but a button to a credential page.`));
    }
  }
  if (has(/\/ObjStm/) && has(/\/Encrypt/)) {
    signals.push(signal('pdf.obfuscated', 30, 'medium', 'PDF structure is obfuscated',
      'Object streams plus encryption make the document deliberately hard to inspect.'));
  }
  return { signals, info: {} };
}

function inspectScript(buf, ext) {
  const signals = [];
  const text = buf.toString('utf8');
  const lines = text.split('\n');
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);

  if (longest > 3000) {
    signals.push(signal('script.minified-blob', 30, 'medium', 'Single enormous line of code',
      `The longest line is ${longest} characters. Dropper scripts are usually one packed line.`));
  }
  const h = entropy(text.slice(0, 65536));
  if (h > 5.2 && text.length > 2000) {
    signals.push(signal('script.high-entropy', 35, 'medium', 'Script content looks encoded',
      `Entropy ${h.toFixed(2)}. Readable source code sits well below this.`));
  }
  if (/^\s*(?:#!\s*\/bin\/(?:ba|z|k)?sh|#!\s*\/usr\/bin\/env)/.test(text) && /\|\s*(?:ba)?sh/.test(text)) {
    signals.push(signal('script.pipe-to-shell', 65, 'high', 'Shell script pipes remote content into a shell',
      'It downloads something and executes it immediately, with no chance to inspect it.'));
  }
  if (ext === '.hta' || /<hta:application/i.test(text)) {
    signals.push(signal('script.hta', 70, 'critical', 'HTML Application (.hta)',
      'HTAs are web pages that run with full local permissions. There is no sandbox.'));
  }
  return { signals, info: { lines: lines.length, longestLine: longest, entropy: h } };
}

// ---------------------------------------------------------------------------
// Main scan
// ---------------------------------------------------------------------------

/**
 * @param {string} filePath  path to the quarantined file
 * @param {object} [meta]    { originalName, sourceUrl, mimeType }
 */
async function scanFile(filePath, meta = {}) {
  const stat = fs.statSync(filePath);
  const originalName = meta.originalName || path.basename(filePath);

  const maxRead = 64 * 1024 * 1024;
  const buf = stat.size <= maxRead
    ? fs.readFileSync(filePath)
    : (() => {
        const fd = fs.openSync(filePath, 'r');
        const b = Buffer.alloc(maxRead);
        fs.readSync(fd, b, 0, maxRead, 0);
        fs.closeSync(fd);
        return b;
      })();

  const signals = [];
  const nameCheck = checkFilename(originalName);
  signals.push(...nameCheck.signals);

  const detected = identify(buf);
  const declaredExt = nameCheck.ext;

  // Extension vs. real content
  if (detected.type !== 'unknown' && detected.type !== 'text' && declaredExt) {
    const consistent = detected.ext.includes(declaredExt);
    if (!consistent) {
      const isExecutableContent = ['pe', 'elf', 'macho', 'lnk', 'class'].includes(detected.type);
      signals.push(signal('file.type-mismatch', isExecutableContent ? 80 : 40,
        isExecutableContent ? 'critical' : 'medium',
        `File claims to be "${declaredExt}" but is really ${detected.type.toUpperCase()}`,
        isExecutableContent
          ? `The content starts with a ${detected.type.toUpperCase()} executable header. Whatever the name says, this is a program.`
          : `Expected ${declaredExt}, found ${detected.type}. The name is misleading.`));
    }
  }
  if (detected.type === 'unknown' && stat.size > 1024) {
    const h = entropy(buf.subarray(0, 262144).toString('latin1'));
    if (h > 7.5) {
      signals.push(signal('file.encrypted-blob', 30, 'medium', 'File is encrypted or compressed with no recognisable header',
        `Entropy ${h.toFixed(2)} and no known file signature. Shadow cannot tell what this is.`));
    }
  }

  // Format-specific
  let formatInfo = {};
  if (detected.type === 'pe') { const r = inspectPe(buf); signals.push(...r.signals); formatInfo.pe = r.info; }
  else if (detected.type === 'zip') { const r = inspectZip(buf, originalName); signals.push(...r.signals); formatInfo.zip = { entryCount: r.info.entries.length, encrypted: r.info.encrypted, entries: r.info.entries.slice(0, 50) }; }
  else if (detected.type === 'ole') { const r = inspectOle(buf); signals.push(...r.signals); }
  else if (detected.type === 'pdf') { const r = inspectPdf(buf); signals.push(...r.signals); }
  else if (detected.type === 'text' || ['.js', '.ps1', '.sh', '.vbs', '.bat', '.cmd', '.hta', '.py', '.jse', '.wsf'].includes(declaredExt)) {
    const r = inspectScript(buf, declaredExt); signals.push(...r.signals); formatInfo.script = r.info;
  }
  else if (detected.type === 'lnk') {
    signals.push(signal('file.lnk', 70, 'critical', 'Windows shortcut file',
      'A .lnk looks like a document but silently runs a command line stored inside it.'));
  }
  else if (detected.type === 'iso' || detected.type === 'cab') {
    signals.push(signal('file.container-image', 35, 'medium', `Disk image / container (${detected.type})`,
      'Mounting an ISO strips the "downloaded from the internet" mark from everything inside it.'));
  }

  // Universal string scan
  const stringHits = scanStrings(buf);
  for (const hit of stringHits) {
    signals.push(signal(`strings.${hit.label.replace(/\s+/g, '-').toLowerCase()}`, hit.score,
      hit.score >= 70 ? 'critical' : hit.score >= 45 ? 'high' : 'medium',
      `Contains ${hit.label}`,
      `Matched: ${hit.sample.replace(/\s+/g, ' ').slice(0, 140)}`));
  }

  const network = findEmbeddedNetworkIndicators(buf);
  if (network.onion.length) {
    signals.push(signal('file.onion-c2', 45, 'high', 'Hard-coded Tor address',
      `Found ${network.onion[0]}. Malware uses hidden services so its control server cannot be taken down.`));
  }

  // Source context
  if (meta.sourceUrl) {
    const { ANONYMOUS_FILE_HOSTS } = require('../soc/data/tld-reputation');
    const { splitHost } = require('../soc/heuristics/url-heuristics');
    try {
      const host = new URL(meta.sourceUrl).hostname.toLowerCase();
      const reg = splitHost(host).registrable;
      if (ANONYMOUS_FILE_HOSTS.has(reg) || ANONYMOUS_FILE_HOSTS.has(host)) {
        signals.push(signal('file.anonymous-host', 30, 'medium', 'Downloaded from an anonymous file host',
          `${host} accepts uploads with no account and no accountability.`));
      }
      if (new URL(meta.sourceUrl).protocol === 'http:') {
        signals.push(signal('file.insecure-transport', 35, 'medium', 'Downloaded over plain HTTP',
          'The file could have been swapped in transit and you would not know.'));
      }
    } catch { /* ignore */ }
  }

  // MIME vs. content
  if (meta.mimeType) {
    const mt = String(meta.mimeType).toLowerCase();
    const claimsBenign = /^(?:image|text|audio|video)\//.test(mt) || mt.includes('pdf');
    if (claimsBenign && ['pe', 'elf', 'macho'].includes(detected.type)) {
      signals.push(signal('file.mime-lie', 70, 'critical', `Server said "${mt}" but sent an executable`,
        'The Content-Type header was chosen to slip past filters.'));
    }
  }

  const hashes = {
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
    sha1: crypto.createHash('sha1').update(buf).digest('hex'),
    md5: crypto.createHash('md5').update(buf).digest('hex'),
  };

  return {
    file: { path: filePath, name: originalName, size: stat.size, sizeHuman: humanSize(stat.size) },
    detectedType: detected.type,
    declaredExtension: declaredExt || null,
    hashes,
    network,
    formatInfo,
    signals,
    scannedAt: new Date().toISOString(),
    truncated: stat.size > maxRead,
  };
}

function humanSize(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = n; let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

module.exports = {
  scanFile, identify, checkFilename, inspectPe, inspectZip, inspectOle,
  inspectPdf, inspectScript, scanStrings, findEmbeddedNetworkIndicators,
  humanSize, MAGIC,
};
