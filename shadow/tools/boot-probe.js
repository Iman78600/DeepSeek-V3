'use strict';
/**
 * Boots the real Shadow app under Electron, waits for the window and the first
 * tab, reports what it found, then exits. Used to prove the application
 * actually starts, which unit tests cannot show.
 *
 *   xvfb-run -a npx electron tools/boot-probe.js
 */

const { app } = require('electron');
const fs = require('fs');
const path = require('path');

const OUT = process.env.SHADOW_PROBE_OUT || path.join(require('os').tmpdir(), 'shadow-probe.json');
const result = { started: false, errors: [], steps: [], views: [] };
const step = (s) => { result.steps.push(s); console.log('[probe]', s); };
const finish = (code) => {
  fs.writeFileSync(OUT, JSON.stringify(result, null, 2));
  app.exit(code);
};

process.on('uncaughtException', (e) => {
  result.errors.push(`uncaught: ${e.stack || e.message}`);
  finish(1);
});
process.on('unhandledRejection', (e) => {
  result.errors.push(`unhandled rejection: ${(e && e.stack) || e}`);
});

step('loading src/main/main.js');
require('../src/main/main.js');

app.whenReady().then(() => {
  step('app ready');
  setTimeout(async () => {
    const { BrowserWindow, session } = require('electron');
    const wins = BrowserWindow.getAllWindows();
    result.started = wins.length > 0;
    step(`browser windows: ${wins.length}`);

    if (wins[0]) {
      const win = wins[0];
      result.title = win.getTitle();
      step(`window title: "${result.title}"`);
      step(`child views: ${win.contentView.children.length}`);

      for (const view of win.contentView.children) {
        const wc = view.webContents;
        const url = wc.getURL();
        let heading = null;
        try {
          heading = await wc.executeJavaScript(
            'document.title + "|" + (document.querySelector("h1,#address") ? "ui-present" : "no-ui")', true);
        } catch (e) { result.errors.push(`executeJavaScript on ${url}: ${e.message}`); }
        result.views.push({ url, heading, crashed: wc.isCrashed() });
        step(`view ${path.basename(url) || url} -> ${heading}`);
      }

      try {
        const png = await win.webContents.capturePage();
        const shot = path.join(path.dirname(OUT), 'shadow-boot.png');
        fs.writeFileSync(shot, png.toPNG());
        result.screenshot = shot;
        step(`screenshot written: ${shot}`);
      } catch (e) { result.errors.push(`capturePage: ${e.message}`); }

      // Confirm the hardened session really is the one rendering pages.
      try {
        const s = session.fromPartition('persist:shadow-web');
        result.userAgent = s.getUserAgent();
        step(`web session UA: ${result.userAgent}`);
      } catch (e) { result.errors.push(`session: ${e.message}`); }
    }

    finish(result.started && result.errors.length === 0 ? 0 : 1);
  }, 7000);
});
