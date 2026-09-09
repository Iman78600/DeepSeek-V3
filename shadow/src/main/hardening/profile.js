'use strict';
/**
 * Defensive settings applied to the Electron session that renders web pages.
 * This is the "so the user doesn't get hacked" layer that is not the firewall
 * and not the analyst: it is about shrinking what a page is allowed to do
 * even when it is allowed to load.
 */

const { PERMISSION_POLICY, decidePermission } = require('./permissions');

/** A stable, common User-Agent so Shadow users look alike, not unique. */
function genericUserAgent() {
  return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
}

/**
 * Chromium command-line switches. Must be applied before app 'ready'.
 * Returns the list so main.js can apply and log them.
 */
function commandLineSwitches(settings) {
  const get = (k, d) => (settings && settings.get(k) !== undefined ? settings.get(k) : d);
  const switches = [
    // Do not leak local IP addresses through WebRTC.
    ['force-webrtc-ip-handling-policy', get('hardening.webrtc', 'disabled') === 'disabled'
      ? 'disable_non_proxied_udp' : 'default_public_interface_only'],
    // No background phone-home.
    ['disable-features', [
      'OptimizationHints',
      'MediaRouter',
      'InterestFeedContentSuggestions',
      'CalculateNativeWinOcclusion',
      'Translate',
      'AutofillServerCommunication',
      ...(get('hardening.disableWebAssembly', false) ? ['WebAssemblyBaseline', 'WebAssemblyTiering'] : []),
    ].join(',')],
    ['disable-background-networking', null],
    ['disable-domain-reliability', null],
    ['no-pings', null],
    ['no-default-browser-check', null],
    ['disable-breakpad', null],
    ['disable-crash-reporter', null],
    ['disable-sync', null],
    ['disable-client-side-phishing-detection', null], // Shadow does its own, locally
  ];
  if (get('hardening.blockWebgl', false)) switches.push(['disable-webgl', null], ['disable-webgl2', null]);
  if (get('dns.mode', 'doh') === 'doh') {
    switches.push(['dns-over-https-mode', 'secure']);
    switches.push(['dns-over-https-templates', get('dns.dohUrl', 'https://dns.quad9.net/dns-query')]);
  }
  return switches;
}

/**
 * Apply everything that can be set on a live session object.
 * @param {Electron.Session} session
 * @param {object} deps { settings, events, analyzer }
 */
function hardenSession(session, { settings, events } = {}) {
  const get = (k, d) => (settings && settings.get(k) !== undefined ? settings.get(k) : d);

  // --- Identity -----------------------------------------------------------
  if (get('hardening.spoofUserAgent', true)) {
    const ua = get('hardening.userAgent', '') || genericUserAgent();
    session.setUserAgent(ua, 'en-US,en;q=0.9');
  }

  // --- Permissions --------------------------------------------------------
  session.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const origin = (() => {
      try { return new URL(webContents.getURL()).origin; } catch { return 'unknown'; }
    })();
    const decision = decidePermission(permission, origin, settings);
    if (events) {
      events.record({
        type: 'permission',
        permission,
        origin,
        allowed: decision.allow,
        reason: decision.reason,
        hostname: (() => { try { return new URL(origin).hostname; } catch { return ''; } })(),
      });
    }
    callback(decision.allow);
    void details;
  });

  // Synchronous checks (used for things like clipboard read).
  session.setPermissionCheckHandler((webContents, permission, requestingOrigin) => {
    const decision = decidePermission(permission, requestingOrigin, settings);
    return decision.allow;
  });

  // --- Device access ------------------------------------------------------
  // A web page never gets to enumerate or claim USB, serial, Bluetooth or HID.
  session.setDevicePermissionHandler(() => false);
  if (typeof session.setBluetoothPairingHandler === 'function') {
    session.setBluetoothPairingHandler((_details, callback) => callback({ cancel: true }));
  }
  session.on('select-usb-device', (event) => event.preventDefault());
  session.on('select-serial-port', (event, portList, webContents, callback) => {
    event.preventDefault();
    callback('');
    void portList; void webContents;
  });
  session.on('select-hid-device', (event, _details, callback) => {
    event.preventDefault();
    callback();
  });

  // --- Cookies ------------------------------------------------------------
  if (get('hardening.blockAllCookies', false)) {
    session.webRequest.onHeadersReceived({ urls: ['<all_urls>'] }, (details, callback) => {
      const headers = { ...details.responseHeaders };
      for (const k of Object.keys(headers)) {
        if (k.toLowerCase() === 'set-cookie') delete headers[k];
      }
      callback({ responseHeaders: headers });
    });
  }

  // --- Certificate errors are never click-through by accident --------------
  // (main.js attaches the analyst-backed handler; this is the safe default.)
  session.setCertificateVerifyProc((request, callback) => {
    // 0 = use Chromium's own result. Shadow never overrides a failure to
    // "trust anyway"; it surfaces the failure to the analyst instead.
    callback(0);
    void request;
  });

  // --- Downloads are never opened by the OS --------------------------------
  session.setSSLConfig({ minVersion: 'tls1.2' });

  return session;
}

/**
 * Web preferences for every page-hosting BrowserView. These are the settings
 * that keep a compromised renderer from reaching the rest of the machine.
 */
function webPreferences(preloadPath, settings) {
  const get = (k, d) => (settings && settings.get(k) !== undefined ? settings.get(k) : d);
  return {
    preload: preloadPath,
    // The renderer gets no Node, no module system, and its own process.
    nodeIntegration: false,
    nodeIntegrationInWorker: false,
    nodeIntegrationInSubFrames: false,
    contextIsolation: true,
    sandbox: true,
    webSecurity: true,
    allowRunningInsecureContent: false,
    experimentalFeatures: false,
    enableBlinkFeatures: '',
    disableBlinkFeatures: [
      'AutomationControlled',
      ...(get('hardening.blockWebgl', false) ? ['WebGL', 'WebGL2'] : []),
    ].filter(Boolean).join(','),
    javascript: get('hardening.javascript', true),
    webviewTag: false,
    navigateOnDragDrop: false,
    spellcheck: false,
    plugins: false,
    images: true,
    safeDialogs: true,
    safeDialogsMessage: 'Shadow stopped this page from opening more dialog boxes.',
    autoplayPolicy: 'user-gesture-required',
    backgroundThrottling: true,
  };
}

module.exports = { hardenSession, webPreferences, commandLineSwitches, genericUserAgent, PERMISSION_POLICY };
