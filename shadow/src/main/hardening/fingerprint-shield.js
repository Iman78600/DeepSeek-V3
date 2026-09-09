'use strict';
/**
 * Fingerprint resistance, injected into the page's own JavaScript world.
 *
 * Why this is not in the preload: Shadow runs pages with contextIsolation on,
 * which is not negotiable. That means the preload gets its own JavaScript
 * context. It shares the DOM with the page, but `navigator`, `Date`,
 * `CanvasRenderingContext2D` and friends are separate wrapper objects. Patching
 * them in the preload would look right and protect nothing.
 *
 * So the shield is injected into the main world through the Chrome DevTools
 * Protocol (`Page.addScriptToEvaluateOnNewDocument`), which runs it before any
 * page script on every navigation, in every frame. The preload keeps the jobs
 * that genuinely belong in an isolated world: telemetry and IPC.
 *
 * The trade this makes: a page can detect that these functions are patched if
 * it looks hard enough. That is unavoidable. The goal is not to be invisible,
 * it is to make the readouts useless as a long-lived identifier.
 */

/**
 * @param {object} config  { canvasNoise, fontProtection, timingJitter, blockWebgl }
 * @param {number} seed    per-session, so noise is stable within a session and
 *                         different across sessions
 * @returns {string} JavaScript source to evaluate in the page's world
 */
function shieldSource(config, seed) {
  const cfg = JSON.stringify({
    canvasNoise: Boolean(config.canvasNoise),
    fontProtection: Boolean(config.fontProtection),
    timingJitter: Boolean(config.timingJitter),
    blockWebgl: Boolean(config.blockWebgl),
  });

  return `(() => {
'use strict';
if (window.__shadowShield) return;
Object.defineProperty(window, '__shadowShield', { value: true, enumerable: false });

const CFG = ${cfg};
const SEED = ${Number(seed) >>> 0};

function rand(n) {
  let x = (SEED ^ (n * 2654435761)) >>> 0;
  x ^= x << 13; x >>>= 0;
  x ^= x >> 17;
  x ^= x << 5; x >>>= 0;
  return x / 4294967296;
}

// Make a patched function look like the original to toString().
function disguise(patched, original) {
  try {
    Object.defineProperty(patched, 'name', { value: original.name, configurable: true });
    Object.defineProperty(patched, 'length', { value: original.length, configurable: true });
  } catch (e) {}
  return patched;
}

function hide(target, prop, value) {
  try {
    Object.defineProperty(target, prop, { get: () => value, configurable: true, enumerable: true });
  } catch (e) {}
}

// ---------------------------------------------------------------- canvas
if (CFG.canvasNoise && typeof CanvasRenderingContext2D !== 'undefined') {
  const perturb = (data, tag) => {
    const stride = 977;
    for (let i = tag % stride; i < data.length; i += stride) {
      if (rand(i + tag) > 0.5) data[i] = data[i] ^ 1;
    }
  };

  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = disguise(function getImageData() {
    const result = origGetImageData.apply(this, arguments);
    perturb(result.data, 1);
    return result;
  }, origGetImageData);

  const noisyCopy = (canvas, tag) => {
    try {
      const ctx = canvas.getContext('2d');
      if (!ctx || !canvas.width || !canvas.height) return;
      if (canvas.width * canvas.height > 8000000) return;
      const img = origGetImageData.call(ctx, 0, 0, canvas.width, canvas.height);
      perturb(img.data, tag);
      ctx.putImageData(img, 0, 0);
    } catch (e) {}
  };

  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = disguise(function toDataURL() {
    noisyCopy(this, 2);
    return origToDataURL.apply(this, arguments);
  }, origToDataURL);

  if (HTMLCanvasElement.prototype.toBlob) {
    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = disguise(function toBlob() {
      noisyCopy(this, 3);
      return origToBlob.apply(this, arguments);
    }, origToBlob);
  }

  // Audio fingerprinting reads back a rendered buffer and hashes it.
  if (typeof AnalyserNode !== 'undefined') {
    const origFloat = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = disguise(function (array) {
      origFloat.call(this, array);
      for (let i = 0; i < array.length; i += 71) array[i] += (rand(i + 7) - 0.5) * 1e-4;
    }, origFloat);
  }
  if (typeof AudioBuffer !== 'undefined') {
    const origChannel = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = disguise(function () {
      const data = origChannel.apply(this, arguments);
      for (let i = 0; i < data.length; i += 1319) data[i] += (rand(i + 11) - 0.5) * 1e-7;
      return data;
    }, origChannel);
  }
}

// ----------------------------------------------------------------- webgl
(() => {
  const mask = (proto) => {
    if (!proto) return;
    const origGetParameter = proto.getParameter;
    proto.getParameter = disguise(function getParameter(pname) {
      // UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL exist only to name
      // your exact GPU. Return a common, generic answer instead.
      if (pname === 37445) return 'Google Inc. (Intel)';
      if (pname === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
      return origGetParameter.call(this, pname);
    }, origGetParameter);

    const origGetExtension = proto.getExtension;
    proto.getExtension = disguise(function getExtension(name) {
      if (String(name) === 'WEBGL_debug_renderer_info') return null;
      return origGetExtension.call(this, name);
    }, origGetExtension);
  };
  if (typeof WebGLRenderingContext !== 'undefined') mask(WebGLRenderingContext.prototype);
  if (typeof WebGL2RenderingContext !== 'undefined') mask(WebGL2RenderingContext.prototype);
})();

// -------------------------------------------------------------- readouts
hide(navigator, 'hardwareConcurrency', 8);
hide(navigator, 'deviceMemory', 8);
hide(navigator, 'maxTouchPoints', 0);
hide(navigator, 'webdriver', false);
hide(navigator, 'doNotTrack', '1');
hide(navigator, 'globalPrivacyControl', true);
hide(navigator, 'languages', Object.freeze(['en-US', 'en']));
hide(navigator, 'plugins', Object.freeze([]));
hide(navigator, 'mimeTypes', Object.freeze([]));

// Pure tracking surface with no legitimate use worth the cost.
try { delete Navigator.prototype.getBattery; } catch (e) {}
hide(navigator, 'connection', undefined);
hide(navigator, 'getBattery', undefined);

// Report the window, not the monitor: multi-monitor setups and unusual
// resolutions are otherwise a strong identifier.
hide(screen, 'availWidth', window.innerWidth || screen.width);
hide(screen, 'availHeight', window.innerHeight || screen.height);
hide(screen, 'availLeft', 0);
hide(screen, 'availTop', 0);
hide(screen, 'colorDepth', 24);
hide(screen, 'pixelDepth', 24);

// ------------------------------------------------------------------ fonts
if (CFG.fontProtection && typeof CanvasRenderingContext2D !== 'undefined') {
  // The classic trick measures a string in many fonts and uses the set that
  // render differently as an identifier. Rounding to whole pixels collapses
  // most of that signal.
  const origMeasureText = CanvasRenderingContext2D.prototype.measureText;
  CanvasRenderingContext2D.prototype.measureText = disguise(function measureText(text) {
    const m = origMeasureText.call(this, text);
    return new Proxy(m, {
      get(target, prop) {
        const v = Reflect.get(target, prop);
        return typeof v === 'number' ? Math.round(v) : v;
      },
    });
  }, origMeasureText);

  for (const prop of ['offsetWidth', 'offsetHeight']) {
    const desc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, prop);
    if (desc && desc.get) {
      Object.defineProperty(HTMLElement.prototype, prop, {
        get() { return Math.round(desc.get.call(this)); },
        configurable: true,
      });
    }
  }

  if (document.fonts && document.fonts.check) {
    const origCheck = document.fonts.check.bind(document.fonts);
    document.fonts.check = disguise(function check(font, text) {
      const generic = /(sans-serif|serif|monospace|Arial|Helvetica|Times|Courier|Georgia|Verdana)/i;
      return generic.test(String(font)) ? origCheck(font, text) : false;
    }, origCheck);
  }
}

// ----------------------------------------------------------------- timing
if (CFG.timingJitter) {
  const origNow = performance.now.bind(performance);
  performance.now = disguise(function now() {
    return Math.floor(origNow() / 0.1) * 0.1;
  }, origNow);

  const origDateNow = Date.now.bind(Date);
  Date.now = disguise(function now() {
    return Math.floor(origDateNow() / 2) * 2;
  }, origDateNow);
}
})();`;
}

module.exports = { shieldSource };
