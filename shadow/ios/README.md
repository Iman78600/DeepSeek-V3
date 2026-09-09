# Shadow on iPhone

Three ways to get Shadow's protection onto an iPhone, in the order of how much
work they cost you.

| | What you get | What it costs |
|---|---|---|
| **1. The web app** | The analyst: check any link, scan any file | Nothing. Open a link, add to Home Screen |
| **2. Content blocker** | Blocklists applied inside Safari itself | A Mac, Xcode, a free Apple ID |
| **3. The native app** | A real browser: navigation gate, deep page scan, fingerprint shield, download sandbox | A Mac, Xcode, and $99/year to keep it installed |

**Start with 1.** It is free, immediate, and covers the threat you actually
meet on a phone, which is a link someone sent you.

---

## The honest constraint

Apple requires every browser on iOS to use WebKit, its own engine. Outside the
EU there is no exception. That is not a limitation Shadow can engineer around,
and any iOS app claiming to be "Chrome" or "Firefox" is Safari's engine wearing
a different interface.

So a faithful port is not possible, and pretending otherwise would be the kind
of security theatre Shadow exists to argue against. Here is what actually
survives the move:

| Desktop feature | On iPhone |
|---|---|
| The analyst (URL and page scoring) | **Same code, unchanged.** Runs in the app or the web app |
| Blocklists | **Yes**, as a WebKit content rule list. Blocks by domain, but cannot score or report |
| Fingerprint shield | **Same source**, injected as a user script at document start |
| Download sandbox | **Yes**, quarantine and scan. iOS cannot run what you download anyway, so this is about what you forward |
| Permission denial (camera, mic) | **Yes** |
| Certificate handling | **Yes**, deferred to the system, never overridden |
| Request-level firewall | **No.** WebKit gives an app navigation policy, not a hook on every subresource. Blocklists replace part of it |
| Private-network / SSRF blocking | **No.** Needs the per-request hook above |
| Tor routing | **No.** iOS has no per-app SOCKS proxy for WKWebView. Use Orbot, which routes the whole device |
| SOC event log | **Partly.** Navigation and download events, but not blocked subrequests, because WebKit does not report them |

---

## 1. The web app

Open the published link on your iPhone, tap Share, then **Add to Home Screen**.
It opens like an app and works with no signal, because the entire detection
engine ships inside the page. Nothing you check is ever uploaded.

To check links from Messages or Mail without copying and pasting, build a
Shortcut:

1. Shortcuts → new shortcut → turn on **Use as Quick Action → Share Sheet**,
   accepting **URLs**.
2. Add **Open URLs**, and set the URL to the app's address followed by `?u=`
   and the **Shortcut Input** variable.

Share any link to it and the verdict opens straight away.

## 2. The Safari content blocker

`mobile/build-content-blocker.js` turns Shadow's blocklists into the JSON
format Safari accepts. Run `npm run update-lists` first for the real feeds,
then:

```bash
node mobile/build-content-blocker.js
```

Wrap `mobile/shadow-blocker.json` in a Content Blocker Extension target in
Xcode and install it to your phone. WebKit then applies the rules itself,
inside Safari, on every site.

WebKit's limits are worth knowing: 150,000 rules maximum, purely declarative,
and the extension never learns what was blocked. That is why this cannot be
the whole firewall, and why the generator emits malware and phishing rules
first, so that if anything is truncated it is advertising.

## 3. The native app

`ios/Shadow/` is a complete SwiftUI app. It does not reimplement any detection
logic: `ios/build-assets.js` copies the same engine, the same blocklists and
the same fingerprint shield the desktop uses into the app bundle.

```bash
node ios/build-assets.js     # writes ios/Shadow/Resources/
```

Then in Xcode: new iOS App project named Shadow, SwiftUI interface, add the
five Swift files and `Resources` as a **folder reference** so regenerating the
assets keeps them in sync.

### How the engine runs

The analyst runs inside an off-screen `WKWebView`, not JavaScriptCore. This is
deliberate. JavaScriptCore implements ECMAScript and nothing else: no `URL`, no
`TextEncoder`. Shadow's engine is built on WHATWG URL parsing, and hand-rolling
that in a polyfill is exactly the kind of subtle work where one mistake becomes
a missed phishing domain. A `WKWebView` already contains a complete, correct
implementation.

It also isolates the analyst from browsing content: they are separate
processes with no shared context, so a hostile page cannot reach the thing
judging it.

### Getting it onto your phone

This is the part people underestimate.

- **Free Apple ID.** Xcode will install it, but it stops working after **7
  days** and you must re-install from the Mac. Fine for trying it.
- **Apple Developer Program, $99/year.** Builds last a year. This is the only
  way to keep it installed without a Mac nearby.
- **The App Store.** Review is unlikely to be smooth for a browser that
  advertises blocking and quarantine, and it is not needed for personal use.

You need a Mac. Xcode does not run on Windows, Linux, or iPad.

---

## What has and has not been verified

**The JavaScript is tested.** `test/mobile-engine.test.js` runs the phone
engine against the desktop engine and requires identical verdicts on every URL,
every page, and every file sample, plus SHA-256 vectors at block boundaries.
That suite passes.

**The Swift is not.** It was written without a Mac, so it has never been
compiled or run. Treat it as a careful implementation to build on, not as
something known to work. Expect to fix compile errors, particularly around
Swift concurrency annotations, which change between Xcode versions.

If you get it building, the first things worth checking are that
`ShadowEngine.start()` resolves (the banner tells you if it did not), that the
content rule list compiles, and that `window.__shadowShield` is `true` on a
loaded page.

---

## The zero-effort option worth doing anyway

Regardless of everything above: on your iPhone, go to **Settings → General →
VPN & Device Management → DNS**, or install a DNS-over-HTTPS profile pointing
at a filtering resolver such as Quad9 (`9.9.9.9`). It blocks known malware and
phishing domains for **every app on the device**, not just the browser, costs
nothing, and takes two minutes.

It is a blunter instrument than Shadow's analyst, with no scoring and no
explanation. But it protects the whole phone, and it is the single highest
value security change most people can make to an iPhone.
