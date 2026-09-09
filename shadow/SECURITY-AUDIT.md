# Security audit of Shadow itself

A browser that inspects other people's code has to survive inspection of its
own. This is what a review of Shadow's first version found, and what was done
about it. Every fix has a regression test in `test/security-regressions.test.js`
or `test/firewall.test.js`, so none of these can come back quietly.

Result: **9 issues found and fixed. 117 unit tests and 16 live functional
checks pass. `npm audit` reports 0 vulnerabilities.**

---

## The threat model this is written against

Shadow's job is to render hostile content. So the assumption throughout is:

> A web page will eventually find a bug in Chromium and take over the renderer
> process it is running in.

That is not pessimism, it is what browser exploits are. Everything below is
judged by one question: **once a renderer is hostile, what can it reach?**

That is also why the browser's own user interface counts as untrusted. The
toolbar, the settings panel and the SOC dashboard are a renderer process too.
Every one of them talks to the privileged main process over IPC, and every one
of those channels is an entry point.

---

## Critical

### C1. TLS verification was disabled entirely

`hardening/profile.js` installed a certificate verifier that returned `0`:

```js
session.setCertificateVerifyProc((request, callback) => {
  callback(0);   // the comment claimed this meant "use Chromium's result"
});
```

In Electron, `callback(0)` means **success**: it tells Chromium the certificate
is trusted and additionally disables Certificate Transparency checking. The
value for "use Chromium's own result" is `-3`.

`0` reads like "no error", which is exactly why this is an easy mistake to
make, and the comment above it asserted the opposite of what the code did.

**Impact.** Every HTTPS connection accepted any certificate: expired,
self-signed, revoked, issued for a different hostname. Anyone able to
intercept traffic (a hostile network, a compromised router, a captive portal)
could read and modify every page and every password, and Shadow would show a
padlock. This defeated the product's central promise, and it defeated the
certificate heuristics in `tls-heuristics.js` at the same time, because
Chromium never reported an error for them to explain.

**Fix.** Return `-3`, with the reasoning written out at the call site so the
next person to touch it does not "simplify" it back. The regression test parses
the function body, strips comments, and asserts `-3` is the only value passed.

### C2. Any executable could be spawned through a setting

`tor.binaryPath` was a plain string. `SettingsStore.set` checked that it was a
string and nothing else. `TorManager.start()` then passed it to `spawn()`.

**Impact.** The settings API is reachable from the browser UI. A renderer
compromise could set `tor.binaryPath` to any file on disk and call `tor:start`,
which turns a rendering bug into arbitrary code execution outside the sandbox.
The same shape existed elsewhere: `tor.bridges` entries were written verbatim
into `torrc` (newline injection adds arbitrary Tor directives),
`hardening.userAgent` went into an HTTP header (CRLF injection), and
`proxy.url` and `dns.dohUrl` could silently downgrade or redirect all traffic.

**Fix.** `storage/setting-validators.js`. Settings whose values *do* something
get a content check, not just a type check. Values loaded from a tampered
settings file go through the same checks, so the file is not a way around them.

### C3. Privileged handlers loaded any URL scheme

`soc:proceed`, `tab:navigate`, `tab:new`, `createTab()` and the `window.open`
handler all took a URL string and passed it to `loadURL()`.

**Impact.** `soc:proceed('file:///home/you/.ssh/id_rsa')` renders a private key
in a tab. `data:` and `javascript:` URLs run attacker-chosen code. Shadow's own
`interstitial.html` and `home.html` are `file://` pages that expose an IPC
bridge, so anything that could navigate to `file://` could reach that bridge.

**Fix.** `hardening/url-policy.js` is now the single place that answers "may
this be loaded". Deny by default; `http` and `https` allowed; Shadow's own
pages recognised by resolved filesystem path rather than by how the path is
spelled, so `/tmp/evil/interstitial.html` is not mistaken for the real one.

### C4. Any scheme could be handed to the operating system

`app:open-external` called `shell.openExternal()` on an unvalidated string.
The confirmation dialog was not a defence, because the dialog showed a URL the
attacker also chose.

**Impact.** `shell.openExternal` hands a URL to the OS protocol handlers. On
Windows that includes `ms-msdt:` and `search-ms:`, which have been used for
real code execution. This is precisely the "web page launches a program" path
Shadow claims to block.

**Fix.** `http`, `https` and `mailto` only.

---

## High

### H1. The analyst trusted a URL reported by the page

`shadow:page-observed` used `observation.url`, a value sent by the renderer,
to decide which origin the page content should be judged against.

**Impact.** A compromised renderer could report a trusted URL alongside benign
HTML and turn its own risk badge green, or have hostile content scored as if it
came from a site on the allowlist.

**Fix.** The main process uses `webContents.getURL()`, which it knows to be
true. The reported HTML is still used, because that is the point of the
observation, but it is length-capped and the origin is not negotiable.

### H2. Redirects were never analysed

The navigation gate hooked `will-navigate` only.

**Impact.** `will-navigate` fires for the address the user asked for, not the
address they end up at. Any link to a benign-looking domain that then redirects
to a phishing page passed the pre-navigation check completely. Link shorteners
and open redirects are how phishing is delivered, so this was not a corner case.

**Fix.** `will-redirect` is gated by the same function, and `did-frame-navigate`
scores subframes so a blocked page cannot simply be loaded inside an iframe.

### H3. `file://` was only gated at the navigation layer

**This one was found by the live functional test, not by review.** The
navigation gate does block a page that tries to reach the disk. But Chromium's
`webRequest` API never fires for the `file` scheme, so the firewall could not
see `file://` at all, and any path to `loadURL()` that did not pass through
`will-navigate` still worked. The functional test loaded `/etc/passwd` and
rendered it.

**Fix.** Enforcement moved to the protocol itself, via a `protocol.handle`
interceptor on the web session that serves only files inside Shadow's own
renderer directory and returns 403 for everything else. That covers every code
path at once rather than every code path we remembered to check.

### H4. Downloads could be released into persistence

`sandbox.releaseDir` is a user setting, so it is renderer-reachable. Releasing
a file into `~/.config/autostart`, `~/Library/LaunchAgents` or a systemd user
directory means it runs at login without anyone opening it. The verdict check
did not help, because a file that scores clean can still be malicious.

**Fix.** `hardening/safe-paths.js`. The destination must be inside the user's
home directory and must not contain a path segment the system executes from.
Checked both when the setting is written and again at release time.

### H5. The local-network block could be bypassed with no referrer

The firewall treated "main frame request with no initiator" as proof the person
typed the address, and allowed it through to the local network.

**Impact.** Any page can produce exactly that with `rel="noreferrer"` or a
stripped `Referrer-Policy`. That handed a page the whole local network,
defeating one of Shadow's better protections.

**Fix.** The main process records address-bar navigations explicitly, with a
15-second expiry, and the firewall consults that record instead of inferring
intent from a missing header. A page cannot forge it because it never touches
that code path.

---

## Medium

### M1. Firewall rule patterns could hang the browser

A rule's `urlPattern` is compiled to a regular expression and evaluated against
every request. A pattern like `(a+)+$` backtracks catastrophically, so one rule
would freeze the browser on the first page load.

**Fix.** Patterns are length-capped, screened for nested quantifiers, compiled
once at validation time, and the rule list is capped.

### M2. Unbounded caches

`Analyzer.cache` and `Analyzer.sessionOverrides` grew without limit. A page
requesting a thousand unique subdomains grew main-process memory to match.

**Fix.** Both are bounded and evict oldest-first.

### M3. Page alerts were free-form

`shadow:page-alert` accepted an arbitrary object from a renderer and put it
straight into the UI and the event log.

**Fix.** Normalised into a fixed shape with an allowlisted severity, capped
lengths, and a limit of 20 alerts per page so a hostile page cannot bury real
findings under noise.

### M4. Inherited object keys were accepted as setting names

`key in DEFAULTS` is true for `__proto__`, `constructor`, `toString` and every
other `Object.prototype` member, so all of them passed the "is this a real
setting" guard. The validator lookup had the same shape: `VALIDATORS['constructor']`
resolves to `Object`, which is a function, so it would have been called as a
validator.

This was **not** exploitable in the version reviewed. `__proto__` happened to
be rejected further down by an unrelated error, and the assignment would have
affected only the settings object rather than `Object.prototype`. Relying on an
accident is how a refactor reintroduces a bug, so it was fixed as written
rather than left because it currently fails to work.

**Fix.** `Object.hasOwn` in both places, and the settings object is created
with a null prototype so there is nothing to override.

---

## Dependency

Shadow was pinned to `electron@^32`, which resolved to 32.3.3. `npm audit`
reported **2 high-severity advisories covering 26 CVEs**. For a security
browser this is the most consequential category of all: an outdated Chromium
means publicly documented exploits work against it.

Several were directly relevant to Shadow's design:

| Advisory | Why it mattered here |
|---|---|
| Permission handler receives main-frame origin instead of the iframe's | Shadow's permission policy is built on the requesting origin |
| Context isolation bypass via `Function.prototype.bind` | Shadow's preload isolation depends on it |
| HTTP redirect followed into local file loader | Shadow's `file://` confinement depends on it |

**Fix.** Upgraded to `electron@^44.3.0`. `npm audit` now reports 0
vulnerabilities.

The permission-handler bug was also fixed in Shadow's own code rather than only
by upgrading: `setPermissionRequestHandler` now prefers `details.requestingUrl`
over `webContents.getURL()`, so a third-party iframe cannot inherit the trust
the user extended to the site in the address bar. This has been an Electron bug
more than once, so Shadow does not rely on the framework getting it right.

---

## Two things that were left alone deliberately

**A page on the local network may reach the local network.** The functional
test initially flagged this. It is correct: it matches the web platform's own
Private Network Access model, where loopback is the most private context and
may reach less private ones. The case that matters, a public page reaching your
LAN, is blocked and tested. Cloud metadata endpoints are refused from
everywhere, including from local pages, because nothing in a browser has a
legitimate reason to read them.

**`--no-sandbox` is honoured rather than overridden.** `app.enableSandbox()`
used to run unconditionally, which beat the flag. That did not produce a safer
browser; it produced one that crash-loops its child processes on any system
that cannot provide the sandbox, with an error most people would not recognise.
Shadow now honours the flag, prints a plain warning, and records
`protection-disabled` in the SOC log so the state is visible rather than
assumed.

---

## What this audit does not cover

- No fuzzing of the file parsers in `sandbox/scanner.js`. They are defensive
  (bounded reads, try/catch around every format walk) but have not been fuzzed.
- No review of Chromium itself, which is the bulk of the attack surface. That
  is what keeping Electron current is for.
- The container detonation path assumes Docker or Podman is configured sanely.
  A misconfigured daemon (rootful, socket exposed) is outside Shadow's control.
- Nothing here has been reviewed by anyone other than its author. Findings from
  a second pair of eyes are welcome.
