# Shadow

A browser that watches the web the way a security analyst would.

Shadow is built on Electron, which is Chromium underneath, so pages render the
way they do in Chrome. What is different is everything wrapped around the page:

| Layer | What it does |
|---|---|
| **The analyst** | Scores every page before it loads and again after it renders. Phishing, fake support pages, cryptominers, wallet-drainers and "paste this into Run" pages get stopped. |
| **The firewall** | Filters every single request a page makes. Known-bad hosts, trackers, non-web ports, and any attempt to reach your own home network are dropped. |
| **The sandbox** | Downloads never touch your Downloads folder. They land in quarantine with the run bit stripped, get taken apart, and only move when you say so. |
| **The hardening** | Camera, microphone, location, USB and clipboard reads are refused. Your canvas, fonts, GPU and timers are fuzzed so sites cannot fingerprint you. |
| **Tor** | Optional. Routes everything through the Tor network. If Tor is not actually running, Shadow refuses to connect rather than quietly leaking. |

Every decision is made on your machine. Shadow does not send the pages you
visit to any service, ours or anyone else's.

---

## Two things to be straight about first

**There is no free VPN in here, and you should be suspicious of any browser
that says it has one.** Running VPN servers costs money. If nobody is charging
you, the product being sold is usually your traffic. Tor is the genuinely free
option that does not work that way, because it is run by volunteers and no
single relay can see both who you are and where you are going. That is what
Shadow uses. If you already pay for a VPN you trust, point Shadow at it under
proxy settings instead.

**Shadow is not antivirus, and a clean verdict is not a promise.** It catches
the patterns attackers actually use, which is a lot, and it is very good at the
categories it covers. It will not catch a brand-new targeted attack written for
you specifically. Nothing will. Treat it as a very attentive colleague looking
over your shoulder, not a force field.

---

## Try it in 30 seconds, no install

The security engine is plain Node with no dependencies, so you can run it
before you build anything:

```bash
cd shadow

# Score a link without visiting it
node tools/scan-cli.js url "http://paypal.com.secure-verify.tk/login/confirm-account"

# Take a file apart the way the sandbox does
node tools/scan-cli.js file ./some-download.docx

# Ask the firewall what it would do with a request
node tools/scan-cli.js request "http://192.168.1.1/admin"

# Fetch a live page and analyse its contents
node tools/scan-cli.js page https://example.com
```

That first command prints:

```
BLOCK  risk 93/100  severity high  (balanced mode, blocks at 65)

  [high    ]  65  "PayPal" appears in the address but this is not paypal.com
             Everything before the last dot is chosen by whoever registered
             "secure-verify.tk". The real owner of this page is secure-verify.tk.
  [high    ]  55  Login page over plain HTTP
  [medium  ]  30  Account/urgency wording in the link
  [medium  ]  22  Abuse-heavy TLD (.tk)
  [low     ]  20  Unencrypted connection
```

## Run the browser

```bash
cd shadow
npm install          # pulls Electron, about 250 MB
npm start
```

Optional extras:

```bash
npm run update-lists     # download the real blocklists (millions of domains)
npm test                 # 117 unit tests covering every detection module
npm run test:functional  # boots the real browser and drives it (Linux, needs xvfb)
sudo apt install tor     # only if you want the Tor button to work
```

The functional test is the interesting one. It starts the actual application,
serves a phishing page and a tracker-laden page from a local server, drives a
real tab at them, and checks that the analyst blocks, the firewall drops, the
fingerprint shield is live in the page's own JavaScript world, and a tab cannot
be made to render `/etc/passwd`. Sixteen checks, all passing.

---

## How the analyst decides

Every check produces a **signal**: an id, a score from 0 to 100, a severity,
and a plain-English explanation. Signals are combined with diminishing returns
rather than added up:

```
total = 100 × (1 − Π(1 − score/100))
```

That matters. Ten weak signals should not outweigh one certain one, and one
strong signal should not get diluted by noise. On top of that, any single
signal scoring 85 or more forces a block no matter what the total says. Those
are the checks where no legitimate site does the thing at all:

- a page asking for your wallet recovery phrase
- a page telling you to paste a command into Run or PowerShell
- a filename using a right-to-left override to hide its real extension
- a document whose macro runs the moment you open it
- a PDF that launches a program

Three strictness modes move the thresholds:

| Mode | Warns at | Blocks at |
|---|---|---|
| strict | 20 | 45 |
| balanced (default) | 35 | 65 |
| relaxed | 55 | 85 |

A site you have explicitly trusted can never be hard-blocked by a heuristic,
only warned about, so a false positive can never lock you out of your own bank.

### What it actually looks for

**In the address**, before a byte is fetched: brand names sitting in a
subdomain (`paypal.com.evil.tk`), lookalike domains built from confusable
characters (`micros0ft.com`), mixed-alphabet homographs, punycode, credentials
hidden before an `@`, raw and obfuscated IP addresses, machine-generated
domain names, non-web ports, open-redirect parameters, and abuse-heavy TLDs.

The lookalike check is careful about false positives. Entropy alone cannot
tell `stackoverflow` (3.55) from `xkqjvbzmrtpl` (3.59), so Shadow also measures
whether a name is pronounceable: vowel distribution and consonant runs.

**In the page**, once it renders: password fields on HTTP, login forms posting
to a different domain, a page presenting itself as a brand it does not own,
obfuscated JavaScript, cryptominers, fake virus warnings, ClickFix
paste-a-command attacks, seed-phrase harvesting, keyloggers, invisible iframes,
clipboard hijacking, and drive-by downloads.

**In the certificate**: hostname mismatches computed independently of
Chromium's own check, self-signed certificates, over-broad wildcards, and
certificates issued hours ago. A brand-new free certificate is not suspicious
on its own, and Shadow treats it as context rather than evidence.

---

## How the firewall works

Every request passes through one pure function before a socket opens. In order:

1. **Your rules.** They can allow or block anything, and they run first.
2. **Schemes.** Only web protocols leave the browser. A page cannot hand a
   `smb://` or custom-protocol URL to your operating system to open.
3. **Ports.** SSH, SMTP, SMB, Redis, RDP, Postgres and about 60 others are
   refused, because browsers get used to smuggle commands into services.
4. **Your own network.** This is the one people underestimate. A page on the
   internet has no business fetching `http://192.168.1.1/`, and neither do
   cloud metadata endpoints at `169.254.169.254`. Both are blocked. A page
   already on your LAN can still talk to your LAN, and typing a local address
   yourself still works.
5. **Blocklists**, weighted by category.
6. **HTTPS-only**, upgrading plaintext automatically.
7. **Lockdown mode**, optionally blocking all third-party scripts and frames.

Request headers are stripped of client hints and other identifying details,
the referrer is trimmed to its origin, and `DNT` and `Sec-GPC` are added.
Responses get `nosniff`, a strict referrer policy, and a `Permissions-Policy`
that turns off every sensor a page might ask for.

---

## How the download sandbox works

Nothing reaches your Downloads folder unexamined.

1. **Quarantine.** The file is written to `~/.shadow/quarantine/<id>/`, mode
   0600 inside a 0700 directory, with `.quarantined` appended so a
   double-click cannot run it. The server's filename is sanitised first, which
   defeats path traversal and right-to-left override tricks.
2. **Identify.** The real file type comes from magic bytes, never the
   extension. A `report.pdf` that starts with `MZ` is a Windows executable,
   and Shadow says so.
3. **Take it apart.** Executables get section entropy, packer detection, and
   writable-plus-executable checks. Office files get macro and auto-run
   detection. PDFs get `/OpenAction`, `/Launch` and `/JavaScript` extraction,
   including from deflate-compressed streams. Archives get inspected for
   executables, shortcuts, encryption, zip-slip and decompression bombs. Every
   file gets a string sweep for encoded PowerShell, reverse shells,
   process-injection APIs, ransomware behaviour and infostealer paths.
4. **Detonate**, optionally. With Docker or Podman installed, Shadow runs the
   file in a throwaway container with no network, no capabilities and a
   read-only filesystem, and watches what it touches. This is off by default.
   Shadow will not pretend a Linux container ran a Windows `.exe`, and says so
   rather than reporting a meaningless clean result.
5. **You decide.** A file Shadow blocked cannot be released without an
   explicit forced confirmation that names what was found.

---

## Security profiles

| Profile | What you get |
|---|---|
| **Standard** | Blocks known-bad sites, ads and trackers. Sandboxes downloads. Sites work normally. |
| **Balanced** (default) | Adds fingerprinting protection, WebRTC leak blocking, a stricter analyst. A few sites may need an exception. |
| **Ghost** | Tor on, third-party scripts and frames blocked, WebGL and WebAssembly off, every download detonated, everything wiped on exit. Many sites will break. That is the trade. |

---

## Layout

```
shadow/
  src/main/
    main.js                  Electron entry, tabs, navigation gates
    ipc.js                   the trust boundary between UI and privileged code
    tor.js                   Tor process, proxy config, fail-closed logic
    soc/
      analyzer.js            one place that produces a verdict
      scoring.js             signal combination and thresholds
      events.js              the SOC event log (JSONL on disk)
      heuristics/            url, content and TLS checks
      data/                  public suffixes, TLD reputation, protected brands
    firewall/
      firewall.js            request decisions (pure function + Electron binding)
      rules.js               IP/CIDR reasoning, port policy, rule matching
      blocklists.js          category lists and label-chain matching
    sandbox/
      quarantine.js          quarantine, release policy
      scanner.js             static file analysis
      detonate.js            optional container detonation
    hardening/
      profile.js             session hardening, web preferences, switches
      permissions.js         permission policy (deny by default)
      url-policy.js          the one place that decides if a URL may be loaded
      safe-paths.js          where a download may be released to
      fingerprint-shield.js  main-world anti-fingerprinting source
    storage/
      store.js               settings with a schema that cannot be weakened
      setting-validators.js  content checks for settings that spawn or proxy
  src/preload/
    site-preload.js          fingerprint resistance + page telemetry
    browser-preload.js       the UI bridge
  src/renderer/              browser chrome, SOC dashboard, block page
  config/                    default settings, presets, blocklists
  tools/                     CLI scanner, blocklist updater, functional test
  test/                      117 unit tests, including security regressions
```

Every security module is plain Node with no Electron import, which is why the
CLI and the test suite exercise exactly the code the browser runs.

---

## Testing it against real samples

The test suite builds genuine malicious structures rather than mocking them:
a hand-assembled PE with UPX sections and encoded PowerShell, a hand-assembled
ZIP with zip-slip entries and a `vbaProject.bin`, a PDF with a `/Launch`
action hidden inside a deflate stream. If you want to check it against
something real, [the EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)
and any sample from [MalwareBazaar](https://bazaar.abuse.ch/) work fine through
the CLI. Do that in a virtual machine, not on your daily driver.

---

## Shadow has been audited too

A browser that inspects other people's code has to survive inspection of its
own. **[SECURITY-AUDIT.md](SECURITY-AUDIT.md)** documents a review of Shadow's
first version: nine issues found and fixed, including one that disabled TLS
verification entirely, one that allowed arbitrary code execution through a
setting, and one found only by running the real browser rather than by reading
it. Every fix has a regression test.

The dependency situation matters as much as the code. Shadow tracks a current
Electron, because an outdated Chromium means publicly documented exploits work.
`npm audit` reports zero vulnerabilities.

## What Shadow deliberately does not do

- **It never overrides a certificate failure.** There is no "proceed anyway"
  that trusts a bad certificate. The analyst explains the failure instead.
- **It never falls back to a direct connection when Tor is on.** If Tor is
  meant to be running and is not, the proxy points at a dead port and nothing
  loads. Being visibly broken beats being invisibly exposed.
- **It never lets a page open another application.** No `openExternal`, no
  custom protocol handlers, no `webview` tags.
- **It never uploads anything.** No cloud reputation service is contacted
  unless you turn one on and supply your own key.
- **It never pretends a protection is on when it is off.** Starting with
  `--no-sandbox` prints a warning and records `protection-disabled` in the SOC
  log, rather than quietly continuing.

## Licence

MIT.
