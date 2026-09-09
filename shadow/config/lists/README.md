# Blocklists

Plain text, one domain per line. Comments start with `#`.

Shadow parses three formats, so you can drop in a list from almost anywhere:

```
example.com                 plain domain
0.0.0.0 example.com         hosts-file format
||example.com^$third-party  adblock format
```

The filename is the category, and the category decides how heavily a match
counts toward a block:

| File           | Weight | Effect                                    |
|----------------|--------|-------------------------------------------|
| `malware.txt`  | 95     | blocked outright                          |
| `phishing.txt` | 95     | blocked outright                          |
| `scam.txt`     | 80     | blocked outright                          |
| `mining.txt`   | 70     | blocked when "block cryptominers" is on   |
| `tracker.txt`  | 12     | blocked when "block trackers" is on       |
| `ads.txt`      | 8      | blocked when "block ads" is on            |
| `custom.txt`   | 90     | your own list, blocked outright           |

Run `npm run update-lists` to fetch the public feeds. Shadow works without
this: a small built-in seed list is compiled into the binary so a fresh
install with no network still blocks the obvious things.

To block something yourself, add a line to `custom.txt`, or use the site
report panel in the browser.
