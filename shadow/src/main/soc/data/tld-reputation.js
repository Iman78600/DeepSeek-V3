'use strict';
/**
 * Reputation data about top-level domains and hosting providers.
 * These are *context* signals, never a verdict on their own. Plenty of
 * legitimate sites live on a .top domain or behind a link shortener.
 */

// TLDs that repeatedly top abuse reports (Spamhaus / Interisle style rankings).
const HIGH_RISK_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'cfd', 'sbs', 'rest', 'bond', 'cyou', 'icu',
  'buzz', 'click', 'link', 'gq', 'ml', 'cf', 'ga', 'tk', 'work', 'fit',
  'monster', 'quest', 'beauty', 'hair', 'skin', 'makeup', 'mom', 'lol',
  'autos', 'boats', 'motorcycles', 'yachts', 'homes', 'christmas',
  'live', 'life', 'store', 'shop', 'online', 'site', 'website', 'space',
  'pw', 'su', 'cc', 'ws', 'wang', 'loan', 'download', 'racing', 'win',
  'stream', 'review', 'date', 'party', 'trade', 'science', 'accountant',
  'faith', 'cricket', 'men', 'kim', 'country', 'gdn', 'realtor', 'casa',
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'bl.ink',
  'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'bitly.com', 'j.mp', 'tr.im',
  'soo.gd', 's2r.co', 'clicky.me', 'gg.gg', 'shrtco.de', 'v.gd', 'x.co',
  'short.io', 'urlz.fr', 'kutt.it', 'chilp.it', 'clck.ru', 'vk.cc', 'u.to',
]);

// Free hostnames that resolve to whatever IP the holder wants. Extremely
// common in commodity malware command-and-control.
const DYNAMIC_DNS = new Set([
  'no-ip.com', 'noip.com', 'ddns.net', 'hopto.org', 'zapto.org', 'sytes.net',
  'servebeer.com', 'serveblog.net', 'servecounterstrike.com', 'serveftp.com',
  'servegame.com', 'servehalflife.com', 'servehttp.com', 'serveirc.com',
  'serveminecraft.net', 'servemp3.com', 'servepics.com', 'servequake.com',
  'redirectme.net', 'myftp.biz', 'myftp.org', 'myvnc.com', 'bounceme.net',
  'dynu.com', 'dynu.net', 'freedynamicdns.net', 'duckdns.org', 'dynv6.net',
  'afraid.org', 'chickenkiller.com', 'crabdance.com', 'ignorelist.com',
  'strangled.net', 'twilightparadox.com', 'us.to', 'mooo.com', 'ftp.sh',
  'changeip.com', 'dnsdynamic.org', 'dnsexit.com', 'sitelutions.com',
  'cloudns.net', 'cloudns.cc', 'cloudns.ph', 'dns-cloud.net', 'dnsabr.com',
]);

// Anyone can publish here in minutes with no identity verification.
const FREE_HOSTS = new Set([
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'netlify.app',
  'vercel.app', 'firebaseapp.com', 'web.app', 'appspot.com', 'herokuapp.com',
  'repl.co', 'replit.dev', 'glitch.me', 'onrender.com', 'fly.dev',
  'ngrok-free.app', 'ngrok.io', 'trycloudflare.com', 'loca.lt', 'serveo.net',
  'weeblysite.com', 'wixsite.com', 'webflow.io', 'blogspot.com', 'tumblr.com',
  'r2.dev', 'ipfs.io', 'dweb.link', 'w3s.link', 'nftstorage.link',
  'notion.site', 'super.site', 'gitbook.io', 'bigcartel.com',
  'blob.core.windows.net', 'storage.googleapis.com', 'backblazeb2.com',
  'sharepoint.com', 'my.canva.site', 'canva.site', 'framer.website',
]);

// Anonymising / bulletproof-ish infrastructure worth flagging on downloads.
const ANONYMOUS_FILE_HOSTS = new Set([
  'anonfiles.com', 'bayfiles.com', 'gofile.io', 'pixeldrain.com', 'file.io',
  'transfer.sh', 'temp.sh', 'catbox.moe', 'litterbox.catbox.moe', 'uguu.se',
  'send.now', 'wetransfer.com', 'mega.nz', 'mediafire.com', 'zippyshare.com',
  '1fichier.com', 'krakenfiles.com', 'dropmefiles.com', 'filebin.net',
  'oshi.at', 'tmpfiles.org', 'bashupload.com', 'ufile.io', 'workupload.com',
  'discordapp.com', 'cdn.discordapp.com', 'telegra.ph', 'paste.ee',
]);

module.exports = { HIGH_RISK_TLDS, SHORTENERS, DYNAMIC_DNS, FREE_HOSTS, ANONYMOUS_FILE_HOSTS };
