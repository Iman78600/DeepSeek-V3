'use strict';
/**
 * Brands that phishing kits impersonate most often. `token` is the
 * registrable label (what an attacker copies); `domain` is the genuine
 * registrable domain; `aliases` are additional legitimate domains that must
 * never be flagged.
 */
const RAW = [
  ['Apple', 'apple', 'apple.com', ['icloud.com', 'apple.co', 'itunes.com', 'me.com']],
  ['Microsoft', 'microsoft', 'microsoft.com', ['live.com', 'office.com', 'outlook.com', 'msn.com', 'microsoftonline.com', 'azure.com', 'windows.com', 'office365.com', 'sharepoint.com']],
  ['Google', 'google', 'google.com', ['youtube.com', 'gmail.com', 'googleapis.com', 'gstatic.com', 'goo.gl', 'withgoogle.com', 'google.co.uk']],
  ['Amazon', 'amazon', 'amazon.com', ['amazonaws.com', 'amazon.co.uk', 'amazon.de', 'primevideo.com', 'a2z.com']],
  ['PayPal', 'paypal', 'paypal.com', ['paypal.me', 'paypalobjects.com']],
  ['Facebook', 'facebook', 'facebook.com', ['fb.com', 'fbcdn.net', 'messenger.com']],
  ['Instagram', 'instagram', 'instagram.com', ['cdninstagram.com']],
  ['Netflix', 'netflix', 'netflix.com', ['nflxvideo.net', 'nflximg.net']],
  ['LinkedIn', 'linkedin', 'linkedin.com', ['licdn.com', 'lnkd.in']],
  ['WhatsApp', 'whatsapp', 'whatsapp.com', ['wa.me', 'whatsapp.net']],
  ['Chase', 'chase', 'chase.com', ['jpmorgan.com', 'jpmorganchase.com']],
  ['Wells Fargo', 'wellsfargo', 'wellsfargo.com', []],
  ['Bank of America', 'bankofamerica', 'bankofamerica.com', ['bofa.com', 'mbna.com']],
  ['Citibank', 'citibank', 'citibank.com', ['citi.com', 'citigroup.com']],
  ['HSBC', 'hsbc', 'hsbc.com', ['hsbc.co.uk', 'hsbc.ca']],
  ['Barclays', 'barclays', 'barclays.com', ['barclays.co.uk']],
  ['Coinbase', 'coinbase', 'coinbase.com', ['cb.run']],
  ['Binance', 'binance', 'binance.com', ['binance.us', 'bnbchain.org']],
  ['MetaMask', 'metamask', 'metamask.io', ['consensys.net']],
  ['Ledger', 'ledger', 'ledger.com', ['ledgerwallet.com']],
  ['Trezor', 'trezor', 'trezor.io', ['satoshilabs.com']],
  ['Kraken', 'kraken', 'kraken.com', []],
  ['DHL', 'dhl', 'dhl.com', ['dhl.de', 'dpdhl.com']],
  ['FedEx', 'fedex', 'fedex.com', []],
  ['UPS', 'ups', 'ups.com', []],
  ['USPS', 'usps', 'usps.com', ['usps.gov']],
  ['Royal Mail', 'royalmail', 'royalmail.com', []],
  ['Steam', 'steampowered', 'steampowered.com', ['steamcommunity.com', 'valvesoftware.com']],
  ['Discord', 'discord', 'discord.com', ['discordapp.com', 'discord.gg']],
  ['Twitter', 'twitter', 'twitter.com', ['x.com', 'twimg.com', 't.co']],
  ['TikTok', 'tiktok', 'tiktok.com', ['tiktokcdn.com', 'bytedance.com']],
  ['Dropbox', 'dropbox', 'dropbox.com', ['dropboxusercontent.com']],
  ['Adobe', 'adobe', 'adobe.com', ['adobelogin.com', 'acrobat.com']],
  ['DocuSign', 'docusign', 'docusign.com', ['docusign.net']],
  ['Zoom', 'zoom', 'zoom.us', ['zoom.com', 'zoomgov.com']],
  ['Slack', 'slack', 'slack.com', ['slack-edge.com', 'slackhq.com']],
  ['GitHub', 'github', 'github.com', ['githubusercontent.com', 'github.io', 'githubassets.com']],
  ['Spotify', 'spotify', 'spotify.com', ['scdn.co', 'spotifycdn.com']],
  ['eBay', 'ebay', 'ebay.com', ['ebayimg.com', 'ebay.co.uk']],
  ['Walmart', 'walmart', 'walmart.com', ['walmartimages.com']],
  ['Booking.com', 'booking', 'booking.com', ['bstatic.com']],
  ['Airbnb', 'airbnb', 'airbnb.com', ['muscache.com']],
  ['Uber', 'uber', 'uber.com', ['ubereats.com', 'uber-assets.com']],
  ['Roblox', 'roblox', 'roblox.com', ['rbxcdn.com']],
  ['Epic Games', 'epicgames', 'epicgames.com', ['unrealengine.com', 'fortnite.com']],
  ['OpenAI', 'openai', 'openai.com', ['chatgpt.com', 'oaistatic.com']],
  ['Anthropic', 'anthropic', 'anthropic.com', ['claude.ai', 'claudeusercontent.com']],
  ['Santander', 'santander', 'santander.com', ['santander.co.uk']],
  ['Revolut', 'revolut', 'revolut.com', []],
  ['Monzo', 'monzo', 'monzo.com', []],
  ['Nubank', 'nubank', 'nubank.com.br', []],
  ['ING', 'ingbank', 'ing.com', ['ing.nl', 'ing.de']],
  ['Outlook', 'outlook', 'outlook.com', ['live.com', 'hotmail.com']],
  ['Telegram', 'telegram', 'telegram.org', ['t.me', 'telegram.me']],
  ['Signal', 'signalmessenger', 'signal.org', ['signal.art']],
  ['Twitch', 'twitch', 'twitch.tv', ['ttvnw.net', 'jtvnw.net']],
  ['Costco', 'costco', 'costco.com', []],
  ['Target', 'targetcorp', 'target.com', []],
  ['IRS', 'irs', 'irs.gov', []],
  ['HMRC', 'hmrc', 'hmrc.gov.uk', ['gov.uk']],
];

const PROTECTED_BRANDS = RAW.map(([name, token, domain, aliases]) => ({
  name, token, domain, aliases: new Set(aliases),
}));

/** Every domain that legitimately belongs to a protected brand. */
const LEGITIMATE_BRAND_DOMAINS = new Set(
  PROTECTED_BRANDS.flatMap((b) => [b.domain, ...b.aliases]),
);

module.exports = { PROTECTED_BRANDS, LEGITIMATE_BRAND_DOMAINS };
