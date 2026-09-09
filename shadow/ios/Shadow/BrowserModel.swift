//
//  BrowserModel.swift
//  The navigation gate, the content blocker, and the download guard.
//
//  What can and cannot be carried over from the desktop, stated plainly:
//
//    Carried over   the analyst (same engine), the blocklists (as a WebKit
//                   content rule list), the fingerprint shield (as a user
//                   script at document start), download quarantine and
//                   scanning, permission denial, the block page.
//
//    Not possible   the request-level firewall. WebKit gives an app the
//                   navigation policy for top-level and frame loads, but not
//                   a hook on every subresource request. Blocklists therefore
//                   run as declarative rules that WebKit applies itself, which
//                   blocks by domain but cannot score, cannot see private-IP
//                   destinations, and reports nothing back. The SOC log on iOS
//                   is thinner than on desktop for that reason.
//
//    Not possible   Tor routing inside the app. iOS has no per-app SOCKS
//                   proxy for WKWebView. The honest answer is Orbot with a
//                   system VPN profile, which routes the whole device.
//

import Foundation
import WebKit
import Combine

@MainActor
final class BrowserModel: NSObject, ObservableObject {

    @Published var url: String = ""
    @Published var title: String = "New tab"
    @Published var isLoading = false
    @Published var canGoBack = false
    @Published var canGoForward = false
    @Published var verdict: Verdict?
    @Published var blockedVerdict: Verdict?     // non-nil while the block page shows
    @Published var quarantined: [QuarantinedFile] = []
    @Published var engineFailure: String?

    let webView: WKWebView

    /// URLs the person has explicitly chosen to continue past, this session.
    private var overrides = Set<String>()

    override init() {
        let config = WKWebViewConfiguration()

        // Nothing survives the app closing.
        config.websiteDataStore = .nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        config.preferences.isFraudulentWebsiteWarningEnabled = true
        config.upgradeKnownHostsToHTTPS = true
        config.allowsInlineMediaPlayback = false
        config.mediaTypesRequiringUserActionForPlayback = .all

        // The fingerprint shield, injected into the page's own world before any
        // page script runs. This is the direct equivalent of the desktop build's
        // CDP injection, and it is why it had to be written as a source string
        // rather than a preload in the first place.
        if let shield = FingerprintShield.userScript() {
            config.userContentController.addUserScript(shield)
        }

        webView = WKWebView(frame: .zero, configuration: config)
        webView.allowsBackForwardNavigationGestures = true
        webView.customUserAgent = FingerprintShield.genericUserAgent

        super.init()

        webView.navigationDelegate = self
        webView.uiDelegate = self

        observe()
        Task { await startUp() }
    }

    private var observers: [NSKeyValueObservation] = []

    private func observe() {
        observers = [
            webView.observe(\.isLoading, options: [.new]) { [weak self] view, _ in
                Task { @MainActor in self?.isLoading = view.isLoading }
            },
            webView.observe(\.title, options: [.new]) { [weak self] view, _ in
                Task { @MainActor in self?.title = view.title ?? "Untitled" }
            },
            webView.observe(\.url, options: [.new]) { [weak self] view, _ in
                Task { @MainActor in self?.url = view.url?.absoluteString ?? "" }
            },
            webView.observe(\.canGoBack, options: [.new]) { [weak self] view, _ in
                Task { @MainActor in self?.canGoBack = view.canGoBack }
            },
            webView.observe(\.canGoForward, options: [.new]) { [weak self] view, _ in
                Task { @MainActor in self?.canGoForward = view.canGoForward }
            },
        ]
    }

    private func startUp() async {
        do {
            try await ShadowEngine.shared.start()
        } catch {
            // Fail loudly. A browser that silently stops analysing pages while
            // still showing a shield icon is worse than one that says it broke.
            engineFailure = error.localizedDescription
        }
        await installBlocklists()
    }

    // MARK: - Blocklists

    private func installBlocklists() async {
        guard let listURL = Bundle.main.url(forResource: "shadow-blocker", withExtension: "json"),
              let json = try? String(contentsOf: listURL, encoding: .utf8) else { return }

        let store = WKContentRuleListStore.default()
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            store?.compileContentRuleList(forIdentifier: "shadow-blocklist", encodedContentRuleList: json) { list, error in
                Task { @MainActor in
                    if let list {
                        self.webView.configuration.userContentController.add(list)
                    } else if let error {
                        self.engineFailure = "Blocklists did not load: \(error.localizedDescription)"
                    }
                    c.resume()
                }
            }
        }
    }

    // MARK: - Navigation

    func go(to text: String) {
        guard let target = Self.normalise(text) else { return }
        webView.load(URLRequest(url: target))
    }

    /// Turn what someone typed into a URL, or a search. Refuses any scheme a
    /// tab has no business displaying, for the same reasons as the desktop.
    static func normalise(_ text: String) -> URL? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if let url = URL(string: trimmed), let scheme = url.scheme?.lowercased() {
            if scheme == "http" || scheme == "https" { return url }
            // file:, javascript:, data: and custom schemes are searched for,
            // never opened.
            return searchURL(for: trimmed)
        }
        let looksLikeHost = trimmed.contains(".") && !trimmed.contains(" ")
        if looksLikeHost, let url = URL(string: "https://\(trimmed)") { return url }
        return searchURL(for: trimmed)
    }

    private static func searchURL(for phrase: String) -> URL? {
        let escaped = phrase.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        return URL(string: "https://duckduckgo.com/?q=\(escaped)")
    }

    func proceedAnyway() {
        guard let blocked = blockedVerdict, let target = blocked.url else { return }
        overrides.insert(target)
        blockedVerdict = nil
        if let url = URL(string: target) { webView.load(URLRequest(url: url)) }
    }

    func dismissBlock() {
        blockedVerdict = nil
        if webView.canGoBack { webView.goBack() }
    }
}

// MARK: - The navigation gate

extension BrowserModel: WKNavigationDelegate {

    nonisolated func webView(_ webView: WKWebView,
                             decidePolicyFor navigationAction: WKNavigationAction,
                             decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        let target = url.absoluteString
        let scheme = url.scheme?.lowercased() ?? ""

        // Schemes never displayed in a tab. On iOS this also covers the app
        // schemes a page can use to launch other apps.
        guard scheme == "http" || scheme == "https" || scheme == "about" else {
            decisionHandler(.cancel)
            return
        }

        // Subframes are checked too: a blocked page is no help if the same
        // content simply loads in an iframe.
        Task { @MainActor in
            if self.overrides.contains(target) {
                decisionHandler(.allow)
                return
            }
            do {
                let verdict = try await ShadowEngine.shared.checkURL(target)
                self.verdict = verdict
                if verdict.isBlocked {
                    decisionHandler(.cancel)
                    if navigationAction.targetFrame?.isMainFrame ?? true {
                        self.blockedVerdict = verdict
                    }
                } else {
                    decisionHandler(.allow)
                }
            } catch {
                // If the analyst is unavailable, say so rather than silently
                // browsing unprotected.
                self.engineFailure = error.localizedDescription
                decisionHandler(.allow)
            }
        }
    }

    nonisolated func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        Task { @MainActor in
            await self.deepScan()
        }
    }

    /// The rendered page, not the HTML the server sent. Phishing kits assemble
    /// their login form in JavaScript precisely to defeat a scan of the source.
    @MainActor
    private func deepScan() async {
        let script = "document.documentElement ? document.documentElement.outerHTML.slice(0, 2000000) : ''"
        guard let html = try? await webView.evaluateJavaScript(script) as? String,
              // Use the URL WebKit knows we are on, never one the page reports.
              let current = webView.url?.absoluteString else { return }

        guard !overrides.contains(current) else { return }

        if let deep = try? await ShadowEngine.shared.checkPage(html: html, url: current) {
            verdict = deep
            if deep.isBlocked {
                webView.stopLoading()
                blockedVerdict = deep
            }
        }
    }

    nonisolated func webView(_ webView: WKWebView,
                             didReceive challenge: URLAuthenticationChallenge,
                             completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Never override a certificate failure. Let the system decide, exactly
        // as the desktop build defers to Chromium.
        completionHandler(.performDefaultHandling, nil)
    }

    nonisolated func webView(_ webView: WKWebView,
                             navigationAction: WKNavigationAction,
                             didBecome download: WKDownload) {
        Task { @MainActor in download.delegate = DownloadGuard.shared }
    }

    nonisolated func webView(_ webView: WKWebView,
                             navigationResponse: WKNavigationResponse,
                             didBecome download: WKDownload) {
        Task { @MainActor in download.delegate = DownloadGuard.shared }
    }

    nonisolated func webView(_ webView: WKWebView,
                             decidePolicyFor navigationResponse: WKNavigationResponse,
                             decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        decisionHandler(navigationResponse.canShowMIMEType ? .allow : .download)
    }
}

// MARK: - Permissions and popups

extension BrowserModel: WKUIDelegate {

    /// Camera and microphone are refused outright, matching the desktop policy.
    nonisolated func webView(_ webView: WKWebView,
                             requestMediaCapturePermissionFor origin: WKSecurityOrigin,
                             initiatedByFrame frame: WKFrameInfo,
                             type: WKMediaCaptureType,
                             decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        decisionHandler(.deny)
    }

    /// A page does not get to open a window. Load it in this tab so it passes
    /// through the navigation gate like anything else.
    nonisolated func webView(_ webView: WKWebView,
                             createWebViewWith configuration: WKWebViewConfiguration,
                             for navigationAction: WKNavigationAction,
                             windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = navigationAction.request.url, navigationAction.targetFrame == nil {
            Task { @MainActor in self.webView.load(URLRequest(url: url)) }
        }
        return nil
    }
}
