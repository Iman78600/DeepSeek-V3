//
//  ShadowEngine.swift
//  Runs Shadow's detection engine and answers questions about URLs and pages.
//
//  Why the engine runs in a WKWebView and not in JavaScriptCore:
//
//  JavaScriptCore is the obvious choice for "run some JavaScript from Swift",
//  and it is the wrong one here. It implements ECMAScript and nothing else: no
//  URL, no TextEncoder, no TextDecoder. Shadow's engine is built on WHATWG URL
//  parsing, and reimplementing that correctly in a polyfill is a large amount
//  of subtle work (host normalisation, IP literal forms, punycode) where a
//  small mistake becomes a missed phishing domain.
//
//  A WKWebView already contains a complete, correct implementation of all of
//  it. So the engine runs in its own off-screen web view that never loads a
//  page and never touches the network. That also isolates it from browsing
//  content: a hostile page cannot reach into the analyst, because they are
//  different processes with no shared context.
//
//  The cost is that every call is asynchronous. That is fine: navigation
//  decisions are already asynchronous, and file scans are not on a hot path.
//

import Foundation
import WebKit

/// A single thing the analyst noticed.
struct Signal: Decodable, Identifiable {
    let id: String
    let score: Int
    let severity: String
    let title: String
    let detail: String
}

/// The analyst's answer.
struct Verdict: Decodable {
    enum Call: String, Decodable { case allow, warn, block }

    let verdict: Call
    let score: Int
    let severity: String
    let signals: [Signal]
    let url: String?
    let hostname: String?

    var isBlocked: Bool { verdict == .block }
    var topFinding: Signal? { signals.first { $0.score > 0 } }
}

enum EngineError: Error, LocalizedError {
    case notReady
    case evaluationFailed(String)
    case badResponse

    var errorDescription: String? {
        switch self {
        case .notReady:
            return "The analyst has not finished starting up."
        case .evaluationFailed(let message):
            return "The analyst could not evaluate that: \(message)"
        case .badResponse:
            return "The analyst returned something Shadow could not read."
        }
    }
}

@MainActor
final class ShadowEngine: NSObject {

    static let shared = ShadowEngine()

    private var webView: WKWebView?
    private var ready = false
    private var pending: [CheckedContinuation<Void, Error>] = []

    private override init() { super.init() }

    /// Build the isolated context and load the engine into it.
    func start() async throws {
        guard webView == nil else { return }

        let config = WKWebViewConfiguration()
        // The analyst never loads a page, so it needs no storage of any kind.
        config.websiteDataStore = .nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        config.suppressesIncrementalRendering = true

        let view = WKWebView(frame: .zero, configuration: config)
        view.navigationDelegate = self
        webView = view

        // about:blank gives a real JavaScript environment with URL and friends,
        // and no origin that could load anything.
        view.loadHTMLString("<!doctype html><meta charset=\"utf-8\">", baseURL: nil)

        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            pending.append(c)
        }

        guard let source = Self.engineSource() else {
            throw EngineError.evaluationFailed("shadow-engine.js is missing from the app bundle")
        }
        _ = try await evaluate(source)

        let version = try await evaluate("ShadowEngine.version") as? String
        ready = (version != nil)
        if !ready { throw EngineError.evaluationFailed("engine loaded but did not register") }
    }

    private static func engineSource() -> String? {
        guard let url = Bundle.main.url(forResource: "shadow-engine", withExtension: "js") else { return nil }
        return try? String(contentsOf: url, encoding: .utf8)
    }

    // MARK: - Public checks

    /// Score a URL before anything is fetched. This gates every navigation.
    func checkURL(_ url: String, mode: String = "balanced") async throws -> Verdict {
        try await decode("ShadowEngine.checkUrl(\(json(url)), { mode: \(json(mode)) })")
    }

    /// Score a page once its HTML is in hand.
    func checkPage(html: String, url: String, mode: String = "balanced") async throws -> Verdict {
        try await decode("ShadowEngine.checkPage(\(json(html)), \(json(url)), { mode: \(json(mode)) })")
    }

    /// Take a downloaded file apart. Bytes are handed over as base64 because
    /// that is the only lossless way through evaluateJavaScript.
    func scanFile(data: Data, name: String, mode: String = "balanced") async throws -> Verdict {
        let base64 = data.base64EncodedString()
        let script = """
        (function () {
          var raw = atob(\(json(base64)));
          var bytes = new Uint8Array(raw.length);
          for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
          return ShadowEngine.scanBytes(bytes, { name: \(json(name)), opts: { mode: \(json(mode)) } });
        }())
        """
        return try await decode(script)
    }

    // MARK: - Plumbing

    private func decode(_ script: String) async throws -> Verdict {
        guard ready else { throw EngineError.notReady }
        // Serialise inside the engine's own context so we decode one clean
        // JSON string rather than a bridged dictionary of Any.
        let wrapped = "JSON.stringify((function () { return \(script); }()))"
        guard let raw = try await evaluate(wrapped) as? String,
              let data = raw.data(using: .utf8) else {
            throw EngineError.badResponse
        }
        return try JSONDecoder().decode(Verdict.self, from: data)
    }

    private func evaluate(_ script: String) async throws -> Any? {
        guard let webView else { throw EngineError.notReady }
        return try await withCheckedThrowingContinuation { continuation in
            webView.evaluateJavaScript(script) { value, error in
                if let error {
                    continuation.resume(throwing: EngineError.evaluationFailed(error.localizedDescription))
                } else {
                    continuation.resume(returning: value)
                }
            }
        }
    }

    /// JSON-encode a Swift string into a JavaScript literal. Never build these
    /// by hand: a page title containing a quote would otherwise inject code
    /// into the analyst.
    private func json(_ value: String) -> String {
        let data = try? JSONSerialization.data(withJSONObject: [value], options: [])
        guard let data, var text = String(data: data, encoding: .utf8) else { return "\"\"" }
        text.removeFirst()   // drop [
        text.removeLast()    // drop ]
        return text
    }
}

extension ShadowEngine: WKNavigationDelegate {
    nonisolated func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        Task { @MainActor in
            let waiting = pending
            pending = []
            waiting.forEach { $0.resume() }
        }
    }

    nonisolated func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        Task { @MainActor in
            let waiting = pending
            pending = []
            waiting.forEach { $0.resume(throwing: EngineError.evaluationFailed(error.localizedDescription)) }
        }
    }
}
