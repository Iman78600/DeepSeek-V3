//
//  ContentView.swift
//  The browser chrome: address bar, verdict badge, block page, downloads.
//

import SwiftUI
import WebKit

struct ContentView: View {
    @StateObject private var model = BrowserModel()
    @StateObject private var downloads = DownloadGuard.shared
    @State private var address = ""
    @State private var showDownloads = false
    @State private var showReport = false
    @FocusState private var addressFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider().overlay(Palette.line)

            ZStack {
                WebViewHost(webView: model.webView)

                if let blocked = model.blockedVerdict {
                    BlockPage(verdict: blocked,
                              onBack: model.dismissBlock,
                              onProceed: model.proceedAnyway)
                        .transition(.opacity)
                }
            }
        }
        .background(Palette.ink)
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showDownloads) { DownloadList(downloads: downloads) }
        .sheet(isPresented: $showReport) { ReportSheet(verdict: model.verdict) }
        .safeAreaInset(edge: .bottom) {
            if let failure = model.engineFailure { EngineBanner(message: failure) }
        }
        .onChange(of: model.url) { _, new in
            if !addressFocused { address = new }
        }
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            Button { model.webView.goBack() } label: { Image(systemName: "chevron.left") }
                .disabled(!model.canGoBack)

            HStack(spacing: 8) {
                Button { showReport = true } label: {
                    Circle()
                        .fill(verdictColor)
                        .frame(width: 9, height: 9)
                }
                .accessibilityLabel("Site report")

                TextField("Search or enter address", text: $address)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .submitLabel(.go)
                    .focused($addressFocused)
                    .font(.system(size: 15, design: .monospaced))
                    .onSubmit {
                        model.go(to: address)
                        addressFocused = false
                    }

                if model.isLoading {
                    ProgressView().scaleEffect(0.7)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(Palette.panel)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Palette.line))

            Button { showDownloads = true } label: {
                Image(systemName: downloads.files.contains(where: \.isBlocked)
                      ? "exclamationmark.arrow.down.circle.fill"
                      : "arrow.down.circle")
            }
            .foregroundStyle(downloads.files.contains(where: \.isBlocked) ? Palette.danger : Palette.text)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Palette.ink)
        .tint(Palette.accent)
    }

    private var verdictColor: Color {
        switch model.verdict?.verdict {
        case .block: return Palette.danger
        case .warn:  return Palette.caution
        case .allow: return Palette.clear
        case nil:    return Palette.muted
        }
    }
}

/// Hosts the single WKWebView. Deliberately one web view for the whole app:
/// every page shares one hardened configuration, so there is no way to end up
/// browsing in a view that was created without the shield.
struct WebViewHost: UIViewRepresentable {
    let webView: WKWebView
    func makeUIView(context: Context) -> WKWebView { webView }
    func updateUIView(_ view: WKWebView, context: Context) {}
}

// MARK: - The block page

struct BlockPage: View {
    let verdict: Verdict
    let onBack: () -> Void
    let onProceed: () -> Void
    @State private var confirming = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Shadow blocked this page")
                        .font(.system(size: 24, weight: .semibold))
                    Text(verdict.hostname ?? "")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundStyle(Palette.muted)
                }

                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(verdict.score)")
                        .font(.system(size: 40, weight: .bold, design: .monospaced))
                        .foregroundStyle(Palette.danger)
                    Text("risk out of 100")
                        .font(.system(size: 13))
                        .foregroundStyle(Palette.muted)
                }

                ForEach(verdict.signals.filter { $0.score > 0 }.prefix(6)) { signal in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(signal.severity.uppercased())
                            .font(.system(size: 9, weight: .medium, design: .monospaced))
                            .tracking(1)
                            .foregroundStyle(Palette.severity(signal.severity))
                        Text(signal.title).font(.system(size: 15, weight: .semibold))
                        Text(signal.detail)
                            .font(.system(size: 13))
                            .foregroundStyle(Palette.muted)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Palette.panel)
                    .overlay(alignment: .leading) {
                        Rectangle().fill(Palette.severity(signal.severity)).frame(width: 3)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }

                VStack(spacing: 10) {
                    Button("Go back to safety", action: onBack)
                        .buttonStyle(.borderedProminent)
                        .frame(maxWidth: .infinity)

                    Button(confirming ? "Yes, I understand the risk" : "Continue anyway") {
                        if confirming { onProceed() } else { confirming = true }
                    }
                    .foregroundStyle(Palette.danger)
                    .frame(maxWidth: .infinity)
                }
                .padding(.top, 4)

                Text("Shadow decided this on your phone. Nothing about the pages you visit is sent anywhere.")
                    .font(.system(size: 11))
                    .foregroundStyle(Palette.muted)
            }
            .padding(20)
        }
        .background(Palette.blockGround)
    }
}

// MARK: - Downloads

struct DownloadList: View {
    @ObservedObject var downloads: DownloadGuard

    var body: some View {
        NavigationStack {
            Group {
                if downloads.files.isEmpty {
                    ContentUnavailableView(
                        "Nothing downloaded",
                        systemImage: "tray",
                        description: Text("Files land in a sandbox and are taken apart before you can open them."))
                } else {
                    List(downloads.files) { file in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack {
                                Text(file.name).font(.system(size: 15, weight: .semibold))
                                Spacer()
                                if let v = file.verdict {
                                    Text(v.verdict.rawValue.uppercased())
                                        .font(.system(size: 9, weight: .medium, design: .monospaced))
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(Palette.verdict(v.verdict).opacity(0.18))
                                        .foregroundStyle(Palette.verdict(v.verdict))
                                        .clipShape(Capsule())
                                }
                            }
                            if let top = file.verdict?.topFinding {
                                Text(top.title).font(.system(size: 12)).foregroundStyle(Palette.muted)
                            }
                            Text(ByteCountFormatter.string(fromByteCount: Int64(file.size), countStyle: .file))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Palette.muted)
                        }
                        .swipeActions {
                            Button("Delete", role: .destructive) { downloads.remove(file) }
                        }
                    }
                }
            }
            .navigationTitle("Downloads")
            .navigationBarTitleDisplayMode(.inline)
        }
        .preferredColorScheme(.dark)
    }
}

struct ReportSheet: View {
    let verdict: Verdict?

    var body: some View {
        NavigationStack {
            Group {
                if let verdict, !verdict.signals.filter({ $0.score > 0 }).isEmpty {
                    List(verdict.signals.filter { $0.score > 0 }) { signal in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(signal.severity.uppercased())
                                .font(.system(size: 9, weight: .medium, design: .monospaced))
                                .foregroundStyle(Palette.severity(signal.severity))
                            Text(signal.title).font(.system(size: 15, weight: .semibold))
                            Text(signal.detail).font(.system(size: 13)).foregroundStyle(Palette.muted)
                        }
                    }
                } else {
                    ContentUnavailableView(
                        "Nothing to report",
                        systemImage: "checkmark.shield",
                        description: Text("None of Shadow's checks fired on this page."))
                }
            }
            .navigationTitle("Site report")
            .navigationBarTitleDisplayMode(.inline)
        }
        .preferredColorScheme(.dark)
    }
}

/// Shown when the analyst failed to start. A browser that quietly stops
/// analysing while still showing a shield is worse than one that admits it.
struct EngineBanner: View {
    let message: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
            VStack(alignment: .leading, spacing: 1) {
                Text("The analyst is not running").font(.system(size: 13, weight: .semibold))
                Text(message).font(.system(size: 11)).foregroundStyle(Palette.muted)
            }
            Spacer()
        }
        .padding(12)
        .background(Palette.caution.opacity(0.12))
        .overlay(alignment: .top) { Rectangle().fill(Palette.caution).frame(height: 2) }
    }
}

enum Palette {
    static let ink        = Color(red: 0.039, green: 0.047, blue: 0.067)
    static let blockGround = Color(red: 0.071, green: 0.027, blue: 0.039)
    static let panel      = Color(red: 0.071, green: 0.086, blue: 0.122)
    static let line       = Color(red: 0.145, green: 0.173, blue: 0.227)
    static let text       = Color(red: 0.894, green: 0.910, blue: 0.941)
    static let muted      = Color(red: 0.494, green: 0.529, blue: 0.600)
    static let accent     = Color(red: 0.357, green: 0.612, blue: 1.0)
    static let clear      = Color(red: 0.243, green: 0.812, blue: 0.557)
    static let caution    = Color(red: 0.941, green: 0.706, blue: 0.161)
    static let high       = Color(red: 1.0, green: 0.561, blue: 0.302)
    static let danger     = Color(red: 1.0, green: 0.365, blue: 0.365)

    static func severity(_ name: String) -> Color {
        switch name {
        case "critical": return danger
        case "high":     return high
        case "medium":   return caution
        case "info":     return accent
        default:         return muted
        }
    }

    static func verdict(_ call: Verdict.Call) -> Color {
        switch call {
        case .block: return danger
        case .warn:  return caution
        case .allow: return clear
        }
    }
}
