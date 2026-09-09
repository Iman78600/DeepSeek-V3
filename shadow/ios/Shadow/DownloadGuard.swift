//
//  DownloadGuard.swift
//  Downloads land in quarantine and are scanned before you can reach them.
//
//  iOS helps here. An app's container is already isolated, nothing downloaded
//  can execute, and the file is invisible to other apps until it is exported.
//  So quarantine on iOS is less about stopping execution and more about the
//  question that actually matters on a phone: is this thing safe to forward,
//  open in another app, or move to a computer where it *can* run.
//

import Foundation
import WebKit

struct QuarantinedFile: Identifiable {
    let id = UUID()
    let name: String
    let path: URL
    let size: Int
    let receivedAt: Date
    var verdict: Verdict?

    var isBlocked: Bool { verdict?.isBlocked ?? false }
}

@MainActor
final class DownloadGuard: NSObject, ObservableObject {

    static let shared = DownloadGuard()

    @Published private(set) var files: [QuarantinedFile] = []
    @Published var lastError: String?

    /// Everything downloaded lives here and nowhere else until released.
    private lazy var quarantineDir: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("Quarantine", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.protectionKey: FileProtectionType.complete])
        return dir
    }()

    private var inFlight: [ObjectIdentifier: URL] = [:]

    /// Strip anything from a server-supplied filename that could escape the
    /// directory or hide the real extension. Same reasoning as the desktop:
    /// a right-to-left override makes "invoice[U+202E]gpj.exe" read as a JPEG.
    static func safeName(_ raw: String) -> String {
        let forbidden = CharacterSet(charactersIn: "/\\:*?\"<>|")
            .union(.controlCharacters)
            .union(CharacterSet(charactersIn: "\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}\u{200E}\u{200F}\u{061C}"))

        let cleaned = raw.components(separatedBy: forbidden).joined(separator: "_")
        let base = (cleaned as NSString).lastPathComponent
        let trimmed = base.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty || trimmed.hasPrefix(".") { return "download.bin" }
        return String(trimmed.prefix(180))
    }

    func removeAll() {
        for file in files { try? FileManager.default.removeItem(at: file.path) }
        files.removeAll()
    }

    func remove(_ file: QuarantinedFile) {
        try? FileManager.default.removeItem(at: file.path)
        files.removeAll { $0.id == file.id }
    }
}

extension DownloadGuard: WKDownloadDelegate {

    nonisolated func download(_ download: WKDownload,
                              decideDestinationUsing response: URLResponse,
                              suggestedFilename: String,
                              completionHandler: @escaping (URL?) -> Void) {
        Task { @MainActor in
            let name = Self.safeName(suggestedFilename)
            // A ".quarantined" suffix, so nothing offers to open it by type
            // before Shadow has looked at it.
            var target = self.quarantineDir.appendingPathComponent(name + ".quarantined")
            var n = 1
            while FileManager.default.fileExists(atPath: target.path) {
                target = self.quarantineDir.appendingPathComponent("\(name) (\(n)).quarantined")
                n += 1
            }
            self.inFlight[ObjectIdentifier(download)] = target
            completionHandler(target)
        }
    }

    nonisolated func downloadDidFinish(_ download: WKDownload) {
        Task { @MainActor in
            guard let path = self.inFlight.removeValue(forKey: ObjectIdentifier(download)) else { return }
            let displayName = path.lastPathComponent
                .replacingOccurrences(of: ".quarantined", with: "")

            guard let data = try? Data(contentsOf: path) else {
                self.lastError = "\(displayName) could not be read after downloading."
                return
            }

            var record = QuarantinedFile(name: displayName, path: path,
                                         size: data.count, receivedAt: Date(), verdict: nil)

            // Cap what is handed to the analyst. A very large file is scanned
            // from its head, which is where headers, sections and the strings
            // that matter live.
            let head = data.count > 32_000_000 ? data.prefix(32_000_000) : data
            record.verdict = try? await ShadowEngine.shared.scanFile(data: Data(head), name: displayName)
            self.files.insert(record, at: 0)
        }
    }

    nonisolated func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        Task { @MainActor in
            if let path = self.inFlight.removeValue(forKey: ObjectIdentifier(download)) {
                try? FileManager.default.removeItem(at: path)
            }
            self.lastError = error.localizedDescription
        }
    }
}
