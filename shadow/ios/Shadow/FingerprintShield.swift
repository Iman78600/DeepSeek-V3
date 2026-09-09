//
//  FingerprintShield.swift
//  Loads the shared shield source and injects it into every page.
//
//  This is where the desktop build's design decision pays off. Because the
//  shield was written as a *source string* rather than a preload module (the
//  desktop needs that too, since context isolation gives a preload its own
//  copies of navigator and the canvas prototypes), the identical source runs
//  here as a WKUserScript at document start.
//
//  Same rules, same noise algorithm, one place to maintain.
//

import Foundation
import WebKit

enum FingerprintShield {

    /// A common User-Agent so Shadow users look alike rather than unique.
    /// Deliberately not a real Safari string with the app's name appended:
    /// naming the app would be the strongest fingerprint on the device.
    static let genericUserAgent =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
        + "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"

    /// A per-launch seed. Stable within a session so a site cannot average the
    /// noise away by sampling repeatedly, and different every launch so the
    /// noise is not itself a long-lived identifier.
    private static let seed: UInt32 = UInt32.random(in: 0...UInt32.max)

    static func userScript() -> WKUserScript? {
        guard let url = Bundle.main.url(forResource: "fingerprint-shield", withExtension: "js"),
              let template = try? String(contentsOf: url, encoding: .utf8) else { return nil }

        let source = template
            .replacingOccurrences(of: "__SHADOW_SEED__", with: String(seed))
            .replacingOccurrences(of: "__SHADOW_CONFIG__", with: config)

        return WKUserScript(source: source,
                            injectionTime: .atDocumentStart,   // before any page script
                            forMainFrameOnly: false)           // frames fingerprint too
    }

    private static var config: String {
        // Kept as JSON so the shared source parses it the same way on both
        // platforms. WebGL masking is always on: on iOS the GPU string is a
        // near-unique device identifier.
        """
        {"canvasNoise":true,"fontProtection":true,"timingJitter":true,"blockWebgl":false}
        """
    }
}
