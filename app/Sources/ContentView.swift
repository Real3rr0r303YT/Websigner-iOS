import SwiftUI

struct ContentView: View {
    private let landingPage = URL(string: "https://real3rr0r303yt.github.io/Websigner-iOS/")!
    private let guide = URL(string: "https://real3rr0r303yt.github.io/Websigner-iOS/#guide")!
    private let source = URL(string: "https://github.com/Real3rr0r303YT/Websigner-iOS")!
    private let donate = URL(string: "https://www.buymeacoffee.com/3rr0r303yt")!

    private var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "v\(short) (\(build))"
    }

    var body: some View {
        NavigationView {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("WebSigner")
                            .font(.largeTitle.bold())
                        Text("Open-source direct web installer & signer for iOS.")
                            .foregroundColor(.secondary)
                        Text(version)
                            .font(.footnote.monospaced())
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 8)
                }

                Section("Links") {
                    Link("Landing page", destination: landingPage)
                    Link("DNS / Anti-Revoke Guide", destination: guide)
                    Link("Source code on GitHub", destination: source)
                    Link("Buy Me a Coffee", destination: donate)
                }

                Section {
                    Text("Licensed under the GNU General Public License v3.0.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("WebSigner")
            .navigationBarTitleDisplayMode(.inline)
        }
        .navigationViewStyle(.stack)
    }
}
