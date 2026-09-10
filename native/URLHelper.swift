import AppKit
import CoreServices
import Foundation

func output(_ value: Any) {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    print(String(data: data, encoding: .utf8)!)
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

let args = CommandLine.arguments
if args.count > 1 {
    switch args[1] {
    case "status":
        guard args.count == 3, let url = URL(string: args[2] + "://callback") else { fail("Expected scheme") }
        if let application = NSWorkspace.shared.urlForApplication(toOpen: url) {
            output(["path": application.path, "bundleId": Bundle(url: application)?.bundleIdentifier ?? ""])
        } else {
            output(["path": NSNull(), "bundleId": NSNull()])
        }
        exit(0)
    case "stop":
        guard args.count == 3 else { fail("Expected application path") }
        let target = URL(fileURLWithPath: args[2]).standardizedFileURL
        for running in NSWorkspace.shared.runningApplications {
            if running.bundleURL?.standardizedFileURL == target { running.terminate() }
        }
        exit(0)
    case "set":
        guard args.count == 4 else { fail("Expected scheme and application path") }
        let application = URL(fileURLWithPath: args[3])
        guard LSRegisterURL(application as CFURL, true) == noErr else { fail("Application registration failed") }
        NSWorkspace.shared.setDefaultApplication(at: application, toOpenURLsWithScheme: args[2]) { error in
            if error != nil { fail("Default application change failed") }
            output(["ok": true])
            exit(0)
        }
        RunLoop.main.run()
    default: fail("Unknown command")
    }
    exit(0)
}

struct Forwarding: Decodable {
    let endpoint: String
    let token: String
}

final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        // The configured loopback receiver must never redirect a code elsewhere.
        completionHandler(nil)
    }
}

final class Receiver: NSObject, NSApplicationDelegate {
    var idleTimer: Timer?
    var pending = 0
    let forwardingSession = URLSession(configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)

    func applicationWillFinishLaunching(_ notification: Notification) {
        NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(receive(_:reply:)),
            forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
    }

    func applicationDidFinishLaunching(_ notification: Notification) { scheduleExit() }

    func scheduleExit() {
        idleTimer?.invalidate()
        idleTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: false) { _ in
            if self.pending == 0 { NSApplication.shared.terminate(nil) }
            else { self.scheduleExit() }
        }
    }

    @objc func receive(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        // Keep the exact string delivered by macOS, including percent escapes and fragment.
        guard let payload = event.paramDescriptor(forKeyword: keyDirectObject)?.stringValue,
              let configURL = Bundle.main.url(forResource: "forwarding", withExtension: "json"),
              let data = try? Data(contentsOf: configURL),
              let config = try? JSONDecoder().decode(Forwarding.self, from: data),
              let endpoint = URL(string: config.endpoint),
              endpoint.scheme == "http", ["127.0.0.1", "[::1]", "::1"].contains(endpoint.host ?? "")
        else { fail("Invalid forwarding configuration or URL event") }
        var request = URLRequest(url: endpoint, timeoutInterval: 5)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer " + config.token, forHTTPHeaderField: "Authorization")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["url": payload])
        pending += 1
        forwardingSession.dataTask(with: request) { _, response, error in
            // Never log callback URLs, authorization codes, or credentials.
            if error != nil || (response as? HTTPURLResponse)?.statusCode != 204 {
                FileHandle.standardError.write(Data("Callback forwarding failed\n".utf8))
            }
            DispatchQueue.main.async { self.pending -= 1; self.scheduleExit() }
        }.resume()
        scheduleExit()
    }
}

let app = NSApplication.shared
let receiver = Receiver()
app.delegate = receiver
app.setActivationPolicy(.prohibited)
app.run()
