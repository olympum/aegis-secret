import AegisSecretCore
import Foundation
import XCTest

final class NoopAuthenticator: DeviceAuthenticator {
    func authenticate(reason: String) async throws {}
}

struct InMemorySecretStore: SecretStore {
    var secrets: [String: Data]

    init(secrets: [String: Data] = [:]) {
        self.secrets = secrets
    }

    func setSecret(_ secretData: Data, for key: String) throws {}

    func readSecret(for key: String) throws -> Data {
        guard let secret = secrets[key] else {
            throw AegisSecretError.runtime("missing secret")
        }
        return secret
    }

    func deleteSecret(for key: String) throws -> Bool {
        secrets[key] != nil
    }

    func listSecrets() throws -> [SecretListItem] {
        secrets.keys.sorted().map(SecretListItem.init(key:))
    }

    func secretExists(for key: String) throws -> Bool {
        secrets[key] != nil
    }
}

final class MockHTTPSession: HTTPSession {
    let handler: @Sendable (URLRequest) throws -> (Data, URLResponse)

    init(handler: @escaping @Sendable (URLRequest) throws -> (Data, URLResponse)) {
        self.handler = handler
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try handler(request)
    }
}

final class AegisSecretCoreTests: XCTestCase {
    func testHelpWhenNoArguments() throws {
        XCTAssertEqual(try CommandParser().parse([], stdinIsTTY: true), .help)
    }

    func testSetDefaultsToPromptWhenTTY() throws {
        XCTAssertEqual(
            try CommandParser().parse(["set", "OPENAI_API_KEY"], stdinIsTTY: true),
            .set(key: "OPENAI_API_KEY", inputMode: .prompt)
        )
    }

    func testSetDefaultsToStdinWhenPiped() throws {
        XCTAssertEqual(
            try CommandParser().parse(["set", "OPENAI_API_KEY"], stdinIsTTY: false),
            .set(key: "OPENAI_API_KEY", inputMode: .stdin)
        )
    }

    func testGetRequiresAgentName() {
        XCTAssertThrowsError(try CommandParser().parse(["get", "OPENAI_API_KEY"], stdinIsTTY: true)) { error in
            XCTAssertEqual(
                error as? AegisSecretError,
                .usage("`get` requires `--agent <name>` so the approval prompt identifies the caller.")
            )
        }
    }

    func testDeleteParses() throws {
        XCTAssertEqual(
            try CommandParser().parse(["delete", "OPENAI_API_KEY"], stdinIsTTY: true),
            .delete(key: "OPENAI_API_KEY")
        )
    }

    func testPolicyValidateFileParses() throws {
        XCTAssertEqual(
            try CommandParser().parse(["policy", "validate", "--file", "/tmp/policies.json"], stdinIsTTY: true),
            .policy(.validateFile(path: "/tmp/policies.json"))
        )
    }

    func testPolicyConfigResolvesDefaults() throws {
        let policy = try PolicyConfig(
            name: "openai-api",
            secretKey: "OPENAI_API_KEY",
            baseURL: "https://api.openai.com",
            allowedMethods: ["get", "post"],
            authMode: .bearer,
            allowedPathPrefixes: ["/v1"]
        ).resolved()

        XCTAssertEqual(policy.allowedHosts, ["api.openai.com"])
        XCTAssertEqual(policy.allowedMethods, ["GET", "POST"])
        XCTAssertEqual(policy.authHeaderName, "Authorization")
        XCTAssertEqual(policy.authHeaderPrefix, "Bearer ")
    }

    func testBrokerRejectsDisallowedHost() async throws {
        let tempDirectory = try temporaryDirectory()
        let policyFile = tempDirectory.appendingPathComponent("policies.json")
        try prettyJSON(
            PolicyFile(policies: [
                PolicyConfig(
                    name: "openai-api",
                    secretKey: "OPENAI_API_KEY",
                    baseURL: "https://api.openai.com",
                    allowedMethods: ["GET"],
                    authMode: .bearer,
                    allowedPathPrefixes: ["/v1"]
                )
            ])
        ).write(to: policyFile)

        let broker = HTTPPolicyBroker(
            policyStore: PolicyStore(fileURL: policyFile),
            secretStore: InMemorySecretStore(secrets: ["OPENAI_API_KEY": Data("secret".utf8)]),
            authenticator: NoopAuthenticator(),
            session: MockHTTPSession { _ in
                XCTFail("network call should not run")
                throw URLError(.badServerResponse)
            }
        )

        do {
            _ = try await broker.request(
                policy: "openai-api",
                request: BrokerRequest(method: "GET", url: "https://evil.example.com/v1/models"),
                requester: "Test"
            )
            XCTFail("expected request to fail")
        } catch let error as AegisSecretError {
            XCTAssertTrue(error.description.contains("not allowed"))
        }
    }

    func testBrokerInjectsAuthorizationHeader() async throws {
        let tempDirectory = try temporaryDirectory()
        let policyFile = tempDirectory.appendingPathComponent("policies.json")
        try prettyJSON(
            PolicyFile(policies: [
                PolicyConfig(
                    name: "openai-api",
                    description: "OpenAI API access",
                    secretKey: "OPENAI_API_KEY",
                    baseURL: "https://api.openai.com",
                    allowedMethods: ["POST"],
                    authMode: .bearer,
                    allowedPathPrefixes: ["/v1"],
                    defaultHeaders: ["Accept": "application/json"]
                )
            ])
        ).write(to: policyFile)

        let session = MockHTTPSession { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer secret")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(String(data: request.httpBody ?? Data(), encoding: .utf8), #"{"prompt":"hi"}"#)

            let response = HTTPURLResponse(
                url: try XCTUnwrap(request.url),
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (Data(#"{"ok":true}"#.utf8), response)
        }

        let broker = HTTPPolicyBroker(
            policyStore: PolicyStore(fileURL: policyFile),
            secretStore: InMemorySecretStore(secrets: ["OPENAI_API_KEY": Data("secret".utf8)]),
            authenticator: NoopAuthenticator(),
            session: session
        )

        let response = try await broker.request(
            policy: "openai-api",
            request: BrokerRequest(
                method: "POST",
                path: "/v1/responses",
                headers: [:],
                bodyData: Data(#"{"prompt":"hi"}"#.utf8),
                bodyIsStructuredJSON: true
            ),
            requester: "Test"
        )

        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(response.body, #"{"ok":true}"#)
        XCTAssertNil(response.bodyBase64)
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
