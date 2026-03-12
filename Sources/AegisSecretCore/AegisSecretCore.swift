import Foundation
import LocalAuthentication
import Security

public let aegisSecretServiceName = "Aegis Secrets"
public let policiesFileEnvironmentKey = "AEGIS_SECRET_POLICIES_FILE"
public let capabilitiesFileEnvironmentKey = "AEGIS_SECRET_CAPABILITIES_FILE"

public enum ExitCode: Int32 {
    case success = 0
    case usage = 64
    case failure = 1
}

public enum AegisSecretError: Error, CustomStringConvertible, Equatable {
    case usage(String)
    case runtime(String)

    public var description: String {
        switch self {
        case .usage(let message), .runtime(let message):
            return message
        }
    }
}

public protocol DeviceAuthenticator: Sendable {
    func authenticate(reason: String) async throws
}

public final class LocalDeviceAuthenticator: DeviceAuthenticator, @unchecked Sendable {
    public init() {}

    public func authenticate(reason: String) async throws {
        let context = LAContext()
        var evaluationError: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            let details = evaluationError?.localizedDescription ?? "Unknown authentication error"
            throw AegisSecretError.runtime("Device owner authentication is unavailable: \(details).")
        }

        try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if success {
                    continuation.resume()
                    return
                }

                if let error {
                    continuation.resume(throwing: AegisSecretError.runtime("Authentication failed: \(error.localizedDescription)."))
                } else {
                    continuation.resume(throwing: AegisSecretError.runtime("Authentication was cancelled."))
                }
            }
        }
    }
}

public struct SecretListItem: Equatable, Codable, Sendable {
    public let key: String

    public init(key: String) {
        self.key = key
    }
}

public protocol SecretStore: Sendable {
    func setSecret(_ secretData: Data, for key: String) throws
    func readSecret(for key: String) throws -> Data
    func deleteSecret(for key: String) throws -> Bool
    func listSecrets() throws -> [SecretListItem]
    func secretExists(for key: String) throws -> Bool
}

public struct KeychainSecretStore: SecretStore {
    public let serviceName: String

    public init(serviceName: String = aegisSecretServiceName) {
        self.serviceName = serviceName
    }

    public func setSecret(_ secretData: Data, for key: String) throws {
        let deleteQuery = baseQuery(for: key)
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw AegisSecretError.runtime("Unable to replace existing secret `\(key)`: \(message(for: deleteStatus)).")
        }

        var addQuery = baseQuery(for: key)
        addQuery[kSecValueData as String] = secretData
        addQuery[kSecAttrLabel as String] = "Aegis secret: \(key)"
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw AegisSecretError.runtime("Unable to store secret `\(key)`: \(message(for: addStatus)).")
        }
    }

    public func readSecret(for key: String) throws -> Data {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw AegisSecretError.runtime("Unable to retrieve secret `\(key)`: \(message(for: status)).")
        }

        guard let data = item as? Data else {
            throw AegisSecretError.runtime("Keychain returned invalid data for `\(key)`.")
        }

        return data
    }

    public func deleteSecret(for key: String) throws -> Bool {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw AegisSecretError.runtime("Unable to delete secret `\(key)`: \(message(for: status)).")
        }
    }

    public func listSecrets() throws -> [SecretListItem] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let dictionaries = item as? [[String: Any]] else {
                throw AegisSecretError.runtime("Keychain returned an unexpected response while listing secrets.")
            }
            return dictionaries
                .compactMap { dictionary in
                    (dictionary[kSecAttrAccount as String] as? String).map(SecretListItem.init(key:))
                }
                .sorted { $0.key < $1.key }
        case errSecItemNotFound:
            return []
        default:
            throw AegisSecretError.runtime("Unable to list secrets: \(message(for: status)).")
        }
    }

    public func secretExists(for key: String) throws -> Bool {
        var query = baseQuery(for: key)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw AegisSecretError.runtime("Unable to check secret `\(key)`: \(message(for: status)).")
        }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
    }
}

public enum AuthMode: String, Codable, Sendable {
    case bearer
    case header
}

public struct CapabilityConfig: Codable, Equatable, Sendable {
    public let name: String
    public let description: String?
    public let secretKey: String
    public let baseURL: String
    public let allowedHosts: [String]?
    public let allowedMethods: [String]
    public let authMode: AuthMode
    public let headerName: String?
    public let headerPrefix: String?
    public let allowedPathPrefixes: [String]
    public let defaultHeaders: [String: String]?

    public init(
        name: String,
        description: String? = nil,
        secretKey: String,
        baseURL: String,
        allowedHosts: [String]? = nil,
        allowedMethods: [String],
        authMode: AuthMode,
        headerName: String? = nil,
        headerPrefix: String? = nil,
        allowedPathPrefixes: [String],
        defaultHeaders: [String: String]? = nil
    ) {
        self.name = name
        self.description = description
        self.secretKey = secretKey
        self.baseURL = baseURL
        self.allowedHosts = allowedHosts
        self.allowedMethods = allowedMethods
        self.authMode = authMode
        self.headerName = headerName
        self.headerPrefix = headerPrefix
        self.allowedPathPrefixes = allowedPathPrefixes
        self.defaultHeaders = defaultHeaders
    }

    private enum CodingKeys: String, CodingKey {
        case name
        case description
        case secretKey = "secret_key"
        case baseURL = "base_url"
        case allowedHosts = "allowed_hosts"
        case allowedMethods = "allowed_methods"
        case authMode = "auth_mode"
        case headerName = "header_name"
        case headerPrefix = "header_prefix"
        case allowedPathPrefixes = "allowed_path_prefixes"
        case defaultHeaders = "default_headers"
    }

    public func resolved() throws -> ResolvedCapability {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            throw AegisSecretError.runtime("Policy names cannot be empty.")
        }

        let trimmedSecretKey = secretKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedSecretKey.isEmpty else {
            throw AegisSecretError.runtime("Policy `\(trimmedName)` is missing `secret_key`.")
        }

        guard let baseURL = URL(string: baseURL), let scheme = baseURL.scheme?.lowercased(), let host = baseURL.host?.lowercased() else {
            throw AegisSecretError.runtime("Policy `\(trimmedName)` has an invalid `base_url`.")
        }

        guard scheme == "https" || scheme == "http" else {
            throw AegisSecretError.runtime("Policy `\(trimmedName)` must use http or https.")
        }

        let hosts = Set((allowedHosts ?? [host]).map { $0.lowercased() })
        guard !hosts.isEmpty else {
            throw AegisSecretError.runtime("Policy `\(trimmedName)` must allow at least one host.")
        }

        let methods = Set(allowedMethods.map { $0.uppercased() })
        let validMethods = Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        guard !methods.isEmpty, methods.isSubset(of: validMethods) else {
            throw AegisSecretError.runtime("Policy `\(trimmedName)` has invalid `allowed_methods`.")
        }

        let pathPrefixes = allowedPathPrefixes.map { normalizePathPrefix($0) }
        guard !pathPrefixes.isEmpty else {
            throw AegisSecretError.runtime("Policy `\(trimmedName)` must declare `allowed_path_prefixes`.")
        }

        let resolvedHeaderName: String
        let resolvedHeaderPrefix: String
        switch authMode {
        case .bearer:
            resolvedHeaderName = (headerName?.trimmedNonEmpty) ?? "Authorization"
            resolvedHeaderPrefix = headerPrefix ?? "Bearer "
        case .header:
            guard let headerName = headerName?.trimmedNonEmpty else {
                throw AegisSecretError.runtime("Policy `\(trimmedName)` with `header` auth_mode requires `header_name`.")
            }
            resolvedHeaderName = headerName
            resolvedHeaderPrefix = headerPrefix ?? ""
        }

        let normalizedHeaders = Dictionary(uniqueKeysWithValues: (defaultHeaders ?? [:]).map { key, value in
            (key, value)
        })

        return ResolvedCapability(
            name: trimmedName,
            description: description,
            secretKey: trimmedSecretKey,
            baseURL: baseURL,
            allowedHosts: hosts,
            allowedMethods: methods,
            authMode: authMode,
            authHeaderName: resolvedHeaderName,
            authHeaderPrefix: resolvedHeaderPrefix,
            allowedPathPrefixes: pathPrefixes,
            defaultHeaders: normalizedHeaders
        )
    }
}

public struct CapabilityFile: Codable, Equatable, Sendable {
    public let capabilities: [CapabilityConfig]

    public init(capabilities: [CapabilityConfig]) {
        self.capabilities = capabilities
    }

    private enum CodingKeys: String, CodingKey {
        case policies
        case capabilities
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let policies = try container.decodeIfPresent([CapabilityConfig].self, forKey: .policies) {
            self.capabilities = policies
            return
        }
        if let capabilities = try container.decodeIfPresent([CapabilityConfig].self, forKey: .capabilities) {
            self.capabilities = capabilities
            return
        }
        self.capabilities = []
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(capabilities, forKey: .policies)
    }
}

public struct CapabilitySummary: Codable, Equatable, Sendable {
    public let name: String
    public let description: String?
    public let baseURL: String
    public let allowedMethods: [String]
    public let allowedPathPrefixes: [String]

    public init(name: String, description: String?, baseURL: String, allowedMethods: [String], allowedPathPrefixes: [String]) {
        self.name = name
        self.description = description
        self.baseURL = baseURL
        self.allowedMethods = allowedMethods
        self.allowedPathPrefixes = allowedPathPrefixes
    }
}

public struct ResolvedCapability: Equatable, Sendable {
    public let name: String
    public let description: String?
    public let secretKey: String
    public let baseURL: URL
    public let allowedHosts: Set<String>
    public let allowedMethods: Set<String>
    public let authMode: AuthMode
    public let authHeaderName: String
    public let authHeaderPrefix: String
    public let allowedPathPrefixes: [String]
    public let defaultHeaders: [String: String]
}

public struct CapabilityProbeResult: Codable, Equatable, Sendable {
    public let ok: Bool
    public let description: String

    public init(ok: Bool, description: String) {
        self.ok = ok
        self.description = description
    }
}

public final class CapabilityStore: @unchecked Sendable {
    public let fileURL: URL

    public init(fileURL: URL = CapabilityStore.defaultURL()) {
        self.fileURL = fileURL
    }

    public static func defaultURL(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let override = environment[policiesFileEnvironmentKey]?.trimmedNonEmpty {
            return URL(fileURLWithPath: expandUserPath(override))
        }
        if let override = environment[capabilitiesFileEnvironmentKey]?.trimmedNonEmpty {
            return URL(fileURLWithPath: expandUserPath(override))
        }

        let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        return homeDirectory
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("aegis-secret", isDirectory: true)
            .appendingPathComponent("policies.json", isDirectory: false)
    }

    public func rawFile(optionalIfMissing: Bool = true) throws -> CapabilityFile {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            if optionalIfMissing {
                return CapabilityFile(capabilities: [])
            }
            throw AegisSecretError.runtime("Policies file not found at `\(fileURL.path)`.")
        }

        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(CapabilityFile.self, from: data)
    }

    public func resolvedCapabilities(optionalIfMissing: Bool = true) throws -> [ResolvedCapability] {
        let file = try rawFile(optionalIfMissing: optionalIfMissing)
        let resolved = try file.capabilities.map { try $0.resolved() }

        let names = resolved.map(\.name)
        if Set(names).count != names.count {
            throw AegisSecretError.runtime("Policies file contains duplicate policy names.")
        }

        return resolved.sorted { $0.name < $1.name }
    }

    public func summaries() throws -> [CapabilitySummary] {
        try resolvedCapabilities().map {
            CapabilitySummary(
                name: $0.name,
                description: $0.description,
                baseURL: $0.baseURL.absoluteString,
                allowedMethods: $0.allowedMethods.sorted(),
                allowedPathPrefixes: $0.allowedPathPrefixes
            )
        }
    }

    public func rawPolicy(named name: String) throws -> CapabilityConfig {
        let file = try rawFile(optionalIfMissing: false)
        guard let capability = file.capabilities.first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Policy `\(name)` was not found.")
        }
        return capability
    }

    public func rawCapability(named name: String) throws -> CapabilityConfig {
        try rawPolicy(named: name)
    }

    public func resolvedPolicy(named name: String) throws -> ResolvedCapability {
        guard let capability = try resolvedCapabilities(optionalIfMissing: false).first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Policy `\(name)` was not found.")
        }
        return capability
    }

    public func resolvedCapability(named name: String) throws -> ResolvedCapability {
        try resolvedPolicy(named: name)
    }

    @discardableResult
    public func importFile(from sourcePath: String) throws -> Int {
        let sourceURL = URL(fileURLWithPath: expandUserPath(sourcePath))
        let data = try Data(contentsOf: sourceURL)
        let file = try JSONDecoder().decode(CapabilityFile.self, from: data)
        _ = try file.capabilities.map { try $0.resolved() }

        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: fileURL, options: .atomic)
        return file.capabilities.count
    }

    public func validateCurrentConfiguration() throws -> Int {
        try resolvedCapabilities(optionalIfMissing: false).count
    }

    public func validateCurrentPolicy(named name: String) throws {
        _ = try resolvedPolicy(named: name)
    }

    public func validateCurrentCapability(named name: String) throws {
        try validateCurrentPolicy(named: name)
    }

    public func validateFile(at path: String) throws -> Int {
        let url = URL(fileURLWithPath: expandUserPath(path))
        let data = try Data(contentsOf: url)
        let file = try JSONDecoder().decode(CapabilityFile.self, from: data)
        _ = try file.capabilities.map { try $0.resolved() }
        return file.capabilities.count
    }
}

public struct BrokerRequest: Equatable, Sendable {
    public let method: String
    public let path: String?
    public let url: String?
    public let headers: [String: String]
    public let bodyData: Data?
    public let bodyIsStructuredJSON: Bool

    public init(
        method: String,
        path: String? = nil,
        url: String? = nil,
        headers: [String: String] = [:],
        bodyData: Data? = nil,
        bodyIsStructuredJSON: Bool = false
    ) {
        self.method = method
        self.path = path
        self.url = url
        self.headers = headers
        self.bodyData = bodyData
        self.bodyIsStructuredJSON = bodyIsStructuredJSON
    }
}

public struct BrokerResponse: Codable, Equatable, Sendable {
    public let status: Int
    public let headers: [String: String]
    public let body: String?
    public let bodyBase64: String?
    public let mimeType: String?
    public let truncated: Bool

    public init(status: Int, headers: [String: String], body: String?, bodyBase64: String?, mimeType: String?, truncated: Bool) {
        self.status = status
        self.headers = headers
        self.body = body
        self.bodyBase64 = bodyBase64
        self.mimeType = mimeType
        self.truncated = truncated
    }
}

public protocol HTTPSession: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: HTTPSession {}

public struct HTTPCapabilityBroker: Sendable {
    public let capabilityStore: CapabilityStore
    public let secretStore: SecretStore
    public let authenticator: DeviceAuthenticator
    public let session: HTTPSession
    public let maxResponseBytes: Int

    public init(
        capabilityStore: CapabilityStore,
        secretStore: SecretStore,
        authenticator: DeviceAuthenticator,
        session: HTTPSession = URLSession.shared,
        maxResponseBytes: Int = 256 * 1024
    ) {
        self.capabilityStore = capabilityStore
        self.secretStore = secretStore
        self.authenticator = authenticator
        self.session = session
        self.maxResponseBytes = maxResponseBytes
    }

    public func probe(capability name: String) throws -> CapabilityProbeResult {
        let capability = try capabilityStore.resolvedPolicy(named: name)
        if try secretStore.secretExists(for: capability.secretKey) {
            return CapabilityProbeResult(ok: true, description: capability.description ?? "Policy is ready.")
        }
        return CapabilityProbeResult(ok: false, description: "The Keychain secret `\(capability.secretKey)` is missing.")
    }

    public func request(capability name: String, request: BrokerRequest, requester: String? = nil) async throws -> BrokerResponse {
        let capability = try capabilityStore.resolvedPolicy(named: name)

        guard try secretStore.secretExists(for: capability.secretKey) else {
            throw AegisSecretError.runtime("Policy `\(capability.name)` is configured, but the Keychain secret `\(capability.secretKey)` is missing.")
        }

        let method = request.method.uppercased()
        guard capability.allowedMethods.contains(method) else {
            throw AegisSecretError.runtime("Method `\(method)` is not allowed for policy `\(capability.name)`.")
        }

        let requestURL = try resolvedURL(for: capability, request: request)
        guard let host = requestURL.host?.lowercased(), capability.allowedHosts.contains(host) else {
            throw AegisSecretError.runtime("Host `\(requestURL.host ?? requestURL.absoluteString)` is not allowed for policy `\(capability.name)`.")
        }

        guard capability.allowedPathPrefixes.contains(where: { matches(path: requestURL.path, allowedPrefix: $0) }) else {
            throw AegisSecretError.runtime("Path `\(requestURL.path)` is not allowed for policy `\(capability.name)`.")
        }

        let protectedHeaderNames = protectedHeaders(for: capability)
        let userHeaders = try validatedUserHeaders(request.headers, protectedHeaderNames: protectedHeaderNames)
        let secret = try secretStore.readSecret(for: capability.secretKey)
        guard let secretString = String(data: secret, encoding: .utf8) else {
            throw AegisSecretError.runtime("Secret `\(capability.secretKey)` is not valid UTF-8 and cannot be used for HTTP authentication.")
        }

        let reason = "Allow \(requester ?? "the local policy broker") to use policy '\(capability.name)' for \(method) \(requestURL.path)."
        try await authenticator.authenticate(reason: reason)

        var urlRequest = URLRequest(url: requestURL)
        urlRequest.httpMethod = method
        for (key, value) in capability.defaultHeaders {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }
        for (key, value) in userHeaders {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }
        urlRequest.setValue("\(capability.authHeaderPrefix)\(secretString)", forHTTPHeaderField: capability.authHeaderName)

        if let bodyData = request.bodyData {
            urlRequest.httpBody = bodyData
            if request.bodyIsStructuredJSON, urlRequest.value(forHTTPHeaderField: "Content-Type") == nil {
                urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            }
        }

        let (data, response) = try await session.data(for: urlRequest)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AegisSecretError.runtime("Policy request did not return an HTTP response.")
        }

        return brokerResponse(from: httpResponse, data: data, protectedHeaderNames: protectedHeaderNames)
    }

    private func resolvedURL(for capability: ResolvedCapability, request: BrokerRequest) throws -> URL {
        if let rawURL = request.url?.trimmedNonEmpty {
            guard let url = URL(string: rawURL) else {
                throw AegisSecretError.runtime("The supplied URL is invalid.")
            }
            return url
        }

        let path = request.path?.trimmedNonEmpty ?? capability.baseURL.path
        guard let url = URL(string: path, relativeTo: capability.baseURL)?.absoluteURL else {
            throw AegisSecretError.runtime("The supplied path is invalid.")
        }
        return url
    }

    private func validatedUserHeaders(_ headers: [String: String], protectedHeaderNames: Set<String>) throws -> [String: String] {
        var sanitized: [String: String] = [:]
        for (key, value) in headers {
            let normalizedKey = key.lowercased()
            guard !protectedHeaderNames.contains(normalizedKey) else {
                throw AegisSecretError.runtime("Header `\(key)` cannot be overridden.")
            }
            sanitized[key] = value
        }
        return sanitized
    }

    private func brokerResponse(from response: HTTPURLResponse, data: Data, protectedHeaderNames: Set<String>) -> BrokerResponse {
        let sanitizedHeaders = response.allHeaderFields.reduce(into: [String: String]()) { partialResult, item in
            guard let rawKey = item.key as? String else { return }
            let normalizedKey = rawKey.lowercased()
            guard !protectedHeaderNames.contains(normalizedKey), normalizedKey != "set-cookie" else { return }
            partialResult[rawKey] = String(describing: item.value)
        }

        let contentType = response.value(forHTTPHeaderField: "Content-Type")
        let mimeType = contentType?.split(separator: ";").first.map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }

        let truncated = data.count > maxResponseBytes
        let effectiveData = truncated ? Data(data.prefix(maxResponseBytes)) : data

        if isTextual(mimeType: mimeType, data: effectiveData), let text = String(data: effectiveData, encoding: .utf8) {
            return BrokerResponse(
                status: response.statusCode,
                headers: sanitizedHeaders,
                body: text,
                bodyBase64: nil,
                mimeType: mimeType,
                truncated: truncated
            )
        }

        return BrokerResponse(
            status: response.statusCode,
            headers: sanitizedHeaders,
            body: nil,
            bodyBase64: effectiveData.base64EncodedString(),
            mimeType: mimeType,
            truncated: truncated
        )
    }

    private func protectedHeaders(for capability: ResolvedCapability) -> Set<String> {
        var headers: Set<String> = [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-api-key"
        ]
        headers.insert(capability.authHeaderName.lowercased())
        return headers
    }
}

public enum SecretInputMode: Equatable {
    case prompt
    case stdin
}

public enum PolicyCommand: Equatable {
    case list
    case show(name: String)
    case validateCurrent(name: String?)
    case validateFile(path: String)
    case importFile(path: String)
}

public enum Command: Equatable {
    case set(key: String, inputMode: SecretInputMode)
    case get(key: String, agentName: String)
    case delete(key: String)
    case list
    case policy(PolicyCommand)
    case help
}

public struct CommandParser {
    public init() {}

    public func parse(_ arguments: [String], stdinIsTTY: Bool) throws -> Command {
        guard let command = arguments.first else {
            return .help
        }

        switch command {
        case "set":
            return try parseSet(Array(arguments.dropFirst()), stdinIsTTY: stdinIsTTY)
        case "get":
            return try parseGet(Array(arguments.dropFirst()))
        case "delete", "rm":
            return try parseDelete(Array(arguments.dropFirst()))
        case "list", "ls":
            guard arguments.count == 1 else {
                throw AegisSecretError.usage("`list` does not accept additional arguments.")
            }
            return .list
        case "policy", "capability":
            return try parsePolicy(Array(arguments.dropFirst()), commandName: command)
        case "help", "--help", "-h":
            return .help
        default:
            throw AegisSecretError.usage("Unknown command `\(command)`.")
        }
    }

    private func parseSet(_ arguments: [String], stdinIsTTY: Bool) throws -> Command {
        guard let key = arguments.first, !key.hasPrefix("-") else {
            throw AegisSecretError.usage("`set` requires a secret key.")
        }

        var useStdin = !stdinIsTTY
        var index = 1
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--stdin":
                useStdin = true
            default:
                throw AegisSecretError.usage("Unknown argument for `set`: `\(argument)`.")
            }
            index += 1
        }

        return .set(key: key, inputMode: useStdin ? .stdin : .prompt)
    }

    private func parseGet(_ arguments: [String]) throws -> Command {
        guard let key = arguments.first, !key.hasPrefix("-") else {
            throw AegisSecretError.usage("`get` requires a secret key.")
        }

        var agentName: String?
        var index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--agent":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw AegisSecretError.usage("`get` requires a value after `--agent`.")
                }
                agentName = arguments[nextIndex]
                index += 2
            default:
                throw AegisSecretError.usage("Unknown argument for `get`: `\(arguments[index])`.")
            }
        }

        guard let agentName, !agentName.isEmpty else {
            throw AegisSecretError.usage("`get` requires `--agent <name>` so the approval prompt identifies the caller.")
        }

        return .get(key: key, agentName: agentName)
    }

    private func parseDelete(_ arguments: [String]) throws -> Command {
        guard arguments.count == 1, let key = arguments.first, !key.hasPrefix("-") else {
            throw AegisSecretError.usage("`delete` requires exactly one secret key.")
        }
        return .delete(key: key)
    }

    private func parsePolicy(_ arguments: [String], commandName: String) throws -> Command {
        guard let subcommand = arguments.first else {
            throw AegisSecretError.usage("`\(commandName)` requires a subcommand.")
        }

        let remaining = Array(arguments.dropFirst())
        switch subcommand {
        case "list":
            guard remaining.isEmpty else {
                throw AegisSecretError.usage("`\(commandName) list` does not accept additional arguments.")
            }
            return .policy(.list)
        case "show":
            guard remaining.count == 1 else {
                throw AegisSecretError.usage("`\(commandName) show` requires a policy name.")
            }
            return .policy(.show(name: remaining[0]))
        case "validate":
            if remaining.isEmpty {
                return .policy(.validateCurrent(name: nil))
            }
            if remaining.count == 2 && remaining[0] == "--file" {
                return .policy(.validateFile(path: remaining[1]))
            }
            if remaining.count == 1, !remaining[0].hasPrefix("-") {
                return .policy(.validateCurrent(name: remaining[0]))
            }
            throw AegisSecretError.usage("Usage: `aegis-secret policy validate [<name> | --file <path>]`.")
        case "import":
            guard remaining.count == 1 else {
                throw AegisSecretError.usage("`\(commandName) import` requires a JSON file path.")
            }
            return .policy(.importFile(path: remaining[0]))
        default:
            throw AegisSecretError.usage("Unknown policy subcommand `\(subcommand)`.")
        }
    }
}

public struct CLIApplication {
    public let parser: CommandParser
    public let secretStore: SecretStore
    public let authenticator: DeviceAuthenticator
    public let capabilityStore: CapabilityStore

    public init(
        parser: CommandParser = CommandParser(),
        secretStore: SecretStore = KeychainSecretStore(),
        authenticator: DeviceAuthenticator = LocalDeviceAuthenticator(),
        capabilityStore: CapabilityStore = CapabilityStore()
    ) {
        self.parser = parser
        self.secretStore = secretStore
        self.authenticator = authenticator
        self.capabilityStore = capabilityStore
    }

    public func run(arguments: [String], stdinIsTTY: Bool) async -> Never {
        do {
            let command = try parser.parse(arguments, stdinIsTTY: stdinIsTTY)
            if command == .help {
                print(usageText)
                exit(ExitCode.success.rawValue)
            }

            try await run(command)
            exit(ExitCode.success.rawValue)
        } catch let error as AegisSecretError {
            emit(error: error)
        } catch {
            emit(error: .runtime(error.localizedDescription))
        }
    }

    private func run(_ command: Command) async throws {
        switch command {
        case .set(let key, let inputMode):
            let secret = try readSecret(using: inputMode)
            guard !secret.isEmpty else {
                throw AegisSecretError.runtime("Refusing to store an empty secret for `\(key)`.")
            }

            try secretStore.setSecret(secret, for: key)
            print("Stored `\(key)` in Keychain.")
        case .get(let key, let agentName):
            let reason = "Allow \(agentName) to access the secret named '\(key)'."
            try await authenticator.authenticate(reason: reason)
            let secret = try secretStore.readSecret(for: key)
            FileHandle.standardOutput.write(secret)
            if isatty(FileHandle.standardOutput.fileDescriptor) != 0 {
                FileHandle.standardOutput.write(Data([0x0A]))
            }
        case .delete(let key):
            let reason = "Allow aegis-secret to delete the secret named '\(key)'."
            try await authenticator.authenticate(reason: reason)
            if try secretStore.deleteSecret(for: key) {
                print("Deleted `\(key)` from Keychain.")
            } else {
                print("No secret named `\(key)` was found.")
            }
        case .list:
            for item in try secretStore.listSecrets() {
                print(item.key)
            }
        case .policy(let policyCommand):
            try handlePolicyCommand(policyCommand)
        case .help:
            print(usageText)
        }
    }

    private func handlePolicyCommand(_ command: PolicyCommand) throws {
        switch command {
        case .list:
            for summary in try capabilityStore.summaries() {
                print(summary.name)
            }
        case .show(let name):
            let data = try prettyJSON(capabilityStore.rawPolicy(named: name))
            print(String(decoding: data, as: UTF8.self))
        case .validateCurrent(let name):
            if let name {
                try capabilityStore.validateCurrentPolicy(named: name)
                print("Policy `\(name)` is valid.")
            } else {
                let count = try capabilityStore.validateCurrentConfiguration()
                print("Validated \(count) policies from `\(capabilityStore.fileURL.path)`.")
            }
        case .validateFile(let path):
            let count = try capabilityStore.validateFile(at: path)
            print("Validated \(count) policies from `\(expandUserPath(path))`.")
        case .importFile(let path):
            let count = try capabilityStore.importFile(from: path)
            print("Imported \(count) policies into `\(capabilityStore.fileURL.path)`.")
        }
    }

    private func readSecret(using inputMode: SecretInputMode) throws -> Data {
        switch inputMode {
        case .stdin:
            return FileHandle.standardInput.readDataToEndOfFile()
        case .prompt:
            print("Enter secret: ", terminator: "")
            fflush(stdout)

            guard let secret = readPassword() else {
                print("")
                throw AegisSecretError.runtime("Failed to read secret from terminal.")
            }

            print("")
            guard let data = secret.data(using: .utf8) else {
                throw AegisSecretError.runtime("Secret could not be encoded as UTF-8.")
            }
            return data
        }
    }

    private func emit(error: AegisSecretError) -> Never {
        switch error {
        case .usage:
            fputs("Error: \(error.description)\n\n\(usageText)\n", stderr)
            exit(ExitCode.usage.rawValue)
        case .runtime:
            fputs("Error: \(error.description)\n", stderr)
            exit(ExitCode.failure.rawValue)
        }
    }
}

public let usageText = """
Usage:
  aegis-secret set <key> [--stdin]
  aegis-secret get <key> --agent <agent-name>
  aegis-secret delete <key>
  aegis-secret list
  aegis-secret policy list
  aegis-secret policy show <name>
  aegis-secret policy validate [<name> | --file <path>]
  aegis-secret policy import <json-file>

Notes:
  `set` reads from the terminal by default, or from stdin when piped / passed `--stdin`.
  `get` is for explicit human use and reveals the raw secret on stdout after device-owner authentication.
  Policy JSON defaults to `~/.config/aegis-secret/policies.json` unless `AEGIS_SECRET_POLICIES_FILE` is set.
"""

public func readPassword() -> String? {
    let stdinFD = FileHandle.standardInput.fileDescriptor
    var term = termios()
    tcgetattr(stdinFD, &term)

    let originalTerm = term
    term.c_lflag &= ~tcflag_t(ECHO)
    tcsetattr(stdinFD, TCSANOW, &term)

    defer {
        var restored = originalTerm
        tcsetattr(stdinFD, TCSANOW, &restored)
    }

    return readLine()
}

public func message(for status: OSStatus) -> String {
    if let text = SecCopyErrorMessageString(status, nil) as String? {
        return text
    }
    return "OSStatus \(status)"
}

public func prettyJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return try encoder.encode(value)
}

public func expandUserPath(_ path: String) -> String {
    NSString(string: path).expandingTildeInPath
}

private func normalizePathPrefix(_ prefix: String) -> String {
    let trimmed = prefix.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty {
        return "/"
    }
    return trimmed.hasPrefix("/") ? trimmed : "/\(trimmed)"
}

private func matches(path: String, allowedPrefix: String) -> Bool {
    if allowedPrefix == "/" {
        return path.hasPrefix("/")
    }
    if path == allowedPrefix {
        return true
    }
    return path.hasPrefix("\(allowedPrefix)/")
}

private func isTextual(mimeType: String?, data: Data) -> Bool {
    if let mimeType {
        let lowered = mimeType.lowercased()
        if lowered.hasPrefix("text/") || lowered.contains("json") || lowered.contains("xml") || lowered.contains("javascript") || lowered.contains("x-www-form-urlencoded") {
            return true
        }
    }
    return String(data: data, encoding: .utf8) != nil
}

private extension String {
    var trimmedNonEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
