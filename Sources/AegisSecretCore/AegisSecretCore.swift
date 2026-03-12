import Foundation
import LocalAuthentication
import Security

public let aegisSecretServiceName = "Aegis Secrets"
public let aegisSecretMetadataServiceName = "Aegis Secrets Metadata"
public let policiesFileEnvironmentKey = "AEGIS_SECRET_POLICIES_FILE"

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
        context.localizedFallbackTitle = ""
        var evaluationError: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &evaluationError) else {
            let details = evaluationError?.localizedDescription ?? "Unknown authentication error"
            throw AegisSecretError.runtime("Biometric authentication is unavailable: \(details).")
        }

        try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
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
    func readSecret(for key: String, reason: String) throws -> Data
    func deleteSecret(for key: String) throws -> Bool
    func listSecrets() throws -> [SecretListItem]
    func secretExists(for key: String) throws -> Bool
}

public extension SecretStore {
    func readSecret(for key: String, reason: String) throws -> Data {
        try readSecret(for: key)
    }
}

public struct KeychainSecretStore: SecretStore {
    public let serviceName: String
    public let metadataServiceName: String

    public init(
        serviceName: String = aegisSecretServiceName,
        metadataServiceName: String = aegisSecretMetadataServiceName
    ) {
        self.serviceName = serviceName
        self.metadataServiceName = metadataServiceName
    }

    public func setSecret(_ secretData: Data, for key: String) throws {
        let deleteQuery = baseQuery(for: key)
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw AegisSecretError.runtime("Unable to replace existing secret `\(key)`: \(message(for: deleteStatus)).")
        }

        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &accessControlError
        ) else {
            let details = accessControlError?.takeRetainedValue().localizedDescription ?? "Unknown access control error"
            throw AegisSecretError.runtime("Unable to create access control for secret `\(key)`: \(details).")
        }

        var addQuery = baseQuery(for: key)
        addQuery[kSecValueData as String] = secretData
        addQuery[kSecAttrLabel as String] = "Aegis secret: \(key)"
        addQuery[kSecAttrAccessControl as String] = accessControl

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw AegisSecretError.runtime(storageErrorMessage(for: key, status: addStatus))
        }

        try upsertMetadata(for: key)
    }

    public func readSecret(for key: String) throws -> Data {
        try readSecret(for: key, reason: "Access the secret named '\(key)'.")
    }

    public func readSecret(for key: String, reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = ""

        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw AegisSecretError.runtime(readErrorMessage(for: key, status: status))
        }

        guard let data = item as? Data else {
            throw AegisSecretError.runtime("Keychain returned invalid data for `\(key)`.")
        }

        return data
    }

    public func deleteSecret(for key: String) throws -> Bool {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        let metadataStatus = SecItemDelete(metadataQuery(for: key) as CFDictionary)
        guard metadataStatus == errSecSuccess || metadataStatus == errSecItemNotFound else {
            throw AegisSecretError.runtime("Unable to update secret index for `\(key)`: \(message(for: metadataStatus)).")
        }

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
        try listMetadataKeys()
    }

    public func secretExists(for key: String) throws -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true

        var query = baseQuery(for: key)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return true
        case errSecInteractionNotAllowed:
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
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func metadataQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataServiceName,
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func upsertMetadata(for key: String) throws {
        let deleteStatus = SecItemDelete(metadataQuery(for: key) as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw AegisSecretError.runtime("Unable to update secret index for `\(key)`: \(message(for: deleteStatus)).")
        }

        var addQuery = metadataQuery(for: key)
        addQuery[kSecValueData as String] = Data()
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        addQuery[kSecAttrLabel as String] = "Aegis secret metadata: \(key)"

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AegisSecretError.runtime("Unable to update secret index for `\(key)`: \(message(for: status)).")
        }
    }

    private func listMetadataKeys() throws -> [SecretListItem] {
        let context = LAContext()
        context.interactionNotAllowed = true

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataServiceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationContext as String: context,
            kSecUseDataProtectionKeychain as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let dictionaries = item as? [[String: Any]] else {
                throw AegisSecretError.runtime("Keychain returned an unexpected response while listing secrets.")
            }
            return dictionaries.compactMap { dictionary in
                (dictionary[kSecAttrAccount as String] as? String).map(SecretListItem.init(key:))
            }
        case errSecItemNotFound:
            return []
        case errSecInteractionNotAllowed:
            return []
        default:
            throw AegisSecretError.runtime("Unable to list secrets: \(message(for: status)).")
        }
    }

    private func storageErrorMessage(for key: String, status: OSStatus) -> String {
        if status == errSecMissingEntitlement {
            return """
            Unable to store secret `\(key)`: the signed Aegis app/helper is missing the entitlement required for the Data Protection keychain. Build and sign the app bundle with a valid Apple code-signing identity before using biometric-only secrets.
            """
        }
        return "Unable to store secret `\(key)`: \(message(for: status))."
    }

    private func readErrorMessage(for key: String, status: OSStatus) -> String {
        if status == errSecMissingEntitlement {
            return """
            Unable to retrieve secret `\(key)`: the signed Aegis app/helper is missing the entitlement required for the Data Protection keychain. Build and sign the app bundle with a valid Apple code-signing identity before using biometric-only secrets.
            """
        }
        return "Unable to retrieve secret `\(key)`: \(message(for: status))."
    }
}

public enum AuthMode: String, Codable, Sendable {
    case bearer
    case header
}

public struct PolicyConfig: Codable, Equatable, Sendable {
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

    public func resolved() throws -> ResolvedPolicy {
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

        return ResolvedPolicy(
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

public struct PolicyFile: Codable, Equatable, Sendable {
    public let policies: [PolicyConfig]

    public init(policies: [PolicyConfig]) {
        self.policies = policies
    }
}

public struct PolicySummary: Codable, Equatable, Sendable {
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

public struct ResolvedPolicy: Equatable, Sendable {
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

public struct PolicyProbeResult: Codable, Equatable, Sendable {
    public let ok: Bool
    public let description: String

    public init(ok: Bool, description: String) {
        self.ok = ok
        self.description = description
    }
}

public final class PolicyStore: @unchecked Sendable {
    public let fileURL: URL

    public init(fileURL: URL = PolicyStore.defaultURL()) {
        self.fileURL = fileURL
    }

    public static func defaultURL(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let override = environment[policiesFileEnvironmentKey]?.trimmedNonEmpty {
            return URL(fileURLWithPath: expandUserPath(override))
        }

        let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        return homeDirectory
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("aegis-secret", isDirectory: true)
            .appendingPathComponent("policies.json", isDirectory: false)
    }

    public func rawFile(optionalIfMissing: Bool = true) throws -> PolicyFile {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            if optionalIfMissing {
                return PolicyFile(policies: [])
            }
            throw AegisSecretError.runtime("Policies file not found at `\(fileURL.path)`.")
        }

        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(PolicyFile.self, from: data)
    }

    public func resolvedPolicies(optionalIfMissing: Bool = true) throws -> [ResolvedPolicy] {
        let file = try rawFile(optionalIfMissing: optionalIfMissing)
        let resolved = try file.policies.map { try $0.resolved() }

        let names = resolved.map(\.name)
        if Set(names).count != names.count {
            throw AegisSecretError.runtime("Policies file contains duplicate policy names.")
        }

        return resolved.sorted { $0.name < $1.name }
    }

    public func listPolicies() throws -> [PolicySummary] {
        try resolvedPolicies().map {
            PolicySummary(
                name: $0.name,
                description: $0.description,
                baseURL: $0.baseURL.absoluteString,
                allowedMethods: $0.allowedMethods.sorted(),
                allowedPathPrefixes: $0.allowedPathPrefixes
            )
        }
    }

    public func rawPolicy(named name: String) throws -> PolicyConfig {
        let file = try rawFile(optionalIfMissing: false)
        guard let policy = file.policies.first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Policy `\(name)` was not found.")
        }
        return policy
    }

    public func resolvedPolicy(named name: String) throws -> ResolvedPolicy {
        guard let policy = try resolvedPolicies(optionalIfMissing: false).first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Policy `\(name)` was not found.")
        }
        return policy
    }

    @discardableResult
    public func importFile(from sourcePath: String) throws -> Int {
        let sourceURL = URL(fileURLWithPath: expandUserPath(sourcePath))
        let data = try Data(contentsOf: sourceURL)
        let file = try JSONDecoder().decode(PolicyFile.self, from: data)
        _ = try file.policies.map { try $0.resolved() }

        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: fileURL, options: .atomic)
        return file.policies.count
    }

    public func validateCurrentConfiguration() throws -> Int {
        try resolvedPolicies(optionalIfMissing: false).count
    }

    public func validateCurrentPolicy(named name: String) throws {
        _ = try resolvedPolicy(named: name)
    }

    public func validateFile(at path: String) throws -> Int {
        let url = URL(fileURLWithPath: expandUserPath(path))
        let data = try Data(contentsOf: url)
        let file = try JSONDecoder().decode(PolicyFile.self, from: data)
        _ = try file.policies.map { try $0.resolved() }
        return file.policies.count
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

public struct HTTPPolicyBroker: Sendable {
    public let policyStore: PolicyStore
    public let secretStore: SecretStore
    public let session: HTTPSession
    public let maxResponseBytes: Int

    public init(
        policyStore: PolicyStore,
        secretStore: SecretStore,
        session: HTTPSession = URLSession.shared,
        maxResponseBytes: Int = 256 * 1024
    ) {
        self.policyStore = policyStore
        self.secretStore = secretStore
        self.session = session
        self.maxResponseBytes = maxResponseBytes
    }

    public func probe(policy name: String) throws -> PolicyProbeResult {
        let policy = try policyStore.resolvedPolicy(named: name)
        if try secretStore.secretExists(for: policy.secretKey) {
            return PolicyProbeResult(ok: true, description: policy.description ?? "Policy is ready.")
        }
        return PolicyProbeResult(ok: false, description: "The Keychain secret `\(policy.secretKey)` is missing.")
    }

    public func request(policy name: String, request: BrokerRequest, requester: String? = nil) async throws -> BrokerResponse {
        let policy = try policyStore.resolvedPolicy(named: name)

        let method = request.method.uppercased()
        guard policy.allowedMethods.contains(method) else {
            throw AegisSecretError.runtime("Method `\(method)` is not allowed for policy `\(policy.name)`.")
        }

        let requestURL = try resolvedURL(for: policy, request: request)
        guard let host = requestURL.host?.lowercased(), policy.allowedHosts.contains(host) else {
            throw AegisSecretError.runtime("Host `\(requestURL.host ?? requestURL.absoluteString)` is not allowed for policy `\(policy.name)`.")
        }

        guard policy.allowedPathPrefixes.contains(where: { matches(path: requestURL.path, allowedPrefix: $0) }) else {
            throw AegisSecretError.runtime("Path `\(requestURL.path)` is not allowed for policy `\(policy.name)`.")
        }

        let protectedHeaderNames = protectedHeaders(for: policy)
        let userHeaders = try validatedUserHeaders(request.headers, protectedHeaderNames: protectedHeaderNames)
        let reason = "Allow \(requester ?? "the local policy broker") to use policy '\(policy.name)' for \(method) \(requestURL.path)."
        let secret = try secretStore.readSecret(for: policy.secretKey, reason: reason)
        guard let secretString = String(data: secret, encoding: .utf8) else {
            throw AegisSecretError.runtime("Secret `\(policy.secretKey)` is not valid UTF-8 and cannot be used for HTTP authentication.")
        }

        var urlRequest = URLRequest(url: requestURL)
        urlRequest.httpMethod = method
        for (key, value) in policy.defaultHeaders {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }
        for (key, value) in userHeaders {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }
        urlRequest.setValue("\(policy.authHeaderPrefix)\(secretString)", forHTTPHeaderField: policy.authHeaderName)

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

    private func resolvedURL(for policy: ResolvedPolicy, request: BrokerRequest) throws -> URL {
        if let rawURL = request.url?.trimmedNonEmpty {
            guard let url = URL(string: rawURL) else {
                throw AegisSecretError.runtime("The supplied URL is invalid.")
            }
            return url
        }

        let path = request.path?.trimmedNonEmpty ?? policy.baseURL.path
        guard let url = URL(string: path, relativeTo: policy.baseURL)?.absoluteURL else {
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

    private func protectedHeaders(for policy: ResolvedPolicy) -> Set<String> {
        var headers: Set<String> = [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-api-key"
        ]
        headers.insert(policy.authHeaderName.lowercased())
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
    case installUser
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
        case "delete":
            return try parseDelete(Array(arguments.dropFirst()))
        case "list":
            guard arguments.count == 1 else {
                throw AegisSecretError.usage("`list` does not accept additional arguments.")
            }
            return .list
        case "install-user":
            guard arguments.count == 1 else {
                throw AegisSecretError.usage("`install-user` does not accept additional arguments.")
            }
            return .installUser
        case "policy":
            return try parsePolicy(Array(arguments.dropFirst()))
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

    private func parsePolicy(_ arguments: [String]) throws -> Command {
        guard let subcommand = arguments.first else {
            throw AegisSecretError.usage("`policy` requires a subcommand.")
        }

        let remaining = Array(arguments.dropFirst())
        switch subcommand {
        case "list":
            guard remaining.isEmpty else {
                throw AegisSecretError.usage("`policy list` does not accept additional arguments.")
            }
            return .policy(.list)
        case "show":
            guard remaining.count == 1 else {
                throw AegisSecretError.usage("`policy show` requires a policy name.")
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
                throw AegisSecretError.usage("`policy import` requires a JSON file path.")
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
    public let policyStore: PolicyStore

    public init(
        parser: CommandParser = CommandParser(),
        secretStore: SecretStore = KeychainSecretStore(),
        authenticator: DeviceAuthenticator = LocalDeviceAuthenticator(),
        policyStore: PolicyStore = PolicyStore()
    ) {
        self.parser = parser
        self.secretStore = secretStore
        self.authenticator = authenticator
        self.policyStore = policyStore
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
            let secret = try secretStore.readSecret(for: key, reason: reason)
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
        case .installUser:
            let installation = try UserInstaller(currentExecutablePath: CommandLine.arguments[0]).install()
            print("Installed user shims for `\(installation.appBundleURL.path)`.")
            if installation.registeredCodex {
                print("Registered the Codex MCP server.")
            }
            if installation.registeredClaude {
                print("Registered the Claude MCP server.")
            }
            if !installation.registeredCodex && !installation.registeredClaude {
                print("No supported MCP client CLI was found, so only PATH shims were created.")
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
            for summary in try policyStore.listPolicies() {
                print(summary.name)
            }
        case .show(let name):
            let data = try prettyJSON(policyStore.rawPolicy(named: name))
            print(String(decoding: data, as: UTF8.self))
        case .validateCurrent(let name):
            if let name {
                try policyStore.validateCurrentPolicy(named: name)
                print("Policy `\(name)` is valid.")
            } else {
                let count = try policyStore.validateCurrentConfiguration()
                print("Validated \(count) policies from `\(policyStore.fileURL.path)`.")
            }
        case .validateFile(let path):
            let count = try policyStore.validateFile(at: path)
            print("Validated \(count) policies from `\(expandUserPath(path))`.")
        case .importFile(let path):
            let count = try policyStore.importFile(from: path)
            print("Imported \(count) policies into `\(policyStore.fileURL.path)`.")
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
  aegis-secret install-user
  aegis-secret policy list
  aegis-secret policy show <name>
  aegis-secret policy validate [<name> | --file <path>]
  aegis-secret policy import <json-file>

Notes:
  `set` reads from the terminal by default, or from stdin when piped / passed `--stdin`.
  `get` is for explicit human use and reveals the raw secret on stdout after device-owner authentication.
  `install-user` creates PATH shims in `~/.local/bin` and registers user-scoped MCP integrations for installed Codex / Claude CLIs.
  Policy JSON defaults to `~/.config/aegis-secret/policies.json` unless `AEGIS_SECRET_POLICIES_FILE` is set.
"""

public struct UserInstallationSummary {
    public let appBundleURL: URL
    public let registeredCodex: Bool
    public let registeredClaude: Bool
}

public struct UserInstaller {
    public let currentExecutablePath: String
    public let environment: [String: String]
    public let fileManager: FileManager

    public init(
        currentExecutablePath: String,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) {
        self.currentExecutablePath = currentExecutablePath
        self.environment = environment
        self.fileManager = fileManager
    }

    public func install() throws -> UserInstallationSummary {
        let appBundleURL = try resolveAppBundleURL()
        guard !appBundleURL.path.hasPrefix("/Volumes/") else {
            throw AegisSecretError.runtime("Run `install-user` after copying Aegis Secret.app to /Applications or ~/Applications.")
        }

        let executableURL = appBundleURL.appendingPathComponent("Contents/MacOS/aegis-secret")
        let binDirectory = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/bin", isDirectory: true)
        try fileManager.createDirectory(at: binDirectory, withIntermediateDirectories: true)

        try writeShim(
            named: "aegis-secret",
            targetExecutable: executableURL,
            arguments: [],
            in: binDirectory
        )
        try writeShim(
            named: "aegis-secret-mcp",
            targetExecutable: executableURL,
            arguments: ["--mcp-server"],
            in: binDirectory
        )

        let serverName = "aegis-secret"
        let registeredCodex = try registerCodex(serverName: serverName, executableURL: executableURL)
        let registeredClaude = try registerClaude(serverName: serverName, executableURL: executableURL)

        return UserInstallationSummary(
            appBundleURL: appBundleURL,
            registeredCodex: registeredCodex,
            registeredClaude: registeredClaude
        )
    }

    private func resolveAppBundleURL() throws -> URL {
        let bundleURL = Bundle.main.bundleURL.standardizedFileURL
        if bundleURL.pathExtension == "app" {
            return bundleURL
        }

        let executableURL = URL(fileURLWithPath: currentExecutablePath).resolvingSymlinksInPath()
        let candidate = executableURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        if candidate.pathExtension == "app" {
            return candidate.standardizedFileURL
        }

        throw AegisSecretError.runtime("`install-user` must be run from the signed Aegis Secret app bundle.")
    }

    private func writeShim(
        named shimName: String,
        targetExecutable: URL,
        arguments: [String],
        in directory: URL
    ) throws {
        let shimURL = directory.appendingPathComponent(shimName)
        let renderedArguments = arguments.map { shellQuote($0) }.joined(separator: " ")
        let argumentSuffix = renderedArguments.isEmpty ? "" : " \(renderedArguments)"
        let contents = """
        #!/bin/zsh
        exec \(shellQuote(targetExecutable.path))\(argumentSuffix) "$@"
        """

        try contents.write(to: shimURL, atomically: true, encoding: .utf8)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: shimURL.path)
    }

    private func registerCodex(serverName: String, executableURL: URL) throws -> Bool {
        guard let codexExecutable = findExecutable(named: "codex") else {
            return false
        }

        _ = try runProcess(
            executableURL: codexExecutable,
            arguments: ["mcp", "remove", serverName],
            allowFailure: true
        )
        _ = try runProcess(
            executableURL: codexExecutable,
            arguments: [
                "mcp", "add", serverName,
                "--env", "AEGIS_SECRET_AGENT_NAME=Codex",
                "--",
                executableURL.path,
                "--mcp-server"
            ]
        )
        return true
    }

    private func registerClaude(serverName: String, executableURL: URL) throws -> Bool {
        guard let claudeExecutable = findExecutable(named: "claude") else {
            return false
        }

        _ = try runProcess(
            executableURL: claudeExecutable,
            arguments: ["mcp", "remove", serverName],
            allowFailure: true
        )

        let payloadData = try JSONSerialization.data(
            withJSONObject: [
                "type": "stdio",
                "command": executableURL.path,
                "args": ["--mcp-server"],
                "env": ["AEGIS_SECRET_AGENT_NAME": "Claude"]
            ],
            options: []
        )
        guard let payload = String(data: payloadData, encoding: .utf8) else {
            throw AegisSecretError.runtime("Failed to encode the Claude MCP registration payload.")
        }

        _ = try runProcess(
            executableURL: claudeExecutable,
            arguments: ["mcp", "add-json", serverName, payload]
        )
        return true
    }

    private func findExecutable(named executableName: String) -> URL? {
        guard let path = environment["PATH"] else {
            return nil
        }

        for component in path.split(separator: ":") {
            let candidate = URL(fileURLWithPath: String(component), isDirectory: true)
                .appendingPathComponent(executableName)
            if fileManager.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
    }

    @discardableResult
    private func runProcess(
        executableURL: URL,
        arguments: [String],
        allowFailure: Bool = false
    ) throws -> String {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        process.environment = environment

        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe

        try process.run()
        process.waitUntilExit()

        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(decoding: outputData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)

        if process.terminationStatus != 0 && !allowFailure {
            let renderedCommand = ([executableURL.path] + arguments).joined(separator: " ")
            let detail = output.isEmpty ? "exit status \(process.terminationStatus)" : output
            throw AegisSecretError.runtime("Command failed: \(renderedCommand)\n\(detail)")
        }

        return output
    }
}

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

public func shellQuote(_ value: String) -> String {
    "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
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
