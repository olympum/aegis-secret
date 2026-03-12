import Foundation
import LocalAuthentication
import Security

public let aegisSecretServiceName = "Aegis Secrets"
public let aegisSecretMetadataServiceName = "Aegis Secrets Metadata"
public let commandsFileEnvironmentKey = "AEGIS_SECRET_COMMANDS_FILE"

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
        case errSecSuccess, errSecInteractionNotAllowed:
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
        case errSecItemNotFound, errSecInteractionNotAllowed:
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

public struct WrappedCommandConfig: Codable, Equatable, Sendable {
    public let name: String
    public let command: String
    public let description: String?
    public let approvalWindowSeconds: Int?
    public let timeoutSeconds: Int?
    public let maxOutputBytes: Int?
    public let denyPrefixes: [[String]]?
    public let allowPrefixes: [[String]]?
    public let denyFlags: [String]?
    public let environment: [String: String]?

    public init(
        name: String,
        command: String,
        description: String? = nil,
        approvalWindowSeconds: Int? = nil,
        timeoutSeconds: Int? = nil,
        maxOutputBytes: Int? = nil,
        denyPrefixes: [[String]]? = nil,
        allowPrefixes: [[String]]? = nil,
        denyFlags: [String]? = nil,
        environment: [String: String]? = nil
    ) {
        self.name = name
        self.command = command
        self.description = description
        self.approvalWindowSeconds = approvalWindowSeconds
        self.timeoutSeconds = timeoutSeconds
        self.maxOutputBytes = maxOutputBytes
        self.denyPrefixes = denyPrefixes
        self.allowPrefixes = allowPrefixes
        self.denyFlags = denyFlags
        self.environment = environment
    }

    private enum CodingKeys: String, CodingKey {
        case name
        case command
        case description
        case approvalWindowSeconds = "approval_window_seconds"
        case timeoutSeconds = "timeout_seconds"
        case maxOutputBytes = "max_output_bytes"
        case denyPrefixes = "deny_prefixes"
        case allowPrefixes = "allow_prefixes"
        case denyFlags = "deny_flags"
        case environment
    }

    public func resolved() throws -> ResolvedWrappedCommand {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            throw AegisSecretError.runtime("Wrapped command names cannot be empty.")
        }

        let trimmedCommand = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedCommand.isEmpty else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` is missing `command`.")
        }

        guard !(denyPrefixes?.isEmpty == false && allowPrefixes?.isEmpty == false) else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` cannot define both `deny_prefixes` and `allow_prefixes`.")
        }

        let resolvedApprovalWindow = approvalWindowSeconds ?? 300
        guard resolvedApprovalWindow >= 0 else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` has an invalid `approval_window_seconds`.")
        }

        let resolvedTimeout = timeoutSeconds ?? 30
        guard resolvedTimeout > 0 else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` has an invalid `timeout_seconds`.")
        }

        let resolvedMaxOutputBytes = maxOutputBytes ?? 256 * 1024
        guard resolvedMaxOutputBytes > 0 else {
            throw AegisSecretError.runtime("Wrapped command `\(trimmedName)` has an invalid `max_output_bytes`.")
        }

        let normalizedDenyPrefixes = try normalizePrefixes(denyPrefixes, name: trimmedName, field: "deny_prefixes")
        let normalizedAllowPrefixes = try normalizePrefixes(allowPrefixes, name: trimmedName, field: "allow_prefixes")
        let normalizedFlags = try normalizeFlags(denyFlags, name: trimmedName)
        let normalizedEnvironment = try normalizeEnvironment(environment, name: trimmedName)

        return ResolvedWrappedCommand(
            name: trimmedName,
            command: trimmedCommand,
            description: description?.trimmedNonEmpty,
            approvalWindowSeconds: resolvedApprovalWindow,
            timeoutSeconds: resolvedTimeout,
            maxOutputBytes: resolvedMaxOutputBytes,
            denyPrefixes: normalizedDenyPrefixes,
            allowPrefixes: normalizedAllowPrefixes,
            denyFlags: normalizedFlags,
            environment: normalizedEnvironment
        )
    }

    private func normalizePrefixes(
        _ prefixes: [[String]]?,
        name: String,
        field: String
    ) throws -> [[String]] {
        guard let prefixes else {
            return []
        }

        return try prefixes.map { prefix in
            let normalized = prefix.compactMap { value in
                value.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            }
            guard !normalized.isEmpty else {
                throw AegisSecretError.runtime("Wrapped command `\(name)` contains an empty prefix in `\(field)`.")
            }
            return normalized
        }
    }

    private func normalizeFlags(_ flags: [String]?, name: String) throws -> Set<String> {
        let normalized = Set((flags ?? []).compactMap {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        })
        if normalized.contains(where: { !$0.hasPrefix("-") }) {
            throw AegisSecretError.runtime("Wrapped command `\(name)` has an invalid `deny_flags` entry.")
        }
        return normalized
    }

    private func normalizeEnvironment(_ environment: [String: String]?, name: String) throws -> [String: String] {
        let environment = environment ?? [:]
        for key in environment.keys {
            if key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                throw AegisSecretError.runtime("Wrapped command `\(name)` has an empty environment variable name.")
            }
        }
        return environment
    }
}

public struct CommandFile: Codable, Equatable, Sendable {
    public let version: Int
    public let commands: [WrappedCommandConfig]

    public init(version: Int = 1, commands: [WrappedCommandConfig]) {
        self.version = version
        self.commands = commands
    }

    public static func defaultTemplate() -> CommandFile {
        CommandFile(
            version: 1,
            commands: [
                WrappedCommandConfig(
                    name: "gh",
                    command: "gh",
                    description: "GitHub CLI",
                    denyPrefixes: [["auth"], ["alias"], ["extension"]],
                    denyFlags: ["--hostname"]
                ),
                WrappedCommandConfig(
                    name: "aws",
                    command: "aws",
                    description: "AWS CLI",
                    denyPrefixes: [
                        ["configure"],
                        ["sts", "assume-role"],
                        ["sts", "assume-role-with-saml"],
                        ["sts", "assume-role-with-web-identity"],
                        ["sts", "get-session-token"],
                        ["sts", "get-federation-token"],
                        ["ecr", "get-login-password"],
                        ["rds", "generate-db-auth-token"],
                        ["codeartifact", "get-authorization-token"],
                        ["eks", "get-token"]
                    ],
                    denyFlags: ["--debug"]
                ),
                WrappedCommandConfig(
                    name: "gcloud",
                    command: "gcloud",
                    description: "Google Cloud CLI",
                    denyPrefixes: [["auth"], ["config", "config-helper"]],
                    denyFlags: ["--account", "--access-token-file"]
                ),
            ]
        )
    }
}

public struct WrappedCommandSummary: Codable, Equatable, Sendable {
    public let name: String
    public let description: String?
    public let command: String
    public let approvalWindowSeconds: Int
    public let executableResolves: Bool

    public init(name: String, description: String?, command: String, approvalWindowSeconds: Int, executableResolves: Bool) {
        self.name = name
        self.description = description
        self.command = command
        self.approvalWindowSeconds = approvalWindowSeconds
        self.executableResolves = executableResolves
    }
}

public struct ResolvedWrappedCommand: Equatable, Sendable {
    public let name: String
    public let command: String
    public let description: String?
    public let approvalWindowSeconds: Int
    public let timeoutSeconds: Int
    public let maxOutputBytes: Int
    public let denyPrefixes: [[String]]
    public let allowPrefixes: [[String]]
    public let denyFlags: Set<String>
    public let environment: [String: String]
}

public final class CommandStore: @unchecked Sendable {
    public let fileURL: URL
    public let environment: [String: String]
    public let fileManager: FileManager

    public init(
        fileURL: URL = CommandStore.defaultURL(),
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) {
        self.fileURL = fileURL
        self.environment = environment
        self.fileManager = fileManager
    }

    public static func defaultURL(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let override = environment[commandsFileEnvironmentKey]?.trimmedNonEmpty {
            return URL(fileURLWithPath: expandUserPath(override))
        }

        let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        return homeDirectory
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("aegis-secret", isDirectory: true)
            .appendingPathComponent("commands.json", isDirectory: false)
    }

    public func rawFile(optionalIfMissing: Bool = true) throws -> CommandFile {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            if optionalIfMissing {
                return CommandFile.defaultTemplate()
            }
            throw AegisSecretError.runtime("Commands file not found at `\(fileURL.path)`.")
        }

        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(CommandFile.self, from: data)
    }

    public func resolvedCommands(optionalIfMissing: Bool = true) throws -> [ResolvedWrappedCommand] {
        let file = try rawFile(optionalIfMissing: optionalIfMissing)
        guard file.version == 1 else {
            throw AegisSecretError.runtime("Unsupported commands file version `\(file.version)`.")
        }

        let resolved = try file.commands.map { try $0.resolved() }
        let names = resolved.map(\.name)
        guard Set(names).count == names.count else {
            throw AegisSecretError.runtime("Commands file contains duplicate wrapped command names.")
        }

        return resolved.sorted { $0.name < $1.name }
    }

    public func listCommands() throws -> [WrappedCommandSummary] {
        try resolvedCommands().map { command in
            WrappedCommandSummary(
                name: command.name,
                description: command.description,
                command: command.command,
                approvalWindowSeconds: command.approvalWindowSeconds,
                executableResolves: resolveExecutable(named: command.command) != nil
            )
        }
    }

    public func rawCommand(named name: String) throws -> WrappedCommandConfig {
        let file = try rawFile(optionalIfMissing: false)
        guard let command = file.commands.first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Wrapped command `\(name)` was not found.")
        }
        return command
    }

    public func resolvedCommand(named name: String) throws -> ResolvedWrappedCommand {
        guard let command = try resolvedCommands(optionalIfMissing: false).first(where: { $0.name == name }) else {
            throw AegisSecretError.runtime("Wrapped command `\(name)` was not found.")
        }
        return command
    }

    @discardableResult
    public func importFile(from sourcePath: String) throws -> Int {
        let sourceURL = URL(fileURLWithPath: expandUserPath(sourcePath))
        let data = try Data(contentsOf: sourceURL)
        let file = try JSONDecoder().decode(CommandFile.self, from: data)
        guard file.version == 1 else {
            throw AegisSecretError.runtime("Unsupported commands file version `\(file.version)`.")
        }
        _ = try file.commands.map { try $0.resolved() }

        try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: fileURL, options: .atomic)
        return file.commands.count
    }

    public func validateCurrentConfiguration() throws -> Int {
        try resolvedCommands(optionalIfMissing: false).count
    }

    public func validateCurrentCommand(named name: String) throws {
        _ = try resolvedCommand(named: name)
    }

    public func validateFile(at path: String) throws -> Int {
        let url = URL(fileURLWithPath: expandUserPath(path))
        let data = try Data(contentsOf: url)
        let file = try JSONDecoder().decode(CommandFile.self, from: data)
        guard file.version == 1 else {
            throw AegisSecretError.runtime("Unsupported commands file version `\(file.version)`.")
        }
        _ = try file.commands.map { try $0.resolved() }
        return file.commands.count
    }

    public func writeDefaultFileIfMissing() throws {
        guard !fileManager.fileExists(atPath: fileURL.path) else {
            return
        }

        try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try prettyJSON(CommandFile.defaultTemplate()).write(to: fileURL, options: .atomic)
    }

    public func resolveExecutable(named executableName: String) -> URL? {
        if executableName.contains("/") {
            let url = URL(fileURLWithPath: expandUserPath(executableName))
            return fileManager.isExecutableFile(atPath: url.path) ? url : nil
        }

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
}

public actor ApprovalCache {
    private var expirations: [String: Date] = [:]

    public init() {}

    public func authorize(
        key: String,
        windowSeconds: Int,
        reason: String,
        authenticator: DeviceAuthenticator
    ) async throws {
        let now = Date()
        if let expiration = expirations[key], expiration > now {
            return
        }

        try await authenticator.authenticate(reason: reason)

        if windowSeconds > 0 {
            expirations[key] = now.addingTimeInterval(TimeInterval(windowSeconds))
        } else {
            expirations.removeValue(forKey: key)
        }
    }
}

public struct CommandExecutionRequest: Sendable {
    public let executableURL: URL
    public let arguments: [String]
    public let environment: [String: String]
    public let currentDirectoryURL: URL?
    public let timeoutSeconds: Int
    public let maxOutputBytes: Int

    public init(
        executableURL: URL,
        arguments: [String],
        environment: [String: String],
        currentDirectoryURL: URL?,
        timeoutSeconds: Int,
        maxOutputBytes: Int
    ) {
        self.executableURL = executableURL
        self.arguments = arguments
        self.environment = environment
        self.currentDirectoryURL = currentDirectoryURL
        self.timeoutSeconds = timeoutSeconds
        self.maxOutputBytes = maxOutputBytes
    }
}

public struct RawCommandExecutionResult: Sendable {
    public let stdout: Data
    public let stderr: Data
    public let exitCode: Int32

    public init(stdout: Data, stderr: Data, exitCode: Int32) {
        self.stdout = stdout
        self.stderr = stderr
        self.exitCode = exitCode
    }
}

public protocol CommandExecutor: Sendable {
    func execute(_ request: CommandExecutionRequest) async throws -> RawCommandExecutionResult
}

public final class ProcessCommandExecutor: CommandExecutor, @unchecked Sendable {
    public init() {}

    public func execute(_ request: CommandExecutionRequest) async throws -> RawCommandExecutionResult {
        let process = Process()
        process.executableURL = request.executableURL
        process.arguments = request.arguments
        process.environment = request.environment
        process.currentDirectoryURL = request.currentDirectoryURL
        process.standardInput = FileHandle.nullDevice

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()

        let stdoutTask = Task {
            try await readStream(
                from: stdoutPipe.fileHandleForReading,
                maxBytes: request.maxOutputBytes,
                process: process,
                label: "stdout",
                commandName: request.executableURL.lastPathComponent
            )
        }
        let stderrTask = Task {
            try await readStream(
                from: stderrPipe.fileHandleForReading,
                maxBytes: request.maxOutputBytes,
                process: process,
                label: "stderr",
                commandName: request.executableURL.lastPathComponent
            )
        }
        let terminationTask = Task {
            await waitForTermination(process)
        }
        let timeoutTask = Task {
            try await Task.sleep(for: .seconds(request.timeoutSeconds))
            if process.isRunning {
                process.terminate()
            }
            throw AegisSecretError.runtime("Command `\(request.executableURL.lastPathComponent)` timed out after \(request.timeoutSeconds) seconds.")
        }

        let exitCode = await terminationTask.value
        timeoutTask.cancel()

        let stdout = try await stdoutTask.value
        let stderr = try await stderrTask.value
        _ = try? await timeoutTask.value

        return RawCommandExecutionResult(stdout: stdout, stderr: stderr, exitCode: exitCode)
    }

    private func readStream(
        from handle: FileHandle,
        maxBytes: Int,
        process: Process,
        label: String,
        commandName: String
    ) async throws -> Data {
        var data = Data()
        for try await byte in handle.bytes {
            if data.count >= maxBytes {
                if process.isRunning {
                    process.terminate()
                }
                throw AegisSecretError.runtime("Command `\(commandName)` exceeded the \(maxBytes)-byte \(label) limit.")
            }
            data.append(byte)
        }
        return data
    }

    private func waitForTermination(_ process: Process) async -> Int32 {
        while process.isRunning {
            try? await Task.sleep(for: .milliseconds(25))
        }
        return process.terminationStatus
    }
}

public struct WrappedCommandInvocationResult: Codable, Equatable, Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
    public let stdoutJSON: JSONValue?
    public let stdoutTruncated: Bool
    public let stderrTruncated: Bool

    public init(
        exitCode: Int32,
        stdout: String,
        stderr: String,
        stdoutJSON: JSONValue?,
        stdoutTruncated: Bool,
        stderrTruncated: Bool
    ) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.stdoutJSON = stdoutJSON
        self.stdoutTruncated = stdoutTruncated
        self.stderrTruncated = stderrTruncated
    }

    private enum CodingKeys: String, CodingKey {
        case exitCode = "exit_code"
        case stdout
        case stderr
        case stdoutJSON = "stdout_json"
        case stdoutTruncated = "stdout_truncated"
        case stderrTruncated = "stderr_truncated"
    }
}

public struct WrappedCommandRunner: Sendable {
    public let commandStore: CommandStore
    public let authenticator: DeviceAuthenticator
    public let approvalCache: ApprovalCache
    public let executor: CommandExecutor
    public let environment: [String: String]

    public init(
        commandStore: CommandStore = CommandStore(),
        authenticator: DeviceAuthenticator = LocalDeviceAuthenticator(),
        approvalCache: ApprovalCache = ApprovalCache(),
        executor: CommandExecutor = ProcessCommandExecutor(),
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) {
        self.commandStore = commandStore
        self.authenticator = authenticator
        self.approvalCache = approvalCache
        self.executor = executor
        self.environment = environment
    }

    public func run(
        name: String,
        args: [String],
        cwd: String? = nil,
        requester: String? = nil
    ) async throws -> WrappedCommandInvocationResult {
        let wrappedCommand = try commandStore.resolvedCommand(named: name)
        try validate(args: args, for: wrappedCommand)

        guard let executableURL = commandStore.resolveExecutable(named: wrappedCommand.command) else {
            throw AegisSecretError.runtime("Wrapped command `\(wrappedCommand.name)` points to `\(wrappedCommand.command)`, which is not executable on PATH.")
        }

        let workingDirectoryURL = try resolveWorkingDirectory(cwd)
        let requesterLabel = requester?.trimmedNonEmpty ?? "the local agent"
        let reason = "Allow \(requesterLabel) to run wrapped command '\(wrappedCommand.name)'."
        try await approvalCache.authorize(
            key: wrappedCommand.name,
            windowSeconds: wrappedCommand.approvalWindowSeconds,
            reason: reason,
            authenticator: authenticator
        )

        var executionEnvironment = environment
        for (key, value) in wrappedCommand.environment {
            executionEnvironment[key] = value
        }

        let rawResult = try await executor.execute(
            CommandExecutionRequest(
                executableURL: executableURL,
                arguments: args,
                environment: executionEnvironment,
                currentDirectoryURL: workingDirectoryURL,
                timeoutSeconds: wrappedCommand.timeoutSeconds,
                maxOutputBytes: wrappedCommand.maxOutputBytes
            )
        )

        let stdout = String(decoding: rawResult.stdout, as: UTF8.self)
        let stderr = String(decoding: rawResult.stderr, as: UTF8.self)
        let stdoutJSON = try decodeJSONIfPresent(rawResult.stdout)

        return WrappedCommandInvocationResult(
            exitCode: rawResult.exitCode,
            stdout: stdout,
            stderr: stderr,
            stdoutJSON: stdoutJSON,
            stdoutTruncated: false,
            stderrTruncated: false
        )
    }

    private func validate(args: [String], for command: ResolvedWrappedCommand) throws {
        for argument in args {
            if command.denyFlags.contains(argument) || command.denyFlags.contains(where: { argument.hasPrefix("\($0)=") }) {
                throw AegisSecretError.runtime("Flag `\(argument)` is not allowed for wrapped command `\(command.name)`.")
            }
        }

        if !command.allowPrefixes.isEmpty && !command.allowPrefixes.contains(where: { matchesPrefix(args, prefix: $0) }) {
            throw AegisSecretError.runtime("Arguments are not allowed for wrapped command `\(command.name)`.")
        }

        if let matchedPrefix = command.denyPrefixes.first(where: { matchesPrefix(args, prefix: $0) }) {
            let renderedPrefix = matchedPrefix.joined(separator: " ")
            throw AegisSecretError.runtime("The `\(renderedPrefix)` subcommand is not allowed for wrapped command `\(command.name)`.")
        }
    }

    private func resolveWorkingDirectory(_ cwd: String?) throws -> URL? {
        guard let cwd = cwd?.trimmedNonEmpty else {
            return nil
        }

        let expanded = expandUserPath(cwd)
        guard expanded.hasPrefix("/") else {
            throw AegisSecretError.runtime("Working directory must be an absolute path.")
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: expanded, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw AegisSecretError.runtime("Working directory `\(expanded)` does not exist.")
        }

        return URL(fileURLWithPath: expanded, isDirectory: true)
    }

    private func decodeJSONIfPresent(_ data: Data) throws -> JSONValue? {
        guard let text = String(data: data, encoding: .utf8)?.trimmedNonEmpty else {
            return nil
        }

        let trimmedData = Data(text.utf8)
        do {
            return try JSONDecoder().decode(JSONValue.self, from: trimmedData)
        } catch {
            return nil
        }
    }
}

private func matchesPrefix(_ args: [String], prefix: [String]) -> Bool {
    guard !prefix.isEmpty, args.count >= prefix.count else {
        return false
    }
    return Array(args.prefix(prefix.count)) == prefix
}

public enum SecretInputMode: Equatable {
    case prompt
    case stdin
}

public enum WrappedCommandManagementCommand: Equatable {
    case list
    case show(name: String)
    case validateCurrent(name: String?)
    case validateFile(path: String)
    case importFile(path: String)
}

public enum CLICommand: Equatable {
    case set(key: String, inputMode: SecretInputMode)
    case get(key: String, agentName: String)
    case delete(key: String)
    case list
    case installUser
    case command(WrappedCommandManagementCommand)
    case run(name: String, args: [String])
    case help
}

public struct CommandParser {
    public init() {}

    public func parse(_ arguments: [String], stdinIsTTY: Bool) throws -> CLICommand {
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
        case "command":
            return try parseCommand(Array(arguments.dropFirst()))
        case "run":
            return try parseRun(Array(arguments.dropFirst()))
        case "help", "--help", "-h":
            return .help
        default:
            throw AegisSecretError.usage("Unknown command `\(command)`.")
        }
    }

    private func parseSet(_ arguments: [String], stdinIsTTY: Bool) throws -> CLICommand {
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

    private func parseGet(_ arguments: [String]) throws -> CLICommand {
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

    private func parseDelete(_ arguments: [String]) throws -> CLICommand {
        guard arguments.count == 1, let key = arguments.first, !key.hasPrefix("-") else {
            throw AegisSecretError.usage("`delete` requires exactly one secret key.")
        }
        return .delete(key: key)
    }

    private func parseCommand(_ arguments: [String]) throws -> CLICommand {
        guard let subcommand = arguments.first else {
            throw AegisSecretError.usage("`command` requires a subcommand.")
        }

        let remaining = Array(arguments.dropFirst())
        switch subcommand {
        case "list":
            guard remaining.isEmpty else {
                throw AegisSecretError.usage("`command list` does not accept additional arguments.")
            }
            return .command(.list)
        case "show":
            guard remaining.count == 1 else {
                throw AegisSecretError.usage("`command show` requires a wrapped command name.")
            }
            return .command(.show(name: remaining[0]))
        case "validate":
            if remaining.isEmpty {
                return .command(.validateCurrent(name: nil))
            }
            if remaining.count == 2 && remaining[0] == "--file" {
                return .command(.validateFile(path: remaining[1]))
            }
            if remaining.count == 1, !remaining[0].hasPrefix("-") {
                return .command(.validateCurrent(name: remaining[0]))
            }
            throw AegisSecretError.usage("Usage: `aegis-secret command validate [<name> | --file <path>]`.")
        case "import":
            guard remaining.count == 1 else {
                throw AegisSecretError.usage("`command import` requires a JSON file path.")
            }
            return .command(.importFile(path: remaining[0]))
        default:
            throw AegisSecretError.usage("Unknown command subcommand `\(subcommand)`.")
        }
    }

    private func parseRun(_ arguments: [String]) throws -> CLICommand {
        guard let name = arguments.first, !name.hasPrefix("-") else {
            throw AegisSecretError.usage("`run` requires a wrapped command name.")
        }

        let remaining = Array(arguments.dropFirst())
        guard remaining.isEmpty || remaining.first == "--" else {
            throw AegisSecretError.usage("Usage: `aegis-secret run <name> -- <args...>`.")
        }
        let args = remaining.isEmpty ? [] : Array(remaining.dropFirst())
        return .run(name: name, args: args)
    }
}

public struct CLIApplication {
    public let parser: CommandParser
    public let secretStore: SecretStore
    public let authenticator: DeviceAuthenticator
    public let commandStore: CommandStore
    public let wrappedCommandRunner: WrappedCommandRunner

    public init(
        parser: CommandParser = CommandParser(),
        secretStore: SecretStore = KeychainSecretStore(),
        authenticator: DeviceAuthenticator = LocalDeviceAuthenticator(),
        commandStore: CommandStore = CommandStore(),
        wrappedCommandRunner: WrappedCommandRunner? = nil
    ) {
        self.parser = parser
        self.secretStore = secretStore
        self.authenticator = authenticator
        self.commandStore = commandStore
        self.wrappedCommandRunner = wrappedCommandRunner ?? WrappedCommandRunner(
            commandStore: commandStore,
            authenticator: authenticator
        )
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

    private func run(_ command: CLICommand) async throws {
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
            let installation = try UserInstaller(
                currentExecutablePath: CommandLine.arguments[0],
                commandStore: commandStore
            ).install()
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
        case .command(let wrappedCommandCommand):
            try handleWrappedCommandManagement(wrappedCommandCommand)
        case .run(let name, let args):
            let result = try await wrappedCommandRunner.run(
                name: name,
                args: args,
                requester: "aegis-secret"
            )
            if !result.stdout.isEmpty {
                FileHandle.standardOutput.write(Data(result.stdout.utf8))
            }
            if !result.stderr.isEmpty {
                FileHandle.standardError.write(Data(result.stderr.utf8))
            }
            if result.exitCode != 0 {
                throw AegisSecretError.runtime("Wrapped command `\(name)` exited with status \(result.exitCode).")
            }
        case .help:
            print(usageText)
        }
    }

    private func handleWrappedCommandManagement(_ command: WrappedCommandManagementCommand) throws {
        switch command {
        case .list:
            for summary in try commandStore.listCommands() {
                print(summary.name)
            }
        case .show(let name):
            let data = try prettyJSON(commandStore.rawCommand(named: name))
            print(String(decoding: data, as: UTF8.self))
        case .validateCurrent(let name):
            if let name {
                try commandStore.validateCurrentCommand(named: name)
                print("Wrapped command `\(name)` is valid.")
            } else {
                let count = try commandStore.validateCurrentConfiguration()
                print("Validated \(count) wrapped commands from `\(commandStore.fileURL.path)`.")
            }
        case .validateFile(let path):
            let count = try commandStore.validateFile(at: path)
            print("Validated \(count) wrapped commands from `\(expandUserPath(path))`.")
        case .importFile(let path):
            let count = try commandStore.importFile(from: path)
            print("Imported \(count) wrapped commands into `\(commandStore.fileURL.path)`.")
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
  aegis-secret command list
  aegis-secret command show <name>
  aegis-secret command validate [<name> | --file <path>]
  aegis-secret command import <json-file>
  aegis-secret run <name> -- <args...>

Notes:
  `set` reads from the terminal by default, or from stdin when piped / passed `--stdin`.
  `get` is for explicit human use and reveals the raw secret on stdout after device-owner authentication.
  `install-user` creates PATH shims in `~/.local/bin` and registers user-scoped MCP integrations for installed Codex / Claude CLIs.
  Wrapped commands default to `~/.config/aegis-secret/commands.json` unless `AEGIS_SECRET_COMMANDS_FILE` is set.
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
    public let commandStore: CommandStore

    public init(
        currentExecutablePath: String,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default,
        commandStore: CommandStore = CommandStore()
    ) {
        self.currentExecutablePath = currentExecutablePath
        self.environment = environment
        self.fileManager = fileManager
        self.commandStore = commandStore
    }

    public func install() throws -> UserInstallationSummary {
        let appBundleURL = try resolveAppBundleURL()
        guard !appBundleURL.path.hasPrefix("/Volumes/") else {
            throw AegisSecretError.runtime("Run `install-user` after copying Aegis Secret.app to /Applications or ~/Applications.")
        }

        try commandStore.writeDefaultFileIfMissing()

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
        commandStore.resolveExecutable(named: executableName)
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

private extension String {
    var trimmedNonEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}
