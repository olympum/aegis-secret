import Foundation

private struct ToolErrorPayload: Codable {
    let error: String
}

public enum JSONValue: Codable, Equatable, Sendable {
    case string(String)
    case number(Double)
    case integer(Int)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value.")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .integer(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }
}

private struct RPCRequest: Decodable {
    let jsonrpc: String?
    let id: JSONValue?
    let method: String
    let params: JSONValue?
}

private struct RPCResponse<Payload: Encodable>: Encodable {
    let jsonrpc = "2.0"
    let id: JSONValue?
    let result: Payload?
    let error: RPCError?
}

private struct RPCError: Encodable {
    let code: Int
    let message: String
}

private struct ServerInfo: Codable {
    let name: String
    let version: String
}

private struct InitializeResult: Codable {
    let protocolVersion: String
    let capabilities: [String: JSONValue]
    let serverInfo: ServerInfo
}

private struct ToolDescriptor: Codable {
    let name: String
    let title: String
    let description: String
    let inputSchema: [String: JSONValue]
    let outputSchema: [String: JSONValue]
}

private struct ToolsListResult: Codable {
    let tools: [ToolDescriptor]
}

private struct ToolContent: Codable {
    let type: String
    let text: String
}

private struct ToolCallResult<Payload: Encodable>: Encodable {
    let content: [ToolContent]
    let structuredContent: Payload
    let isError: Bool
}

public final class StdioMCPServer {
    private let policyStore: PolicyStore
    private let secretStore: SecretStore
    private let agentName: String?

    public init(
        policyStore: PolicyStore = PolicyStore(),
        secretStore: SecretStore = KeychainSecretStore(),
        agentName: String? = ProcessInfo.processInfo.environment["AEGIS_SECRET_AGENT_NAME"]
    ) {
        self.policyStore = policyStore
        self.secretStore = secretStore
        self.agentName = agentName
    }

    public func run() async {
        while let line = readLine() {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                continue
            }

            do {
                let request = try JSONDecoder().decode(RPCRequest.self, from: Data(trimmed.utf8))
                try await handle(request)
            } catch {
                try? emit(RPCResponse<JSONValue>(
                    id: nil,
                    result: nil,
                    error: RPCError(code: -32700, message: "Invalid JSON-RPC request: \(error.localizedDescription)")
                ))
            }
        }
    }

    private func handle(_ request: RPCRequest) async throws {
        switch request.method {
        case "initialize":
            let result = InitializeResult(
                protocolVersion: "2024-11-05",
                capabilities: [
                    "tools": .object([
                        "listChanged": .bool(false),
                    ]),
                ],
                serverInfo: ServerInfo(name: "aegis-secret", version: "0.1.0")
            )
            try emit(RPCResponse(id: request.id, result: result, error: nil))
        case "notifications/initialized":
            return
        case "tools/list":
            try emit(RPCResponse(id: request.id, result: ToolsListResult(tools: toolDescriptors()), error: nil))
        case "tools/call":
            guard let params = request.params?.objectValue else {
                try emitError(id: request.id, message: "Missing tool call params.")
                return
            }
            try await handleToolCall(id: request.id, params: params)
        default:
            if request.id != nil {
                try emitError(id: request.id, message: "Unknown method `\(request.method)`.")
            }
        }
    }

    private func handleToolCall(id: JSONValue?, params: [String: JSONValue]) async throws {
        guard let name = params["name"]?.stringValue else {
            try emitError(id: id, message: "Missing tool name.")
            return
        }

        let arguments = params["arguments"]?.objectValue ?? [:]

        do {
            switch name {
            case "list_policies":
                try emitToolResult(id: id, payload: ["policies": try policyStore.listPolicies()])
            case "probe_policy":
                guard let policy = arguments["policy"]?.stringValue else {
                    try emitToolError(id: id, message: "Missing `policy`.")
                    return
                }
                let broker = HTTPPolicyBroker(policyStore: policyStore, secretStore: secretStore)
                try emitToolResult(id: id, payload: broker.probe(policy: policy))
            case "http_request":
                guard let policy = arguments["policy"]?.stringValue else {
                    try emitToolError(id: id, message: "Missing `policy`.")
                    return
                }
                guard let method = arguments["method"]?.stringValue else {
                    try emitToolError(id: id, message: "Missing `method`.")
                    return
                }
                let broker = HTTPPolicyBroker(policyStore: policyStore, secretStore: secretStore)
                let response = try await broker.request(
                    policy: policy,
                    request: BrokerRequest(
                        method: method,
                        path: arguments["path"]?.stringValue,
                        url: arguments["url"]?.stringValue,
                        headers: try decodeHeaders(arguments["headers"]),
                        bodyData: try decodeBody(arguments["body"]).data,
                        bodyIsStructuredJSON: try decodeBody(arguments["body"]).structuredJSON
                    ),
                    requester: arguments["requester"]?.stringValue ?? agentName ?? "MCP client"
                )
                try emitToolResult(id: id, payload: response)
            default:
                try emitToolError(id: id, message: "Unknown tool `\(name)`.")
            }
        } catch let error as AegisSecretError {
            try emitToolError(id: id, message: error.description)
        } catch {
            try emitToolError(id: id, message: error.localizedDescription)
        }
    }

    private func toolDescriptors() -> [ToolDescriptor] {
        [
            ToolDescriptor(
                name: "list_policies",
                title: "List policies",
                description: "List the safe brokered policies available to the local agent. This never returns raw secret names or values.",
                inputSchema: [
                    "type": .string("object"),
                    "properties": .object([:]),
                ],
                outputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "policies": .object([
                            "type": .string("array"),
                        ]),
                    ]),
                ]
            ),
            ToolDescriptor(
                name: "probe_policy",
                title: "Probe policy",
                description: "Check whether a configured policy exists locally and whether its backing Keychain secret is available.",
                inputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "policy": .object([
                            "type": .string("string"),
                            "description": .string("Policy name to probe."),
                        ]),
                    ]),
                    "required": .array([.string("policy")]),
                ],
                outputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "ok": .object(["type": .string("boolean")]),
                        "description": .object(["type": .string("string")]),
                    ]),
                ]
            ),
            ToolDescriptor(
                name: "http_request",
                title: "HTTP request",
                description: "Send an authenticated HTTP request through a named local policy. The secret never leaves the local broker.",
                inputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "policy": .object([
                            "type": .string("string"),
                            "description": .string("Policy name to use."),
                        ]),
                        "method": .object([
                            "type": .string("string"),
                            "description": .string("HTTP method, such as GET or POST."),
                        ]),
                        "path": .object([
                            "type": .string("string"),
                            "description": .string("Optional relative path under the policy base URL."),
                        ]),
                        "url": .object([
                            "type": .string("string"),
                            "description": .string("Optional absolute URL. It must still match the policy."),
                        ]),
                        "headers": .object([
                            "type": .string("object"),
                            "description": .string("Optional non-sensitive request headers."),
                        ]),
                        "body": .object([
                            "description": .string("Optional request body. Strings are sent as-is; objects and arrays are JSON-encoded."),
                        ]),
                        "requester": .object([
                            "type": .string("string"),
                            "description": .string("Optional caller label shown in the approval prompt."),
                        ]),
                    ]),
                    "required": .array([
                        .string("policy"),
                        .string("method"),
                    ]),
                ],
                outputSchema: [
                    "type": .string("object"),
                    "properties": .object([
                        "status": .object(["type": .string("integer")]),
                        "headers": .object(["type": .string("object")]),
                        "body": .object(["type": .string("string")]),
                        "body_base64": .object(["type": .string("string")]),
                        "mime_type": .object(["type": .string("string")]),
                        "truncated": .object(["type": .string("boolean")]),
                    ]),
                ]
            ),
        ]
    }

    private func decodeHeaders(_ value: JSONValue?) throws -> [String: String] {
        guard let object = value?.objectValue else {
            return [:]
        }

        var headers: [String: String] = [:]
        for (key, value) in object {
            guard let stringValue = value.stringValue else {
                throw AegisSecretError.runtime("Header `\(key)` must be a string.")
            }
            headers[key] = stringValue
        }
        return headers
    }

    private func decodeBody(_ value: JSONValue?) throws -> (data: Data?, structuredJSON: Bool) {
        guard let value else {
            return (nil, false)
        }

        if let stringValue = value.stringValue {
            return (stringValue.data(using: .utf8), false)
        }

        let data = try JSONEncoder().encode(value)
        return (data, true)
    }

    private func emitToolResult<Payload: Codable>(id: JSONValue?, payload: Payload) throws {
        let data = try prettyJSON(payload)
        let response = ToolCallResult(
            content: [ToolContent(type: "text", text: String(decoding: data, as: UTF8.self))],
            structuredContent: payload,
            isError: false
        )
        try emit(RPCResponse(id: id, result: response, error: nil))
    }

    private func emitToolError(id: JSONValue?, message: String) throws {
        let payload = ToolErrorPayload(error: message)
        let data = try prettyJSON(payload)
        let response = ToolCallResult(
            content: [ToolContent(type: "text", text: String(decoding: data, as: UTF8.self))],
            structuredContent: payload,
            isError: true
        )
        try emit(RPCResponse(id: id, result: response, error: nil))
    }

    private func emitError(id: JSONValue?, message: String) throws {
        try emit(RPCResponse<JSONValue>(
            id: id,
            result: nil,
            error: RPCError(code: -32601, message: message)
        ))
    }

    private func emit<Payload: Encodable>(_ response: RPCResponse<Payload>) throws {
        let data = try JSONEncoder().encode(response)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0A]))
    }
}
