import AegisSecretCore
import Foundation
import MCP

private struct ToolErrorPayload: Codable {
    let error: String
}

@main
struct AegisSecretMCPEntryPoint {
    static func main() async {
        let capabilityStore = CapabilityStore()
        let secretStore = KeychainSecretStore()
        let authenticator = LocalDeviceAuthenticator()
        let broker = HTTPCapabilityBroker(
            capabilityStore: capabilityStore,
            secretStore: secretStore,
            authenticator: authenticator
        )

        let server = Server(
            name: "aegis-secret",
            version: "0.1.0",
            capabilities: .init(
                tools: .init(listChanged: false)
            )
        )

        await server.withMethodHandler(ListTools.self) { _ in
            .init(tools: [
                Tool(
                    name: "list_capabilities",
                    title: "List capabilities",
                    description: "List the safe brokered capabilities available to the local agent. This never returns raw secret names or values.",
                    inputSchema: .object([
                        "type": .string("object"),
                        "properties": .object([:])
                    ]),
                    outputSchema: .object([
                        "type": .string("object"),
                        "properties": .object([
                            "capabilities": .object([
                                "type": .string("array")
                            ])
                        ])
                    ])
                ),
                Tool(
                    name: "probe_capability",
                    title: "Probe capability",
                    description: "Check whether a configured capability exists locally and whether its backing Keychain secret is available.",
                    inputSchema: .object([
                        "type": .string("object"),
                        "properties": .object([
                            "capability": .object([
                                "type": .string("string"),
                                "description": .string("Capability name to probe.")
                            ])
                        ]),
                        "required": .array([.string("capability")])
                    ]),
                    outputSchema: .object([
                        "type": .string("object"),
                        "properties": .object([
                            "ok": .object(["type": .string("boolean")]),
                            "description": .object(["type": .string("string")])
                        ])
                    ])
                ),
                Tool(
                    name: "http_request",
                    title: "HTTP request",
                    description: "Send an authenticated HTTP request through a named local capability. The secret never leaves the local broker.",
                    inputSchema: .object([
                        "type": .string("object"),
                        "properties": .object([
                            "capability": .object([
                                "type": .string("string"),
                                "description": .string("Capability name to use.")
                            ]),
                            "method": .object([
                                "type": .string("string"),
                                "description": .string("HTTP method, such as GET or POST.")
                            ]),
                            "path": .object([
                                "type": .string("string"),
                                "description": .string("Optional relative path under the capability base URL.")
                            ]),
                            "url": .object([
                                "type": .string("string"),
                                "description": .string("Optional absolute URL. It must still match the capability policy.")
                            ]),
                            "headers": .object([
                                "type": .string("object"),
                                "description": .string("Optional non-sensitive request headers.")
                            ]),
                            "body": .object([
                                "description": .string("Optional request body. Strings are sent as-is; objects and arrays are JSON-encoded.")
                            ]),
                            "requester": .object([
                                "type": .string("string"),
                                "description": .string("Optional caller label shown in the approval prompt.")
                            ])
                        ]),
                        "required": .array([
                            .string("capability"),
                            .string("method")
                        ])
                    ]),
                    outputSchema: .object([
                        "type": .string("object"),
                        "properties": .object([
                            "status": .object(["type": .string("integer")]),
                            "headers": .object(["type": .string("object")]),
                            "body": .object(["type": .string("string")]),
                            "body_base64": .object(["type": .string("string")]),
                            "mime_type": .object(["type": .string("string")]),
                            "truncated": .object(["type": .string("boolean")])
                        ])
                    ])
                )
            ])
        }

        await server.withMethodHandler(CallTool.self) { params in
            do {
                switch params.name {
                case "list_capabilities":
                    return try successResult(["capabilities": capabilityStore.summaries()])
                case "probe_capability":
                    guard let capability = params.arguments?["capability"]?.stringValue else {
                        return errorResult("Missing `capability`.")
                    }
                    return try successResult(broker.probe(capability: capability))
                case "http_request":
                    guard let arguments = params.arguments else {
                        return errorResult("Missing tool arguments.")
                    }

                    guard let capability = arguments["capability"]?.stringValue else {
                        return errorResult("Missing `capability`.")
                    }
                    guard let method = arguments["method"]?.stringValue else {
                        return errorResult("Missing `method`.")
                    }

                    let headers = try decodeHeaders(arguments["headers"])
                    let body = try decodeBody(arguments["body"])
                    let requester = arguments["requester"]?.stringValue ?? ProcessInfo.processInfo.environment["AEGIS_SECRET_AGENT_NAME"] ?? "MCP client"
                    let response = try await broker.request(
                        capability: capability,
                        request: BrokerRequest(
                            method: method,
                            path: arguments["path"]?.stringValue,
                            url: arguments["url"]?.stringValue,
                            headers: headers,
                            bodyData: body.data,
                            bodyIsStructuredJSON: body.structuredJSON
                        ),
                        requester: requester
                    )
                    return try successResult(response)
                default:
                    return errorResult("Unknown tool `\(params.name)`.")
                }
            } catch let error as AegisSecretError {
                return errorResult(error.description)
            } catch {
                return errorResult(error.localizedDescription)
            }
        }

        do {
            let transport = StdioTransport()
            try await server.start(transport: transport)
            await server.waitUntilCompleted()
        } catch {
            fputs("aegis-secret-mcp error: \(error.localizedDescription)\n", stderr)
            Foundation.exit(ExitCode.failure.rawValue)
        }
    }

    private static func decodeHeaders(_ value: Value?) throws -> [String: String] {
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

    private static func decodeBody(_ value: Value?) throws -> (data: Data?, structuredJSON: Bool) {
        guard let value else {
            return (nil, false)
        }

        if let stringValue = value.stringValue {
            return (stringValue.data(using: .utf8), false)
        }

        let data = try JSONEncoder().encode(value)
        return (data, true)
    }

    private static func successResult<T: Codable>(_ payload: T) throws -> CallTool.Result {
        let data = try prettyJSON(payload)
        return try .init(
            content: [
                Tool.Content.text(String(decoding: data, as: UTF8.self))
            ],
            structuredContent: payload,
            isError: false
        )
    }

    private static func errorResult(_ message: String) -> CallTool.Result {
        let payload = ToolErrorPayload(error: message)
        let data = (try? prettyJSON(payload)) ?? Data("{\"error\":\"\(message)\"}".utf8)
        return (try? .init(
            content: [
                Tool.Content.text(String(decoding: data, as: UTF8.self))
            ],
            structuredContent: payload,
            isError: true
        )) ?? .init(content: [Tool.Content.text(message)], isError: true)
    }
}
