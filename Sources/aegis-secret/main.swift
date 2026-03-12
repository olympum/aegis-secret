import AegisSecretCore
import Foundation

@main
struct AegisSecretCLIEntryPoint {
    static func main() async {
        let app = CLIApplication()
        await app.run(
            arguments: Array(CommandLine.arguments.dropFirst()),
            stdinIsTTY: isatty(FileHandle.standardInput.fileDescriptor) != 0
        )
    }
}
