import Foundation

final class FileLogger {

    static let shared = FileLogger()

    private let queue = DispatchQueue(label: "PassportNFC.FileLogger")

    private var fileHandle: FileHandle?

    private(set) var logFileURL: URL?

    private init() {}


    // MARK: - Start with custom name

    func startSession(fileName: String? = nil) {
        
        let formatter = DateFormatter()

            formatter.dateFormat = "yyyyMMdd_HHmmss"

            let baseName = fileName ?? "PassportRead"

            let logName = "\(baseName)_\(formatter.string(from: Date()))"

        queue.sync {

            closeSession()

            let documents = FileManager.default.urls(

                for: .documentDirectory,

                in: .userDomainMask

            ).first!

            let logsDirectory = documents.appendingPathComponent(

                "Logs",

                isDirectory: true

            )

            try? FileManager.default.createDirectory(

                at: logsDirectory,

                withIntermediateDirectories: true

            )

            // Remove invalid filename characters

            let safeName = logName.replacingOccurrences(

                of: #"[/\\?%*|"<>\:]"#,

                with: "_",

                options: .regularExpression

            )

            var fileURL = logsDirectory.appendingPathComponent("\(safeName).log")

            // Prevent overwriting existing files

            var count = 1

            while FileManager.default.fileExists(atPath: fileURL.path) {

                fileURL = logsDirectory.appendingPathComponent(

                    "\(safeName)_\(count).log"

                )

                count += 1

            }

            FileManager.default.createFile(

                atPath: fileURL.path,

                contents: nil

            )

            do {

                fileHandle = try FileHandle(forWritingTo: fileURL)

                logFileURL = fileURL

                write("===== Log started =====")

            } catch {

                print("Unable to create log file: \(error)")

            }

        }

    }

    // MARK: - Write

    func write(_ message: String) {

        queue.async {

            guard let fileHandle = self.fileHandle else {

                return

            }

            let timestamp = ISO8601DateFormatter().string(from: Date())

            let line = "\(timestamp) \(message)\n"

            guard let data = line.data(using: .utf8) else {

                return

            }

            do {

                try fileHandle.seekToEnd()

                fileHandle.write(data)

            } catch {

                print("Unable to write log: \(error)")

            }

        }

    }

    // MARK: - Close

    func closeSession() {

        write("===== Log ended =====")

        do {

            try fileHandle?.close()

        } catch {

        }

        fileHandle = nil

    }

    // MARK: - Current log file

    func currentLogFileURL() -> URL? {

        return logFileURL

    }

}
