//
//  Logger.swift
//  PassportNFCProfessional
//
//  Created by honorsupplying on 3/27/26.
//

import Foundation
import os

public final class Logger {

    public static let shared = Logger()

    private init() {
        createLogDirectoryIfNeeded()
    }

    // MARK: - Config
    public enum LogLevel: String {
        case debug = "DEBUG"
        case info = "INFO"
        case error = "ERROR"
    }

    public var isDebugEnabled: Bool = false
    public var maxFileSize: UInt64 = 2 * 1024 * 1024 // 2MB
    public var maxNumberOfFiles: Int = 5

    // MARK: - File
    private let fileManager = FileManager.default
    private let folderName = "FrameworkLogs"
    private let fileName = "current.log"

    private var logDirectory: URL {
        fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(folderName)
    }

    private var logFile: URL {
        logDirectory.appendingPathComponent(fileName)
    }

    private let queue = DispatchQueue(label: "logger.queue", qos: .utility)

    private let osLogger = os.Logger(subsystem: "com.yourframework", category: "log")

    // MARK: - Public
    public func log(_ message: String, level: LogLevel = .info) {
        if level == .debug && !isDebugEnabled { return }

        let time = ISO8601DateFormatter().string(from: Date())
        let text = "[\(time)] [\(level.rawValue)] \(message)\n"

        queue.async {
            self.rotateIfNeeded()
            self.write(text)
            self.cleanup()
        }

        osLogger.log("\(level.rawValue): \(message)")
    }

    // MARK: - Write
    private func write(_ text: String) {
        if !fileManager.fileExists(atPath: logFile.path) {
            try? text.write(to: logFile, atomically: true, encoding: .utf8)
        } else {
            if let handle = try? FileHandle(forWritingTo: logFile) {
                handle.seekToEndOfFile()
                handle.write(text.data(using: .utf8)!)
                try? handle.close()
            }
        }
    }

    // MARK: - Directory
    private func createLogDirectoryIfNeeded() {
        if !fileManager.fileExists(atPath: logDirectory.path) {
            try? fileManager.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        }
    }

    // MARK: - Rotation
    private func rotateIfNeeded() {
        guard let attr = try? fileManager.attributesOfItem(atPath: logFile.path),
              let size = attr[.size] as? UInt64 else { return }

        if size > maxFileSize {
            let newName = "log_\(Int(Date().timeIntervalSince1970)).log"
            let newURL = logDirectory.appendingPathComponent(newName)
            try? fileManager.moveItem(at: logFile, to: newURL)
        }
    }

    // MARK: - Cleanup
    private func cleanup() {
        guard let files = try? fileManager.contentsOfDirectory(at: logDirectory, includingPropertiesForKeys: [.creationDateKey]) else { return }

        let archives = files.filter { $0.lastPathComponent != fileName }

        if archives.count <= maxNumberOfFiles { return }

        let sorted = archives.sorted {
            let d1 = try? $0.resourceValues(forKeys: [.creationDateKey]).creationDate ?? Date()
            let d2 = try? $1.resourceValues(forKeys: [.creationDateKey]).creationDate ?? Date()
            return d1! < d2!
        }

        for file in sorted.prefix(archives.count - maxNumberOfFiles) {
            try? fileManager.removeItem(at: file)
        }
    }

    // MARK: - Public Access
    public func getLogs() -> [URL] {
        return (try? fileManager.contentsOfDirectory(at: logDirectory, includingPropertiesForKeys: nil)) ?? []
    }

    public func getLogFolderPath() -> String {
        return logDirectory.path
    }
}
