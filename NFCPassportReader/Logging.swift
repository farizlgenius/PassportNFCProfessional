//
//  Logging.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

struct AppLogger {

    private let logger: Logger
    
    private let category: String

    init(subsystem: String, category: String) {

        self.logger = Logger(subsystem: subsystem, category: category)

        self.category = category

    }

    func debug(_ message: String) {

        logger.debug("\(message)")

        FileLogger.shared.write("[DEBUG][\(category)] \(message)")

    }

    func info(_ message: String) {

        logger.info("\(message)")

        FileLogger.shared.write("[INFO][\(category)] \(message)")

    }

    func error(_ message: String) {

        logger.error("\(message)")

        FileLogger.shared.write("[ERROR][\(category)] \(message)")

    }
    
    func warning(_ message: String) {
        
        logger.warning("\(message)")
        
        FileLogger.shared.write("[WARNING][\(category)] \(message)")
    }

}

extension AppLogger {
    /// Using your bundle identifier is a great way to ensure a unique identifier.
    private static var subsystem = Bundle.main.bundleIdentifier!
    
    /// Tag Reader logs
    static let passportReader = AppLogger(subsystem: subsystem, category: "passportReader")

    /// Tag Reader logs
    static let tagReader = AppLogger(subsystem: subsystem, category: "tagReader")

    /// SecureMessaging logs
    static let secureMessaging = AppLogger(subsystem: subsystem, category: "secureMessaging")

    static let openSSL = AppLogger(subsystem: subsystem, category: "openSSL")

    static let bac = AppLogger(subsystem: subsystem, category: "BAC")
    static let chipAuth = AppLogger(subsystem: subsystem, category: "chipAuthentication")
    static let pace = AppLogger(subsystem: subsystem, category: "PACE")
}

