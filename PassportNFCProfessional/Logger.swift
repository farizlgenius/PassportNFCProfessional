//
//  Logger.swift
//  PassportNFCProfessional
//
//  Created by honorsupplying on 5/27/26.
//
import Foundation
import OSLog


extension Logger {
    /// Using your bundle identifier is a great way to ensure a unique identifier.
    private static var subsystem = Bundle.main.bundleIdentifier!
    
    /// Tag Reader logs
    static let passportReader = Logger(subsystem: subsystem, category: "passportReader")

    /// Tag Reader logs
    static let tagReader = Logger(subsystem: subsystem, category: "tagReader")
    
    static let passportController = Logger(subsystem: subsystem, category: "passportController")
    
    static let readerController = Logger(subsystem: subsystem, category: "readerController")

    /// SecureMessaging logs
    static let secureMessaging = Logger(subsystem: subsystem, category: "secureMessaging")

    static let openSSL = Logger(subsystem: subsystem, category: "openSSL")

    static let bac = Logger(subsystem: subsystem, category: "BAC")
    static let chipAuth = Logger(subsystem: subsystem, category: "chipAuthentication")
    static let pace = Logger(subsystem: subsystem, category: "PACE")
}
