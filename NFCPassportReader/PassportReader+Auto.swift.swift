//
//  PassportReader+Auto.swift.swift
//  NFCPassportReader
//
//  Created by Far-iz Lengha on 28/5/2569 BE.
//

// PassportReader+Auto.swift

import Foundation
import OSLog

#if canImport(CoreNFC)
import CoreNFC
#endif

@available(iOS 15, macOS 12, *)
extension PassportReader {

    public func readPassportAuto(
        mrzKey: String,
        tags: [DataGroupId] = [],
        aaChallenge: [UInt8]? = nil,
        skipSecureElements: Bool = true,
        skipCA: Bool = false,
        skipPACE: Bool = false,
        useExtendedMode: Bool = false,
        customDisplayMessage:
            ((NFCViewDisplayMessage) -> String?)? = nil
    ) async throws -> NFCPassportModel {

        #if canImport(CoreNFC)

        if NFCTagReaderSession.readingAvailable {

            Logger.passportReader.info(
                "Using CoreNFC"
            )

            return try await readPassport(
                mrzKey: mrzKey,
                tags: tags,
                aaChallenge: aaChallenge,
                skipSecureElements:
                    skipSecureElements,
                skipCA: skipCA,
                skipPACE: skipPACE,
                useExtendedMode:
                    useExtendedMode,
                customDisplayMessage:
                    customDisplayMessage
            )
        }

        #endif

        Logger.passportReader.info(
            "CoreNFC unavailable -> using CTK"
        )
        
        // If no tags specified, read all
        if self.dataGroupsToRead.count == 0 {
            // Start off with .COM, will always read (and .SOD but we'll add that after), and then add the others from the COM
            self.dataGroupsToRead.append(contentsOf:[.COM, .SOD] )
            self.readAllDatagroups = true
        } else {
            // We are reading specific datagroups
            self.readAllDatagroups = false
        }

        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        self.aaChallenge = aaChallenge
        self.skipCA = skipCA
        self.skipPACE = skipPACE
        self.useExtendedMode = useExtendedMode
        self.skipSecureElements =
            skipSecureElements

        let transport =
            try await TransportFactory.makeCTK()

        let tagReader =
            TagReader(
                tag: transport
            )

        return try await startReading(
            tagReader: tagReader
        )
    }
}
