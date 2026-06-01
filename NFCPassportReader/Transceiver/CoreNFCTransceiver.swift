//
//  CoreNFCTransceiver.swift
//  NFCPassportReader
//
//  Created by Far-iz Lengha on 28/5/2569 BE.
//

import Foundation
import CoreNFC

final class CoreNFCTransceiver: APDUTransceiver {

    private let tag: NFCISO7816Tag

    init(tag: NFCISO7816Tag) {
        self.tag = tag
    }

    func connect() async throws {
        // already connected by session normally
    }

    func disconnect() {
        // nothing required
    }
    
    func sendCommand(
            apdu: NFCISO7816APDU
        ) async throws -> (Data, UInt8, UInt8) {

            return try await tag.sendCommand(
                apdu: apdu
            )
        }

    func sendCommand(
        _ apdu: NFCISO7816APDU
    ) async throws -> ResponseAPDU {

        try await withCheckedThrowingContinuation { continuation in

            tag.sendCommand(apdu: apdu) {
                data,
                sw1,
                sw2,
                error in

                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                continuation.resume(
                    returning: ResponseAPDU(
                        data: [UInt8](data),
                        sw1: sw1,
                        sw2: sw2
                    )
                )
            }
        }
    }
}
