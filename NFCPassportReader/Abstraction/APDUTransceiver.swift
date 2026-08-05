//
//  APDUTransceiver.swift
//  NFCPassportReader
//
//  Created by Far-iz Lengha on 28/5/2569 BE.
//

import Foundation
import CoreNFC

public protocol APDUTransceiver {

    func connect() async throws

    func disconnect()

    func sendCommand(
        _ apdu: NFCISO7816APDU
    ) async throws -> ResponseAPDU
    
    func sendCommand(
            apdu: NFCISO7816APDU
        ) async throws -> (Data, UInt8, UInt8)
}
