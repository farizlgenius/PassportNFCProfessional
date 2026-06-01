//
//  TransportFactory.swift
//  NFCPassportReader
//
//  Created by Far-iz Lengha on 28/5/2569 BE.
//
import Foundation

#if canImport(CoreNFC)
import CoreNFC
#endif

#if canImport(CryptoTokenKit)
import CryptoTokenKit
#endif

enum TransportFactory {

    static func makeCoreNFC(
        tag: NFCISO7816Tag
    ) -> APDUTransceiver {

        return CoreNFCTransceiver(
            tag: tag
        )
    }
    
    static func makeCTK()
    async throws -> APDUTransceiver {

        guard let slotManager =
            TKSmartCardSlotManager.default else {

            throw NSError(
                domain: "CTK",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                    "No SmartCard slot manager"
                ]
            )
        }

        let slotNames =
            slotManager.slotNames

        guard let first =
            slotNames.first,

            let slot =
            slotManager.slotNamed(first),

            let card =
            slot.makeSmartCard() else {

            throw NSError(
                domain: "CTK",
                code: -2,
                userInfo: [
                    NSLocalizedDescriptionKey:
                    "No smartcard found"
                ]
            )
        }

        try await card.beginSession()

        return CTKTransceiver(
            card: card
        )
    }

   
}
