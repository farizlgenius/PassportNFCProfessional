//
//  CTKTransceiver.swift
//  NFCPassportReader
//
//  Created by Far-iz Lengha on 28/5/2569 BE.
//

import Foundation
import CryptoTokenKit
import CoreNFC

final class CTKTransceiver: APDUTransceiver {

    private let smartCard: TKSmartCard

    // ---------------------------------------------------------
    // RAW APDU SERIALIZATION
    // ---------------------------------------------------------
    //
    // IMPORTANT:
    // CTK does NOT behave like CoreNFC.
    //
    // We must serialize APDU bytes EXACTLY like CoreNFC.
    //
    // For ICAO Secure Messaging:
    //
    // ALWAYS append trailing Le = 00
    //
    // Example:
    // 0C B0 00 00 0D 97 01 04 8E 08 .... 00
    //
    // ---------------------------------------------------------

    private func serializeAPDU(
        _ apdu: NFCISO7816APDU
    ) -> Data {

        var bytes: [UInt8] = [
            apdu.instructionClass,
            apdu.instructionCode,
            apdu.p1Parameter,
            apdu.p2Parameter
        ]

        let body = apdu.data ?? Data()
        let le = apdu.expectedResponseLength

        let isSecureMessaging =
            apdu.instructionClass == 0x0C

        // =====================================================
        // ICAO SECURE MESSAGING
        // =====================================================

        if isSecureMessaging {

            // Lc + Body
            if !body.isEmpty {

                if body.count <= 255 {

                    bytes.append(UInt8(body.count))

                } else {

                    // Extended Lc
                    bytes.append(0x00)

                    bytes.append(
                        UInt8((body.count >> 8) & 0xFF)
                    )

                    bytes.append(
                        UInt8(body.count & 0xFF)
                    )
                }

                bytes.append(contentsOf: body)
            }

            // IMPORTANT:
            // CoreNFC ALWAYS appends trailing Le=00
            // for protected APDU.
            //
            // CTK must do EXACTLY the same.
            //
            bytes.append(0x00)

            return Data(bytes)
        }

        // =====================================================
        // STANDARD ISO7816 APDU
        // =====================================================

        // CASE 1
        // No body / No Le
        if body.isEmpty && le <= 0 {

            return Data(bytes)
        }

        // CASE 2
        // No body / Le only
        if body.isEmpty && le > 0 {

            if le <= 256 {

                bytes.append(
                    le == 256
                    ? 0x00
                    : UInt8(le)
                )

            } else {

                // Extended Le
                bytes.append(0x00)

                bytes.append(
                    UInt8((le >> 8) & 0xFF)
                )

                bytes.append(
                    UInt8(le & 0xFF)
                )
            }

            return Data(bytes)
        }

        // CASE 3
        // Body / No Le
        if !body.isEmpty && le <= 0 {

            if body.count <= 255 {

                bytes.append(UInt8(body.count))
                bytes.append(contentsOf: body)

            } else {

                // Extended Lc
                bytes.append(0x00)

                bytes.append(
                    UInt8((body.count >> 8) & 0xFF)
                )

                bytes.append(
                    UInt8(body.count & 0xFF)
                )

                bytes.append(contentsOf: body)
            }

            return Data(bytes)
        }

        // CASE 4
        // Body + Le

        if body.count <= 255 {

            bytes.append(UInt8(body.count))
            bytes.append(contentsOf: body)

            if le == 256 {

                bytes.append(0x00)

            } else {

                bytes.append(UInt8(le))
            }

        } else {

            // Extended Case 4

            bytes.append(0x00)

            bytes.append(
                UInt8((body.count >> 8) & 0xFF)
            )

            bytes.append(
                UInt8(body.count & 0xFF)
            )

            bytes.append(contentsOf: body)

            if le >= 65536 {

                bytes.append(0x00)
                bytes.append(0x00)

            } else {

                bytes.append(
                    UInt8((le >> 8) & 0xFF)
                )

                bytes.append(
                    UInt8(le & 0xFF)
                )
            }
        }

        return Data(bytes)
    }

    // =========================================================
    // INIT
    // =========================================================

    init(card: TKSmartCard) {

        self.smartCard = card

        // IMPORTANT:
        // Disable automatic extended APDU handling.
        //
        // Many ePassports fail secure messaging
        // when CTK negotiates extended APDU automatically.
        //
        smartCard.useExtendedLength = false

        smartCard.isSensitive = true
    }

    // =========================================================
    // CONNECT
    // =========================================================

    func connect() async throws {

        try await smartCard.beginSession()

        // MUST remain disabled
        smartCard.useExtendedLength = false
    }

    // =========================================================
    // DISCONNECT
    // =========================================================

    func disconnect() {

        smartCard.endSession()
    }

    // =========================================================
    // SEND COMMAND (Tuple)
    // =========================================================

    func sendCommand(
        apdu: NFCISO7816APDU
    ) async throws -> (Data, UInt8, UInt8) {

        let request = serializeAPDU(apdu)

        print(
            "CTK OUT:",
            request.map {
                String(format: "%02X", $0)
            }.joined(separator: " ")
        )

        return try await withCheckedThrowingContinuation {
            continuation in

            smartCard.transmit(request) {
                response,
                error in

                if let error {

                    continuation.resume(
                        throwing: error
                    )

                    return
                }

                guard let response,
                      response.count >= 2 else {

                    continuation.resume(
                        throwing: NSError(
                            domain: "CTK",
                            code: -1
                        )
                    )

                    return
                }

                print(
                    "CTK IN:",
                    response.map {
                        String(format: "%02X", $0)
                    }.joined(separator: " ")
                )

                let sw1 =
                    response[response.count - 2]

                let sw2 =
                    response[response.count - 1]

                let data =
                    response.dropLast(2)

                continuation.resume(
                    returning: (
                        Data(data),
                        sw1,
                        sw2
                    )
                )
            }
        }
    }

    // =========================================================
    // SEND COMMAND (ResponseAPDU)
    // =========================================================

    func sendCommand(
        _ apdu: NFCISO7816APDU
    ) async throws -> ResponseAPDU {

        let request =
            serializeAPDU(apdu)

        print(
            "CTK OUT:",
            request.map {
                String(format: "%02X", $0)
            }.joined(separator: " ")
        )

        return try await withCheckedThrowingContinuation {
            continuation in

            smartCard.transmit(request) {
                response,
                error in

                if let error {

                    continuation.resume(
                        throwing: error
                    )

                    return
                }

                guard let response,
                      response.count >= 2 else {

                    continuation.resume(
                        throwing: NSError(
                            domain: "CTK",
                            code: -2
                        )
                    )

                    return
                }

                print(
                    "CTK IN:",
                    response.map {
                        String(format: "%02X", $0)
                    }.joined(separator: " ")
                )

                let sw1 =
                    response[response.count - 2]

                let sw2 =
                    response[response.count - 1]

                let data =
                    response.dropLast(2)

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
