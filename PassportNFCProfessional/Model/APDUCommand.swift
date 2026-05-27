//
//  APDUCommand.swift
//  PassportNFCProfessional
//
//  Created by honorsupplying on 5/27/26.
//

import Foundation

public struct APDUCommand {

    // MARK: - Properties

    public let instructionClass: UInt8

    public let instructionCode: UInt8

    public let p1Parameter: UInt8

    public let p2Parameter: UInt8

    public let data: Data?

    // Same naming as CoreNFC
    public let expectedResponseLength: Int

    // MARK: - Init

    public init(
        instructionClass: UInt8,
        instructionCode: UInt8,
        p1Parameter: UInt8,
        p2Parameter: UInt8,
        data: Data = Data(),
        expectedResponseLength: Int = 0
    ) {

        self.instructionClass =
            instructionClass

        self.instructionCode =
            instructionCode

        self.p1Parameter =
            p1Parameter

        self.p2Parameter =
            p2Parameter

        self.data = data

        self.expectedResponseLength =
            expectedResponseLength
    }
}


extension APDUCommand: CustomStringConvertible {

    public var description: String {

        let dataHex = data?
            .map { String(format: "%02X", $0) }
            .joined(separator: " ")
            ?? ""

        return String(
            format: "CLA=%02X INS=%02X P1=%02X P2=%02X DATA=[%@] Le=%d",
            instructionClass,
            instructionCode,
            p1Parameter,
            p2Parameter,
            dataHex,
            expectedResponseLength
        )
    }
}


extension APDUCommand {

    init?(bytes: [UInt8]) {

        // Minimum APDU header
        guard bytes.count >= 4 else {
            return nil
        }

        let cla = bytes[0]
        let ins = bytes[1]
        let p1  = bytes[2]
        let p2  = bytes[3]

        // Case 1
        // CLA INS P1 P2

        if bytes.count == 4 {

            self.init(
                instructionClass: cla,
                instructionCode: ins,
                p1Parameter: p1,
                p2Parameter: p2
            )

            return
        }

        // Case 2
        // CLA INS P1 P2 Le

        if bytes.count == 5 {

            let le = Int(bytes[4])

            self.init(
                instructionClass: cla,
                instructionCode: ins,
                p1Parameter: p1,
                p2Parameter: p2,
                expectedResponseLength: le
            )

            return
        }

        // Case 3 / 4
        // CLA INS P1 P2 Lc Data [Le]

        let lc = Int(bytes[4])

        guard bytes.count >= 5 + lc else {
            return nil
        }

        let data = Data(bytes[5 ..< 5 + lc])

        var le = 0

        // Optional Le
        if bytes.count > 5 + lc {

            le = Int(bytes[5 + lc])
        }

        self.init(
            instructionClass: cla,
            instructionCode: ins,
            p1Parameter: p1,
            p2Parameter: p2,
            data: data,
            expectedResponseLength: le
        )
    }
}


extension APDUCommand {

    func toData() -> Data {

        var bytes: [UInt8] = [

            instructionClass,

            instructionCode,

            p1Parameter,

            p2Parameter

        ]

        // MARK: - Lc + Data

        if let data, !data.isEmpty {

            if data.count <= 0xFF {

                // Short Lc

                bytes.append(UInt8(data.count))

            } else {

                // Extended Lc

                bytes.append(0x00)

                bytes.append(

                    UInt8((data.count >> 8) & 0xFF)

                )

                bytes.append(

                    UInt8(data.count & 0xFF)

                )

            }

            bytes.append(contentsOf: data)

        }

        // MARK: - Le

        if expectedResponseLength > 0 {

            // ISO7816 special case:

            // 0x00 means 256 bytes

            if expectedResponseLength == 256 {

                bytes.append(0x00)

            } else if expectedResponseLength < 256 {

                bytes.append(

                    UInt8(expectedResponseLength)

                )

            } else {

                // Extended Le

                bytes.append(0x00)

                bytes.append(

                    UInt8((expectedResponseLength >> 8) & 0xFF)

                )

                bytes.append(

                    UInt8(expectedResponseLength & 0xFF)

                )

            }

        }

        return Data(bytes)

    }

}
