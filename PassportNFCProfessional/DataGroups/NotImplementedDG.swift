//
//  NotImplementedDG.swift
//  PassportNFCProfessional
//
//  Created by honorsupplying on 5/27/26.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class NotImplementedDG: DataGroup {
    override public var datagroupType: DataGroupId { .Unknown }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}
