//
//  DataGroupHash.swift
//  PassportNFCProfessional
//
//  Created by honorsupplying on 5/27/26.
//

@available(iOS 13, macOS 10.15, *)
public struct DataGroupHash {
    public var id: String
    public var sodHash: String
    public var computedHash : String
    public var match : Bool
}
