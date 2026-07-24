//
//  BACHandler.swift
//  NFCTest
//
//  Created by Andy Qua on 07/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

#if !os(macOS)
import CoreNFC

@available(iOS 15, *)
public class BACHandler {
    let KENC : [UInt8] = [0,0,0,1]
    let KMAC : [UInt8] = [0,0,0,2]
    
    public var ksenc : [UInt8] = []
    public var ksmac : [UInt8] = []

    var rnd_icc : [UInt8] = []
    var rnd_ifd : [UInt8] = []
    public var kifd : [UInt8] = []
    
    var tagReader : TagReader?
    
    public init() {
        // For testing only
    }
    
    public init(tagReader: TagReader) {
        self.tagReader = tagReader
    }

    public func performBACAndGetSessionKeys( mrzKey : String ) async throws {
        guard let tagReader = self.tagReader else {
            throw NFCPassportReaderError.NoConnectedTag
        }
        
        AppLogger.bac.debug( "BACHandler - deriving Document Basic Access Keys" )
        _ = try self.deriveDocumentBasicAccessKeys(mrz: mrzKey)
        
        // Make sure we clear secure messaging (could happen if we read an invalid DG or we hit a secure error
        tagReader.secureMessaging = nil
        
        // get Challenge
        AppLogger.bac.debug( "BACHandler - Getting initial challenge" )
        let response = try await tagReader.getChallenge()
    
        AppLogger.bac.debug( "DATA - \(response.data)" )
        
        AppLogger.bac.debug( "BACHandler - Doing mutual authentication" )
        let cmd_data = self.authentication(rnd_icc: [UInt8](response.data))
        let maResponse = try await tagReader.doMutualAuthentication(cmdData: Data(cmd_data))
        AppLogger.bac.debug( "DATA - \(maResponse.data)" )
        guard maResponse.data.count > 0 else {
            throw NFCPassportReaderError.InvalidMRZKey
        }
        
        let (KSenc, KSmac, ssc) = try self.sessionKeys(data: [UInt8](maResponse.data))
        tagReader.secureMessaging = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        AppLogger.bac.debug( "BACHandler - complete" )
    }


    func deriveDocumentBasicAccessKeys(mrz: String) throws -> ([UInt8], [UInt8]) {
        let kseed = generateInitialKseed(kmrz:mrz)
    
        AppLogger.bac.debug("Calculate the Basic Access Keys (Kenc and Kmac) using TR-SAC 1.01, 4.2")
        let smskg = SecureMessagingSessionKeyGenerator()
        self.ksenc = try smskg.deriveKey(keySeed: kseed, mode: .ENC_MODE)
        self.ksmac = try smskg.deriveKey(keySeed: kseed, mode: .MAC_MODE)
                
        return (ksenc, ksmac)
    }
    
    ///
    /// Calculate the kseed from the kmrz:
    /// - Calculate a SHA-1 hash of the kmrz
    /// - Take the most significant 16 bytes to form the Kseed.
    /// @param kmrz: The MRZ information
    /// @type kmrz: a string
    /// @return: a 16 bytes string
    ///
    /// - Parameter kmrz: mrz key
    /// - Returns: first 16 bytes of the mrz SHA1 hash
    ///
    func generateInitialKseed(kmrz : String ) -> [UInt8] {
        
        AppLogger.bac.debug("Calculate the SHA-1 hash of MRZ_information")
        AppLogger.bac.debug("\tMRZ KEY - \(kmrz)")
        let hash = calcSHA1Hash( [UInt8](kmrz.data(using:.utf8)!) )
        
        AppLogger.bac.debug("\tsha1(MRZ_information): \(binToHexRep(hash))")
        
        let subHash = Array(hash[0..<16])
        AppLogger.bac.debug("Take the most significant 16 bytes to form the Kseed")
        AppLogger.bac.debug("\tKseed: \(binToHexRep(subHash))" )
        
        return Array(subHash)
    }
    
    
    /// Construct the command data for the mutual authentication.
    /// - Request an 8 byte random number from the MRTD's chip (rnd.icc)
    /// - Generate an 8 byte random (rnd.ifd) and a 16 byte random (kifd)
    /// - Concatenate rnd.ifd, rnd.icc and kifd (s = rnd.ifd + rnd.icc + kifd)
    /// - Encrypt it with TDES and the Kenc key (eifd = TDES(s, Kenc))
    /// - Compute the MAC over eifd with TDES and the Kmax key (mifd = mac(pad(eifd))
    /// - Construct the APDU data for the mutualAuthenticate command (cmd_data = eifd + mifd)
    ///
    /// @param rnd_icc: The challenge received from the ICC.
    /// @type rnd_icc: A 8 bytes binary string
    /// @return: The APDU binary data for the mutual authenticate command
    func authentication( rnd_icc : [UInt8]) -> [UInt8] {
        self.rnd_icc = rnd_icc
        
        AppLogger.bac.debug("Request an 8 byte random number from the MRTD's chip")
        AppLogger.bac.debug("\tRND.ICC: '(binToHexRep(self.rnd_icc))")
        
        self.rnd_icc = rnd_icc

        let rnd_ifd = generateRandomUInt8Array(8)
        let kifd = generateRandomUInt8Array(16)
        
        AppLogger.bac.debug("Generate an 8 byte random and a 16 byte random")
        AppLogger.bac.debug("\tRND.IFD: \(binToHexRep(rnd_ifd))" )
        AppLogger.bac.debug("\tRND.Kifd: \(binToHexRep(kifd))")
        
        let s = rnd_ifd + rnd_icc + kifd
        
        AppLogger.bac.debug("Concatenate RND.IFD, RND.ICC and Kifd")
        AppLogger.bac.debug("\tS: \(binToHexRep(s))")
        
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let eifd = tripleDESEncrypt(key: ksenc,message: s, iv: iv)
        
        AppLogger.bac.debug("Encrypt S with TDES key Kenc as calculated in Appendix 5.2")
        AppLogger.bac.debug("\tEifd: \(binToHexRep(eifd))")
        
        let mifd = mac(algoName: .DES, key: ksmac, msg: pad(eifd, blockSize:8))

        AppLogger.bac.debug("Compute MAC over eifd with TDES key Kmac as calculated in-Appendix 5.2")
        AppLogger.bac.debug("\tMifd: \(binToHexRep(mifd))")
        // Construct APDU
        
        let cmd_data = eifd + mifd
        AppLogger.bac.debug("Construct command data for MUTUAL AUTHENTICATE")
        AppLogger.bac.debug("\tcmd_data: \(binToHexRep(cmd_data))")
        
        self.rnd_ifd = rnd_ifd
        self.kifd = kifd

        return cmd_data
    }
    
    /// Calculate the session keys (KSenc, KSmac) and the SSC from the data
    /// received by the mutual authenticate command.
    
    /// @param data: the data received from the mutual authenticate command send to the chip.
    /// @type data: a binary string
    /// @return: A set of two 16 bytes keys (KSenc, KSmac) and the SSC
    public func sessionKeys(data : [UInt8] ) throws -> ([UInt8], [UInt8], [UInt8]) {
        AppLogger.bac.debug("Decrypt and verify received data and compare received RND.IFD with generated RND.IFD \(binToHexRep(self.ksmac))" )
        
        let response = tripleDESDecrypt(key: self.ksenc, message: [UInt8](data[0..<32]), iv: [0,0,0,0,0,0,0,0] )

        let response_kicc = [UInt8](response[16..<32])
        let Kseed = xor(self.kifd, response_kicc)
        AppLogger.bac.debug("Calculate XOR of Kifd and Kicc")
        AppLogger.bac.debug("\tKseed: \(binToHexRep(Kseed))" )
        
        let smskg = SecureMessagingSessionKeyGenerator()
        let KSenc = try smskg.deriveKey(keySeed: Kseed, mode: .ENC_MODE)
        let KSmac = try smskg.deriveKey(keySeed: Kseed, mode: .MAC_MODE)

//        let KSenc = self.keyDerivation(kseed: Kseed,c: KENC)
//        let KSmac = self.keyDerivation(kseed: Kseed,c: KMAC)
        
        AppLogger.bac.debug("Calculate Session Keys (KSenc and KSmac) using Appendix 5.1")
        AppLogger.bac.debug("\tKSenc: \(binToHexRep(KSenc))" )
        AppLogger.bac.debug("\tKSmac: \(binToHexRep(KSmac))" )
        
        
        let ssc = [UInt8](self.rnd_icc.suffix(4) + self.rnd_ifd.suffix(4))
        AppLogger.bac.debug("Calculate Send Sequence Counter")
        AppLogger.bac.debug("\tSSC: \(binToHexRep(ssc))" )
        return (KSenc, KSmac, ssc)
    }
    
}
#endif
