//
//  PassportLib.swift
//  PassportLib
//
//  Created by Far-iz Lengha on 8/11/2567 BE.
//

import Foundation
import CryptoTokenKit
import CryptoKit
import CommonCrypto
import UIKit
import OSLog


public protocol PassportControllerDelegate{
    func onProgressReadPassportData(progress:Float)
    func onCompleteReadPassportData(data:PassportModel)
    func onBeginCardSession(isSuccess:Bool)
    func onErrorOccur(errorMessage:String,isError:Bool)
}

public class PassportController
{
    private var passport:NFCPassportModel = NFCPassportModel()
    var secureMessaging : SecureMessaging?
    private var bacHandler : BACHandler?
    private var currentlyReadingDataGroup : DataGroupId?
    private var caHandler : ChipAuthenticationHandler?
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true
    private var skipCA = false
    private var skipPACE = false
    private var mrzKey : String = ""
    var maxDataLengthToRead : Int = 0xA0  // Should be able to use 256 to read arbitrary amounts of data at full speed BUT this isn't supported across all passports so for reliability just use the smaller amount.

    
    enum FileID : String{
        case Common = "011E"
        case EFCardAccess = "011C"
        case EFATR = "2F01"
        case EFDIR = "2F00"
        case DG1 = "0101"
        case DG2 = "0102"
        case DG3 = "0103"
        case DG4 = "0104"
        case DG5 = "0105"
        case DG6 = "0106"
        case DG7 = "0107"
        case DG8 = "0108"
        case DG9 = "0109"
        case DG10 = "010A"
        case DG11 = "010B"
        case DG12 = "010C"
        case DG13 = "010D"
        case DG14 = "010E"
        case DG15 = "010F"
        case DG16 = "0110"
    }
    
    
    let DGTAG:[String:String] = [
        "60" : "COM",
        "61" : "DG1",
        "75" : "DG2",
        "63" : "DG3",
        "76" : "DG4",
        "65" : "DG5",
        "66" : "DG6",
        "67" : "DG7",
        "68" : "DG8",
        "69" : "DG9",
        "6A" : "DG10",
        "6B" : "DG11",
        "6C" : "DG12",
        "6D" : "DG13",
        "6E" : "DG14",
        "6F" : "DG15",
        "70" : "DG16",
        "77" : "SOD"
    ]
    
    
    // APDU Command
    let SELECTDFSTR:String = "00A4040007A0000002471001"
    let SELECTDFSTR2:String = "00A4040007A000000247100100"
    let GETCHALLENGESTR:String = "0084000008"
    
    // Properties
    let rmngr:ReaderController
    var isSmartCardInitialized:Bool?
    var isCardSessionBegin:Bool?
    let util:Utility?
    var data:PassportModel?
    
    var progress:Float = 0.0
    var eachProgress:Float = 0.0
    var slotName:String = ""
    var SSCP = ""
    var SKmac = ""
    var SKenc = ""
    let AlphabetArr:[Character:Int] = ["A":10,"B":11,"C":12,"D":13,"E":14,"F":15,"G":16,"H":17,"I":18,"J":19,"K":20,"L":21,"M":22,"N":23,"O":24,"P":25,"Q":26,"R":27,"S":28,"T":29,"U":30,"V":31,"W":32,"X":33,"Y":34,"Z":35]
    let weight:[Int] = [7,3,1]
    
    // Delegate properties
    public var delegate:PassportControllerDelegate?
    
    
    // Constructor
    public init(rmngr:ReaderController,isSmartCardInitialized:Bool){
        util = Utility()
        data = PassportModel()
        self.rmngr = rmngr
        self.isSmartCardInitialized = isSmartCardInitialized
    }
    
    // MARK: - HELPER FUNCTION
    func incrementSSCP(){
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
    }
    
    func sendAPDU(apdu:String,description:String) async -> String{
//        print("LIB >>>> (APDU CMD \(description) >>>> : " + apdu)
        let res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//        print("LIB <<<< (APDU RES \(description) <<<< : " + res.uppercased())
        return res
        
    }
    
    func handleError(description:String){
        print("LIB >>>> \(description)")
        delegate?.onErrorOccur(errorMessage: description,isError: true)
    }
    // MARK: - END OF HELPER HUNCTION
    
    //MARK: - BASIC ACCESS CONTROL
    func BasicAccessControl(mrz:String) async -> Bool {
        
//        print("""
//        
//        #####################################
//          BEGIN EXTERNAL AUTHENTICATION STEP 
//        #####################################
//        
//        """)
        
        // Step 1 : Hash MRZ Data with SHA1 Algorithm
        let mrzData = mrz.data(using: .utf8)
        let Kseed = util?.sha1HashData(data: mrzData!).prefix(32)
//        print("LIB >>>> Kseed : " + Kseed!)
        
        // Step 2 / 3 : Calculate Kenc and Kmac from Kseed and adjust Parity
        let Key1 = util?.CalculateKey(Kseed: String(Kseed!))
        let Kenc = Key1![0]
        let Kmac = Key1![1]
        
//        print("LIB >>>> Kenc : " + Kenc!)
//        print("LIB >>>> Kmac : " + Kmac!)
        
        // Step 4 : Initial SmartCard
        

        if isSmartCardInitialized! {
            isCardSessionBegin = await rmngr.beginCardSession()
            delegate?.onBeginCardSession(isSuccess: isCardSessionBegin!)
        }
        
        if isCardSessionBegin ?? false {
            
            // Step 5 : Transmit APDU for SELECT DF of Passport
            //print("LIB >>>> (APDU CMD SELECT DF) >>>> : " + SELECTDFSTR)
//            print("LIB >>>> (APDU CMD SELECT DF) >>>> ")
            var res = await rmngr.transmitCardAPDU(card:rmngr.card!,apdu: SELECTDFSTR2)
//            print("LIB <<<< (APDU RES SELECT DF) <<<< : " + res)
            
            
            if res == "nil" {
                
//                print("LIB >>>> SELECT PASSPORT DF UNSUCCESS \(res)")
                delegate?.onErrorOccur(errorMessage: "SELECT PASSPORT DF UNSUCCESS, RES : \(res.uppercased())", isError:true)
//                print("""
//                
//                #####################################
//                              THE END !!!
//                #####################################
//                
//                """)
                rmngr.endCardSession()
                return false
            }else{
                
                if res.suffix(2) == "6700" {
                    
                    // Step 5.1 : Transmit APDU for SELECT DF of Passport
                    //print("LIB >>>> (APDU CMD SELECT DF) >>>> : " + SELECTDFSTR)
//                    print("LIB >>>> (APDU CMD SELECT DF) >>>> ")
                    res = await rmngr.transmitCardAPDU(card:rmngr.card!,apdu: SELECTDFSTR)
//                    print("LIB <<<< (APDU RES SELECT DF) <<<< : " + res)
                    
                }
                
                // Step 6 : Transmit Get Challenge APDU
                //print("LIB >>>> (APDU CMD GET CHALLENGE) >>>> : " + GETCHALLENGESTR)
//                print("LIB >>>> (APDU CMD GET CHALLENGE) >>>> ")
                res = await rmngr.transmitCardAPDU(card:rmngr.card!,apdu: GETCHALLENGESTR)
//                print("LIB <<<< (APDU RES GET CHALLENGE) <<<< : " + res.uppercased())
                if res.count <= 4 {
//                    print("LIB >>>> GET CHALLENGE FROM CHIP UNSUCCESS, RES : \(res.uppercased())")
//                    print("""
//                    
//                    #####################################
//                                  THE END !!!
//                    #####################################
//                    
//                    """)
                    delegate?.onErrorOccur(errorMessage: "GET CHALLENGE FROM CHIP UNSUCCESS, RES : \(res.uppercased())",isError: true)
                    rmngr.endCardSession()
                    return false
                }
                let RNDIC = res.uppercased().dropLast(4)
                
                // Step 7 : Generate random 8 byte hex and 16 byte hex
                let Kifd = util?.RandomHex(numDigit: 32)
                let RNDIFD = util?.RandomHex(numDigit: 16)
                
                // Step 8 : Get S by concatenate RNDIFD + RNDIC + Kifd
                let S = RNDIFD! + RNDIC + Kifd!
//                print("LIB >>>> S : " + S)
                
                // Step 9 : Get Eifd by Encrypt S with Kenc by 3DES CBC Algorithm
                let Eifd = util?.TripleDesEncCBC(input: S, key: Kenc!)
//                print("LIB >>>> Eifd : " + Eifd!)
                
                // Step 10 : Get Mifd by Calculate Message Authentication Code Padding Method 2 over Eifd by Kmac
                let Mifd = util?.MessageAuthenticationCodeMethodTwo(input: Eifd!, key: Kmac!)
//                print("LIB MSG >>>> Mifd : " + Mifd!)
                
                // Step 11 : Construct APDU Cmd for do External Authentication Cmd = Eifd concatinate with Mifd
                let apdu = "0082000028" + Eifd! + Mifd! + "28"
                
                // Step 12 : Send APDU command
                //print("LIB >>>> (APDU CMD EXTERNAL AUTH) >>>> : " + apdu)
//                print("LIB >>>> (APDU CMD EXTERNAL AUTH) >>>> : ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//                print("LIB <<<< (APDU RES EXTERNAL AUTH) <<<< : " + res.uppercased())
                
                if res.count <= 4 {
//                    print("LIB >>>> EXTERNAL AUTHENTICATION UNSUCCESS")
//                    print("""
//                    
//                    #####################################
//                                  THE END !!!
//                    #####################################
//                    
//                    """)
                    delegate?.onErrorOccur(errorMessage: "EXTERNAL AUTHENTICATION UNSUCCESS",isError: true)
                    rmngr.endCardSession()
                    return false
                }
                // Step 13 : Get Eic by Cut Off Mic from response and decrypt Eic to get R
                let Eic = res.uppercased().dropLast(20)
//                print("LIB >>>> Eic : " + Eic)
                let R = util?.TripleDesDecCBC(input: String(Eic), key: Kenc!)
//                print("LIB >>>> R : " + R!)
          
                // Step 14 : Get Kic and SSC from R
                let Kic = R!.dropFirst(32)
//                print("LIB >>>> Kic : " + Kic)
                let a = R?.dropLast(32)
                let b = a!.dropLast(16)
                let c = a!.dropFirst(16)
                SSCP = String(b.dropFirst(8) + c.dropFirst(8))
//                print("LIB >>>> SSC : " + SSCP)
          
                // Step 15 : Calculate KSseed by XOR Kic with Kifd
                let SKseed = util?.XOR(Data1: String(Kic), Data2: Kifd!)
          
                // Step 16 : Calculate KSenc and KSmac from SKeed
                let SKey = util?.CalculateKey(Kseed: SKseed!)
                SKenc = SKey![0]!
                SKmac = SKey![1]!
//                print("LIB >>>> SKenc : " + SKenc)
//                print("LIB >>>> SKmac : " + SKmac)
//          
//                print("""
//                
//                #####################################
//                  END EXTERNAL AUTHENTICATION STEP
//                #####################################
//                
//                """)
                return true
                
            } // Select DF
            
        }else{
            delegate?.onErrorOccur(errorMessage: "BEGIN CARD SESSION FAIL && RFID NOT FOUND",isError: false)
//            print("LIB >>>> BEGIN CARD SESSION FAIL && RFID NOT FOUND")
            rmngr.endCardSession()
            return false
        } // Init Card Session
        
    }

    
    // MARK: - Utility Data Management
    
    func ConstructAPDUforSelectDF(DG:String,SKenc:String,SKmac:String,SSCP:String) -> String{
        let CmdHead = "0CA4020C80000000"
        let data = DG + "800000000000"
        let EncData = self.util?.TripleDesEncCBC(input: data, key: SKenc)
        let DO87 = "870901" + EncData!
        let M = CmdHead + DO87
        let N = SSCP + M + "8000000000"
        let CC = self.util?.MessageAuthenticationCodeMethodOne(input: N, key: SKmac)
        let DO8E = "8E08" + CC!
        return "0CA4020C15" + DO87 + DO8E + "00"
    }
    
    
    func VerifySelectRAPDU(APDU:String,SSC:String,Key:String)->Bool{
        let RAPDU = APDU.dropLast(4).uppercased()
        var DropIndex = 0
        if util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08") == -1 {
            DropIndex = RAPDU.count - (self.util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08"))!
        }else{
            DropIndex = RAPDU.count - (self.util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08"))!
        }
        var K = SSC + RAPDU.dropLast(DropIndex - 8) + "80"
        while(K.count % 16 != 0){
            K.append("00")
        }
        let CC = util?.MessageAuthenticationCodeMethodOne(input: K, key: Key)
        if util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08") == -1 {
            DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08"))!
        }else{
            DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08"))!
        }
        let DO8E = RAPDU.dropFirst(DropIndex+12)
        if CC! == DO8E {
            return true
        }else{
            return false
        }
    }
    
    func ConstructAPDUforReadBinary(HexBlock:String,HexOffset:String,HexLength:String,SSC:String,SKmac:String)->String{
        let CmdHeader = "0CB0\(HexBlock)\(HexOffset)80000000"
        let DO97 = "9701\(HexLength)"
        let M = CmdHeader + DO97
        let N = SSC + M + "8000000000"
        let CC = self.util?.MessageAuthenticationCodeMethodOne(input: N, key: SKmac)
        let DO8E = "8E08" + CC!
        let ProtectedAPDU = "0CB0\(HexBlock)\(HexOffset)0D" + DO97 + DO8E + "00"
        return ProtectedAPDU
    }
    
    func ConstructAPDUforReadBinaryExtend(HexBlock:String,HexOffset:String,HexLength:String,SSC:String,SKmac:String)->String{
        let CmdHeader = "0CB0\(HexBlock)\(HexOffset)80000000"
        let DO97 = "9702\(HexLength)"
        let M = CmdHeader + DO97
        let N = SSC + M + "80000000"
        let CC = self.util?.MessageAuthenticationCodeMethodOne(input: N, key: SKmac)
        let DO8E = "8E08" + CC!
        let ProtectedAPDU = "0CB0\(HexBlock)\(HexOffset)00000E" + DO97 + DO8E + "0000"
        return ProtectedAPDU
    }
    
    func VerifyReadBinaryRAPDU(APDU:String,SSC:String,Key:String)->Bool{
        let RAPDU = APDU.dropLast(4).uppercased()
        var DropIndex:Int = 0
        if util?.FindIndexOf(inputString: String(RAPDU), target: "99026A828E08") != -1 {
            return false
        }else{
            if util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08") == -1 {
                if util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08") == -1 {
                    if util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08") == -1 {
                        if util?.FindIndexOf(inputString: String(RAPDU), target: "990267008E08") == -1 {
                            return false
                        }else{
                            DropIndex = RAPDU.count - (util?.FindIndexOf(inputString: String(RAPDU), target: "990267008E08"))!
//                            print(DropIndex)
                        }
                    }else{
                        DropIndex = RAPDU.count - (util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08"))!
//                        print(DropIndex)
                    }
                }else{
                    DropIndex = RAPDU.count - (util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08"))!
//                    print(DropIndex)
                }
                
            }else{
                DropIndex = RAPDU.count - (util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08"))!
//                print(DropIndex)
            }
            
            var K = SSC + RAPDU.dropLast(DropIndex-8) + "80"
            while(K.count % 16 != 0){
                K.append("00")
            }
            let CC = self.util?.MessageAuthenticationCodeMethodOne(input: K, key: Key)
            if util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08") == -1 {
                if util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08") == -1 {
                    //
                    if util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08") == -1 {
                        if util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08") == -1 {
                            DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990267008E08"))!
//                            print(DropIndex)
                        }else{
                            DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08"))!
//                            print(DropIndex)
                        }
                    }else{
                        DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08"))!
//                        print(DropIndex)
                    }
                    
                }else{
                    DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08"))!
//                    print(DropIndex)
                }
            }else{
                DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08"))!
//                print(DropIndex)
            }
            let DO8E = RAPDU.dropFirst(DropIndex+12)
            if CC! == DO8E {
                return true
            }else{
                return false
            }
        }
        
    }
    
    func SplitDataWithTags(dg:String,Tag:String)->String{
        if dg.contains(Tag) {
            let r = dg.range(of:Tag)?.lowerBound
            let startingIndex = dg.distance(from: dg.startIndex, to: r!)
            var data2 = dg.dropFirst(startingIndex)
            if data2.contains(Tag) {
                data2 = data2.dropFirst(4)
                let r = data2.range(of:Tag)?.lowerBound
                let startingIndex = data2.distance(from: data2.startIndex, to: r!)
                let data3 = data2.dropFirst(startingIndex).dropFirst(4)
                let len = Int(data3.prefix(2),radix: 16)!*2
                let data4 = data3.dropFirst(2).prefix(len)
                return (util?.hexStringtoAscii(String(data4)))!
            }
        }
        return ""
    }
    

    
    func hexStringtoAscii(_ hexString : String) -> String {
        
        let pattern = "(0x)?([0-9a-f]{2})"
        let regex = try! NSRegularExpression(pattern: pattern, options: .caseInsensitive)
        let nsString = hexString as NSString
        let matches = regex.matches(in: hexString, options: [], range: NSMakeRange(0, nsString.length))
        let characters = matches.map {
            Character(UnicodeScalar(UInt32(nsString.substring(with: $0.range(at: 2)), radix: 16)!)!)
        }
        return String(characters)
    }
    
    func findIndexAfterPattern(in input: String) -> Int {
        let pattern = "87.*?01"
        
        // Create a regular expression
        if let regex = try? NSRegularExpression(pattern: pattern) {
            let range = NSRange(location: 0, length: input.utf16.count)
            
            // Check for the first match
            if let match = regex.firstMatch(in: input, options: [], range: range) {
                let endIndex = match.range.upperBound // Get the index after the pattern
                return endIndex
            }
        }
        
        return -1 // Return nil if no match is found
    }


    func getDataFromDO87(in input:String) -> String {
        
        let result = CalculateDO87(input)
//        print("LIB >>>> DO87 Data : \(result)")
        return result
        //return String(input.dropFirst(findIndexAfterPattern(in: input)))
    }
    
    
    
    func CalculateDO87(_ apdu:String)->String{
        var index = findIndexAfterPattern(in: apdu)
        // Check that len == data.len or not
        var expect_do87 = apdu.dropFirst(index)
        var expect_len = expect_do87.count/2
        var do87 = apdu.prefix(index).dropFirst(2).dropLast(2)
        if String(do87) == "" {
            do87 = apdu.prefix(index)
        }
        var do87_len = UInt32(do87,radix: 16)! - 1
        var do87_len_rt:UInt32 = 0
        if let d = UInt32(do87.dropFirst(2),radix: 16){
            do87_len_rt = d - 1
        }
        if do87_len == expect_len {
            return String(expect_do87)
        }else if do87_len_rt == expect_len {
            return String(expect_do87)
        }else{
            if index < 10 {
                index = index + 2
            }
            expect_do87 = apdu.dropFirst(index)
            expect_len = expect_do87.count/2
            do87 = apdu.prefix(index).dropFirst(2).dropLast(2)
            do87_len = UInt32(do87,radix: 16)! - 1
            if do87_len == expect_len {
                return String(expect_do87)
            }else{
                if index < 10 {
                    index = index + 2
                }
                expect_do87 = apdu.dropFirst(index)
                expect_len = expect_do87.count/2
                do87 = apdu.prefix(index).dropFirst(2).dropLast(2)
                do87_len = UInt32(do87,radix: 16)! - 1
                if do87_len == expect_len {
                    return String(expect_do87)
                }else{
                    expect_do87 = apdu.dropFirst(index)
                    expect_len = expect_do87.count/2
                    do87 = apdu.prefix(index).dropFirst(4).dropLast(2)
                    do87_len = UInt32(do87,radix: 16)! - 1
                    if do87_len == expect_len {
                        return String(expect_do87)
                    }else{
                        return ""
                    }
                }
            }
        }
    }
    
    func trimTrailing80(from hexString: String) -> String {
        var trimmedString = hexString
        
        // Loop to remove trailing "80", "8000", "800000", etc.
        while trimmedString.hasSuffix("00") || trimmedString.hasSuffix("80") {
            if trimmedString.hasSuffix("80") {
                trimmedString.removeLast(2) // Remove "80"
            }
            while trimmedString.hasSuffix("00") {
                trimmedString.removeLast(2) // Remove trailing "00"
            }
        }
        
        return trimmedString
    }
    
    // GET CHECK SUM FROM MRZ DATA
    func getChecksum(data:String)->String{
        var intarr:[Int] = []
        let chararr = Array(data)
        for char in chararr {
            if AlphabetArr[char] != nil {
                intarr.append(AlphabetArr[char]!)
            }else{
                intarr.append(Int(String(char))!)
            }
            
        }
        var i = 0
        for _ in intarr {
            intarr[i] *= weight[i%3]
            i += 1
        }
        let result = intarr.reduce(0,+)
        return String(result % 10)
    }
    
    // Append Document Number if length less than 9
    func appendDocNo(docNo:String)->String{
        var doc = docNo
        while doc.count < 9 {
            doc = doc + "<"
        }
        return doc
    }
    
    // MARK: - EF.COM
       func readCommon() async -> [String] {
           
//           print("""
//           
//           #####################################
//                   BEGIN READ EF.COM 
//           #####################################
//           
//           """)
           
           // Step 1 : Construct APDU CMD for SELECT COM
           SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
           var apdu = ConstructAPDUforSelectDF(DG: FileID.Common.rawValue, SKenc: SKenc, SKmac: SKmac, SSCP: SSCP)
//           print("LIB >>>> (APDU CMD SELECT EF.COM) >>>> : " + apdu)
//           print("LIB >>>> (APDU CMD SELECT EF.COM) >>>> ")
           var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//           print("LIB <<<< (APDU RES SELECT EF.COM) <<<< : " + res.uppercased())
           
           // Step 2 : Verify Res Apdu select common
           SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
           var verify = VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
           if verify
           {
               // Step 3 : Send APDU Read Binary for get length com data
               SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
               apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "FF", SSC: SSCP, SKmac: SKmac)
               //print("LIB >>>> (APDU CMD GET LEN DG1) >>>> : " + apdu)
//               print("LIB >>>> (APDU CMD GET LEN EF.COM) >>>> ")
               res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//               print("LIB <<<< (APDU RES GET LEN EF.COM) <<<< : " + res.uppercased())
               
               // Step 4 : Verify Res Apdu get com
               SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
               verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
               if verify {
                   // Step 5 : Get Len of DG1 from Response
                   let com = GetDataCOM(APDU:res, SKenc: SKenc)
//                   print("\n")
//                   print("DG List : ")
                   com.forEach { i in
                       print(DGTAG[i]!)
                   }
//                   print("\n")
//                   print("""
//                   
//                   #####################################
//                           END READ EF.COM 
//                   #####################################
//                   
//                   """)
                   
                   return com
               }else{
                   print("LIB >>>> COMPARE RES APDU READ EF.COM FAIL")
                   delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ EF.COM FAIL",isError: true)
                   return []
               } // verify res apdu read ef.com
               
           }else{
               print("LIB >>>> COMPARE RES APDU SELECT EF.COM FAIL")
               delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT EF.COM FAIL",isError: true)
               return []
           } // verify res apdu select ef.com
           
       }
       
       // MARK: - EF.COM DATA MANAGEMENT
       func GetDataCOM(APDU:String,SKenc:String)->[String]{
           //let result = APDU.dropFirst(6).uppercased()
           let result = getDataFromDO87(in: APDU).uppercased()
           var result2:Substring = ""
           if util?.FindIndexOf(inputString: String(result), target: "99029000") == -1 {
               result2 = result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99026282"))!)
           }else{
               result2 = result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99029000"))!)
           }
           let result3 = util?.TripleDesDecCBC(input: String(result2), key: SKenc)
           let result4 = trimTrailing80(from: result3!)
           let index = (util?.FindIndexOf(inputString: result4, target: "5F3606"))! + 22
           let result5 = result4.dropFirst(index)
           return splitTo2CharacterArray(from: String(result5))
       }
       
       func splitTo2CharacterArray(from hexString: String) -> [String] {
           var result: [String] = []
           for i in stride(from: 0, to: hexString.count, by: 2) {
               let index = hexString.index(hexString.startIndex, offsetBy: i)
               let substring = String(hexString[index..<hexString.index(index, offsetBy: 2)])
               result.append(substring)
           }
           return result
       }
    
    
    
   
    
    // MARK: - DATA GROUP 1
    func readDG1() async {

//        print("""
//        
//        #####################################
//              BEGIN READ DATA GROUP 1 
//        #####################################
//        
//        """)
        
        defer{
            
//            print("""
//            
//            #####################################
//                    END READ DATA GROUP 1
//            #####################################
//            
//            """)
            
        }
        
        
        // Step 1 : Consruct APDU Cmd for SELECT DG1
        incrementSSCP();
        var apdu = self.ConstructAPDUforSelectDF(DG:FileID.DG1.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        //print("LIB >>>> (APDU CMD SELECT DG1) >>>> : " + apdu)
        var res = await sendAPDU(apdu: apdu, description: "SELECT DG1")
        
        
        // Step 2 : Verify Res Apdu select DG1
        incrementSSCP()
        guard VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
            handleError(description: "COMPARE RES APDU SELECT DG1 FAIL")
            return
        }
        
        
        // Step 3 : Send APDU Read Binary for get length DG data
        incrementSSCP()
        apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "04", SSC: SSCP, SKmac: SKmac)
        res = await sendAPDU(apdu: apdu, description: "GET LEN DG1")
        
        // Step 4 : Verify Res Apdu get len DG1
        incrementSSCP()
        guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
            handleError(description: " COMPARE RES APDU GET LEN DG1 FAIL")
            return
        }
        
        // Step 5 : Get Len of DG1 from Response
        let len = CalculateLenDG1(APDU:res, SKenc: SKenc)
//        print("LIB >>>> DG1 LEN : " + len)
        
        
        // Step 6 : Construct APDU For Read DG1 Data
        incrementSSCP()
        apdu = self.ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "05", HexLength:len , SSC: SSCP, SKmac: SKmac)
        res = await sendAPDU(apdu: apdu, description: "READ DG1")

        
        // Step 7 : Verify RES APDU Read Data DG1
        incrementSSCP()
        guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
            handleError(description: "COMPARE RES APDU READ DG1 FAIL")
            return
        }
        
        
        // Step 8 : Seperate Data
        let data1 = GetDataDG1(APDU: res, SKenc: SKenc)
//        print("LIB >>>> DG1 : " + data1)
        data?.documentCode = String(data1.prefix(2))
        var data2 = data1.dropFirst(2)
        data?.issueState = Constant.getCountryFromCode(countryCode: String(data2.prefix(3)))
        data?.countryCode = String(data2.prefix(3))
        data2 = data2.dropFirst(3)
        data?.holderFullName = String(data2.prefix(31)).capitalized
        let fullName = String(data2.prefix(31))
//        print(data?.holderFullName ?? "None")
        let splitname = fullName.split(separator: "<", omittingEmptySubsequences: false)
//        print(splitname)
        data?.holderMiddleName = String((splitname[1])).capitalized
        data?.holderLastName = String((splitname[0])).capitalized
        if splitname[3] != "" {
            data?.holderFirstName = String(splitname[2] + " " + splitname[3]).capitalized
        }else{
            data?.holderFirstName = String((splitname[2])).capitalized
        }
        data2 = data2.dropFirst(39)
        data?.documentNumber = String(data2.prefix(9))
        data2 = data2.dropFirst(9)
        data?.docNumCheckDigit = String(data2.prefix(1))
        data2 = data2.dropFirst(1)
        data?.nationality = Constant.getNatiolityFromCode(countryCode: String(data2.prefix(3)))
        data2 = data2.dropFirst(3)
        //data?.dateOfBirth = String(data2.prefix(6))
        let birthDate = String(data2.prefix(6))
        data2 = data2.dropFirst(6)
        data?.dateOfBirthCheckDigit = String(data2.prefix(1))
        data2 = data2.dropFirst(1)
        data?.sex = String(data2.prefix(1))
        data2 = data2.dropFirst(1)
        //data?.dateOfExpiry = String(data2.prefix(6))
        let expireDate = String(data2.prefix(6))
        data2 = data2.dropFirst(6)
        data?.dateOfExpiryCheckDigit = String(data1.prefix(1))
        data2 = data2.dropFirst(1)
        data?.optionalData = String(data2.dropLast(3))
        
        // calculate date of birth reference from ICAO Standard
        /*
         If Birth Date > Current Year = 19
         If Birth Date <= Current  Yera = 20
         */
        let currentYear = Calendar(identifier: .gregorian).component(.year, from: Date())
        if Int(birthDate.prefix(2))! > (currentYear % 100) {
            data?.dateOfBirth = "19" + birthDate
        }else{
            data?.dateOfBirth = "20" + birthDate
        }
        
        // calculate date of expire reference from ICAO Standard
        if let d = data?.dateOfIssue,data?.dateOfIssue != "",let issueYear = Int(d.prefix(4).dropFirst(2)),let exYear = Int(expireDate.prefix(2)) {
            if abs(issueYear - exYear) <= 10  {
                data?.dateOfExpiry = "20" + expireDate
            }else{
                data?.dateOfExpiry = "19" + expireDate
            }
        }else{
            let exYear = Int(expireDate.prefix(2))
            if exYear! >= 40 {
                data?.dateOfExpiry = "19" + expireDate
            }else{
                data?.dateOfExpiry = "20" + expireDate
            }
        }
        
//        print("Date of expire : ")
//        print(data?.dateOfExpiry ?? "")
        
        let exp = util?.isExpired(expirationDate: (data?.dateOfExpiry)!,format: "yyyyMMdd")
        if exp! {
//            print("Document is expried")
            data?.expireFlag = "Y"
        }else{
//            print("Document is not expire")
            data?.expireFlag = "N"
        }
        
        
//        print("\n")
//        print("Data Group 1 Data : ")
//        print("Document Type : Passport" )
//        print("countyCode : \(data?.countryCode ?? "")")
//        print("Issue State : \(data?.issueState ?? "")")
//        print("Fullname : \(data?.holderFullName ?? "")")
//        print("Firstname : \(data?.holderFirstName ?? "")")
//        print("Middlename : \(data?.holderMiddleName ?? "")")
//        print("Lastname : \(data?.holderLastName ?? "")")
//        print("Document number : \(data?.documentNumber ?? "")")
//        print("Nationality : \(data?.nationality ?? "")")
//        print("Birth Date : \(data?.dateOfBirth ?? "")")
//        print("Expiry Date : \(data?.dateOfExpiry ?? "")")
//        print("Sex : \(data?.sex ?? "")")
//        print("Optional Data : \(data?.optionalData ?? "")")
//        print("\n")
        

    }
    
    // MARK: - DG1 DATA MANAGEMENT
    func CalculateLenDG1(APDU:String,SKenc:String)->String{
        var result = APDU.uppercased()
        result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99029000"))!))
        result = getDataFromDO87(in: result)
        result = String((util?.TripleDesDecCBC(input: String(result), key: SKenc).dropFirst(2))!)
        let index = result.count - (util?.FindIndexOf(inputString: String(result), target: "5F1F"))!
        let length = result.dropLast(index)
        return String(length)
    }
    
    func GetDataDG1(APDU:String,SKenc:String)->String{
        //let result = APDU.dropFirst(6).uppercased()
        let result = APDU.uppercased()
        var result2:Substring = ""
        if util?.FindIndexOf(inputString: String(result), target: "99029000") == -1 {
            result2 = result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99026282"))!)
        }else{
            result2 = result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99029000"))!)
        }
        var result3 = getDataFromDO87(in: String(result2))
        result3 = (util?.TripleDesDecCBC(input: String(result3), key: SKenc))!
        //print("LIB >>>> DG1 HEX : " + result3!.dropLast(16))
        let result4 = trimTrailing80(from: result3)
        return (util?.hexStringtoAscii(result4))!
    }
    
    // MARK: - DATA GROUP 2
    func readDG2() async {
        
//        print("""
//        
//        #####################################
//              BEGIN READ DATA GROUP 2 
//        #####################################
//        
//        """)
        
        defer{
            
//            print("""
//            
//            #####################################
//                   END READ DATA GROUP 2
//            #####################################
//            
//            """)
            
            
        }
        

        // Step 1 : Consruct APDU for SELECT DG2
        //SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        incrementSSCP()
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG2.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        var res = await sendAPDU(apdu: apdu, description: "SELECT DG2")
        
        // Step 2 : Verify RES APDU Select DG2
        incrementSSCP()
        guard VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
            handleError(description: "COMPARE RES APDU SELECT DG2 FAIL")
            return
        }
        
        
        // Step 3 : Send APDU Get Len DG2
        incrementSSCP()
        apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "30", SSC: SSCP, SKmac: SKmac)
        res = await sendAPDU(apdu: apdu, description: "GET LEN DG2")

        
        // Step 4 : Verify Res APDU Get Len DG2
        incrementSSCP()
        guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
            handleError(description: "COMPARE RES APDU GET LEN DG2 FAIL")
            return
        }
        
        
        let len = CalculateLenDG2(APDU:res, SKenc: SKenc)
//        print("LIB >>>> DG2 LEN : " + len[0])
//        print("LIB >>>> DG2 OFFSET : " + len[1])
        
        var reqLenHex:String = len[0]
        //var reqLenHex:String = "6700"
        
        // Step 5 : Get All Data DG2
        incrementSSCP()
        apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset: len[1], HexLength: reqLenHex, SSC: SSCP, SKmac: SKmac)
        res = await sendAPDU(apdu: apdu, description: "READ FULL LEN DG2")
        
        
        // Step 6 : Verify Res Apdu Read DG2
        incrementSSCP()
        guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
            handleError(description: "COMPARE RES APDU READ DG2 FAIL")
            return
        }
        
        var r:String = ""
        var rr:String = ""
        
        
        // MARK: - Old Chip Handle
        
        // Adding : Handle chip limit request data length.
        if res.uppercased().suffix(4) == "6700" {
            
            reqLenHex = "0400"
            incrementSSCP()
            apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset: len[1], HexLength: reqLenHex, SSC: SSCP, SKmac: SKmac)
            res = await sendAPDU(apdu: apdu, description: "READ DG2 WITH LEN 1024")
            
            incrementSSCP()
            guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
                handleError(description: "COMPARE RES APDU READ DG2 FAIL WITH 1024 KENGTH FAIL")
                data?.faceImage = ""
                return
            }
            
            
            if res.uppercased().suffix(4) == "6700" {
                
                reqLenHex = "0200"
                incrementSSCP()
                apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset: len[1], HexLength: reqLenHex, SSC: SSCP, SKmac: SKmac)
                res = await sendAPDU(apdu: apdu, description: "READ DG2 WITH LEN 512")

                
                incrementSSCP()
                guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
                    handleError(description: "COMPARE RES APDU READ DG2 FAIL WITH 512 KENGTH FAIL")
                    data?.faceImage = ""
                    return
                }
                
            }
        

        }
        
        // MARK: - Old Chip Handle End
        
        var arr = GetDataDG2(APDU: res, SKenc: SKenc)
        r = arr[0]
        rr = arr[1]
        let allLen = (UInt32(len[0],radix: 16)! * 2) - 100 //- 1000
//        print("LIB >>>> DG2 CHARACTER LEN : \(allLen)")
        
        guard r.count < allLen else {
            //let r2 = r.dropFirst(92)
            if util?.FindIndexOf(inputString: r, target: "0000000C6A502020") != -1 {
                
                let r2 = String(r.dropFirst((util?.FindIndexOf(inputString: r, target: "0000000C6A502020"))!))
                //let rr2 = rr.dropFirst(92)
                let rr2 = String(rr.dropFirst((util?.FindIndexOf(inputString: rr, target: "0000000C6A502020"))!))
                if let image = UIImage(data: String(r2).hexadecimal!){
//                    print("LIB >>>> FACE DATA WITH TEMPLATE (JP2000 FORMAT) : ")
//                    print(r)
//                    print("LIB >>>> FACE RAW (JP2000 FORMAT) : ")
//                    print(r2)
                    let djpg = image.jpegData(compressionQuality: 1.0)
                    data?.faceImage = djpg?.base64EncodedString()
                }else if let image = UIImage(data: String(rr2).hexadecimal!){
//                    print("LIB >>>> FACE DATA WITH TEMPLATE (JP2000 FORMAT) : ")
//                    print(r)
//                    print("LIB >>>> FACE RAW (JP2000 FORMAT) : ")
//                    print(r2)
                    let djpg = image.jpegData(compressionQuality: 1.0)
                    data?.faceImage = djpg?.base64EncodedString()
                }else{
                    data?.faceImage = ""
                }
                
            }else if util?.FindIndexOf(inputString: r, target: "FFD8FFE000104A464946") != -1 {
//                let r2 = r.dropFirst(74)
//                let rr2 = rr.dropFirst(74)
                let r2 = String(r.dropFirst((util?.FindIndexOf(inputString: r, target: "FFD8FFE000104A464946"))!))
                let rr2 = String(rr.dropFirst((util?.FindIndexOf(inputString: rr, target: "FFD8FFE000104A464946"))!))
                if let image = UIImage(data:String(r2).hexadecimal!){
//                    print("LIB >>>> FACE DATA WITH TEMPLATE(JFIF FORMAT) : ")
//                    print(r)
//                    print("LIB >>>> FACE RAW (JFIF FORMAT) : ")
//                    print(r2)
                    let djpg = image.jpegData(compressionQuality: 1.0)
                    data?.faceImage = djpg?.base64EncodedString()
                }else if let image = UIImage(data: String(rr2).hexadecimal!){
//                    print("LIB >>>> FACE DATA WITH TEMPLATE(JFIF FORMAT) : ")
//                    print(r)
//                    print("LIB >>>> FACE RAW (JFIF FORMAT) : ")
//                    print(r2)
                    let djpg = image.jpegData(compressionQuality: 1.0)
                    data?.faceImage = djpg?.base64EncodedString()
                }
                else{
                    data?.faceImage = ""
                }
            }else{
                data?.faceImage = ""
            }
            return
        }
        
//        print("LIB >>>> DG2 FOUND REMAIN")
        var re:String = ""
        var re2:String = ""
        
        // Step 7 : Get Remain Data DG2
        incrementSSCP()
        //apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset:"00", HexLength: "0384", SSC: SSCP, SKmac: SKmac)
        //print("LIB >>>> (APDU CMD READ DG2) >>>> : " + apdu)
        apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset:"00", HexLength: reqLenHex, SSC: SSCP, SKmac: SKmac)
        res = await sendAPDU(apdu: apdu, description: "READ REAMIN DG2")

        // Step 6 : Verify Res Apdu Read DG2
        incrementSSCP()
        guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
            handleError(description: "COMPARE RES APDU READ REMAIN DG2 FAIL")
            data?.faceImage = ""
            return
        }

        arr = GetRemainDataDG2(APDU: res, SKenc: SKenc)
        re.append(arr[0])
        re2.append(arr[1])
        
        // Loop for get all remain data
        while re.count < allLen {
            
            // Step 7 : Get Remain Data DG2
            let new = re.count/2
            var newOffset = String(new,radix: 16)
            while newOffset.count < 4 {
                newOffset = "0" + newOffset
            }
            incrementSSCP()
            apdu = ConstructAPDUforReadBinaryExtend(HexBlock: String(newOffset.dropLast(2)), HexOffset: String(newOffset.dropFirst(2)), HexLength: reqLenHex, SSC: SSCP, SKmac: SKmac)
            res = await sendAPDU(apdu: apdu, description: "READ REMAIN DG2")

            
            // Step 8 : Verify Res Apdu Read DG2
            incrementSSCP()
            guard VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac) else {
                handleError(description: "COMPARE RES APDU READ REMAIN DG2 FAIL")
                data?.faceImage = ""
                break
            }
            
            arr = GetRemainDataDG2(APDU: res, SKenc: SKenc)
            re.append(arr[0])
            re2.append(arr[1])

        }
        
        // JP2 = 170 = Format
        //var re1 = String(re.dropFirst(170))
        var re1 = ""
        if util?.FindIndexOf(inputString: re, target: "0000000C6A502020") != -1 {
            re1 = String(re.dropFirst((util?.FindIndexOf(inputString: re, target: "0000000C6A502020"))!))
            if let image = UIImage(data: re1.hexadecimal!) {
//                print("LIB >>>> FACE DATA WITH TEMPLATE (JP2000 FORMAT) : ")
//                print(re)
//                print("LIB >>>> FACE RAW (JP2000 FORMAT) : ")
//                print(re1)
                let djpg = image.jpegData(compressionQuality: 1.0)
                data?.faceImage = djpg?.base64EncodedString()
            }else{
                data?.faceImage = ""
            }
        }else if util?.FindIndexOf(inputString: re, target: "FFD8FFE000104A464946") != -1{
            
            // JFIF Format
            re1 = String(re.dropFirst((util?.FindIndexOf(inputString: re, target: "FFD8FFE000104A464946"))!))
//            print("LIB >>>> FACE DATA WITH TEMPLATE (JFIF FORMAT) : ")
//            print(re)
//            print("LIB >>>> FACE RAW (JFIF FORMAT) : ")
//            print(re1)
            
            // Function below is used for Drop trailing "FFFF"
            //let re2 = String(re1.dropLast(128))
            //print("Below is RE2")
            //print(re2)
            if let image = UIImage(data: re1.hexadecimal!){
                let djpg = image.jpegData(compressionQuality: 1.0)
                data?.faceImage = djpg?.base64EncodedString()
            }else{
                data?.faceImage = ""
            }
            
        }else{
            data?.faceImage = ""
        }
        

    }
    
    // MARK: - DG2 DATA MANAGEMENT
    func CalculateLenDG2(APDU:String,SKenc:String)->[String]{
        //var result = APDU.dropFirst(6)
        var result = APDU.uppercased()//getDataFromDO87(in: APDU).uppercased()
        result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990290008E08"))!))
        //print("result 1 : " + result)
        result = getDataFromDO87(in: result)
        let encResult = util?.TripleDesDecCBC(input: String(result), key: SKenc)
//        print("LIB >>>>  CALCULATE DG2 LEN ENC RESULT : " + encResult!)
        // Calculate length of header in biometric template
        let offsetIndex1 = util?.FindIndexOf(inputString: String(encResult!), target: "7F61")
        let offsetIndex2 = encResult!.count - offsetIndex1!
        let offsetValue1 = encResult!.dropLast(offsetIndex2).dropFirst(4)
        let diffValue = UInt32(offsetValue1,radix: 16)! + 4
        let diffValueStr = String(format:"%X",diffValue)
        var offsetIndex3 = util?.FindIndexOf(inputString: String(encResult!), target: "5F2E")
        if offsetIndex3 == -1 {
            offsetIndex3 = util?.FindIndexOf(inputString: String(encResult!), target: "7F2E")
        }
        var offsetValue2 = encResult!.dropFirst(offsetIndex3! + 6)
        offsetValue2 = offsetValue2.dropLast(offsetValue2.count - 4)
        let offsetValue = UInt64(diffValueStr,radix: 16)! - UInt64(offsetValue2,radix: 16)!
        let offset = String(format:"%X",offsetValue)
//        let offsetValue2Diff = UInt32(offsetValue2,radix: 16)! + 2
//        let len = String(format: "%X", offsetValue2Diff)
        let len = offsetValue2
        return [String(len),offset]
    }
    
    
    
    func GetDataDG2(APDU:String,SKenc:String)->[String]{
        //var result = APDU.dropFirst(10)//.dropFirst(10)
        var result = APDU.uppercased()//getDataFromDO87(in: APDU).uppercased()
        if util?.FindIndexOf(inputString: String(result), target: "99029000") == -1 {
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99026282"))!))
        }else{
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99029000"))!))
        }
        // Manual Cut DO87
        var result1 = getDataFromDO87(in: result)
        var fix = String(result.dropFirst(10))
        result1 = (util?.TripleDesDecCBC(input: String(result1), key: SKenc))!
        fix = (util?.TripleDesDecCBC(input: String(fix), key: SKenc))!
//        print("LIB >>>> GET DATA DG2 ENC : ")
//        print(result1)
        //.dropFirst(92)
        return [result1,fix]
    }
    
    func GetRemainDataDG2(APDU:String,SKenc:String)->[String]{
        //var result = APDU.dropFirst(10)
        var result = APDU.uppercased()//getDataFromDO87(in: APDU).uppercased()
        var result1:String
        var result2:String
        if util?.FindIndexOf(inputString: String(result), target: "990290008E") == -1 {
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990262828E"))!))
            var nofix = getDataFromDO87(in: result)
            var fix = String(result.dropFirst(10))
            nofix = String((util?.TripleDesDecCBC(input: String(nofix), key: SKenc).dropFirst(4))!)
            fix = String((util?.TripleDesDecCBC(input: String(fix), key: SKenc).dropFirst(4))!)
//            print("LIB >>>> DECRYPT BEFORE DROP : ")
//            print(nofix)
            //result = result.dropLast(10)
            //result1 = trimHexStringToLength(hexString: String(result), targetLength: 1796)
            result1 = trimTrailing80(from: String(nofix))
            result2 = trimTrailing80(from: String(fix))
//            print("LIB >>>> DECRYPT RESULT : ")
//            print(result1)
        }else{
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990290008E"))!))
            var nofix = getDataFromDO87(in: result)
            var fix = String(result.dropFirst(10))
            nofix = String((util?.TripleDesDecCBC(input: String(nofix), key: SKenc).dropFirst(4))!)
            fix = String((util?.TripleDesDecCBC(input: String(fix), key: SKenc).dropFirst(4))!)
//            print("LIB >>>> DECRYPT BEFORE DROP : ")
//            print(nofix)
            //result = result.dropLast(2)
            //result1 = trimHexStringToLength(hexString: String(result), targetLength: 1796)
            result1 = trimTrailing80(from: nofix)
            result2 = trimTrailing80(from: fix)
//            print("LIB >>>> DECRYPT RESULT : ")
//            print(result1)
        }
        return [result1,result2]
    }
    
    func trimHexStringToLength(hexString: String, targetLength: Int) -> String {

        if hexString.count <= targetLength {
            return hexString // คืนค่าถ้าความยาวไม่เกินเป้าหมาย
        }

        let trimmedString = String(hexString.prefix(targetLength))
        return trimmedString
    }
    
    // MARK: - Data Group 3
    
    // MARK: - Data Group 4
    
    // MARK: - Data Group 5
    
    // MARK: - Data Group 6
    
    // MARK: - Data Group 7
    func readDG7() async {
        
//        print("""
//        
//        #####################################
//              BEGIN READ DATA GROUP 7 
//        #####################################
//        
//        """)
        
        // MARK: - Step 1 : Consruct APDU for SELECT DG7
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG7.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
//        print("LIB >>>> (APDU CMD SELECT DG7) >>>> : " + apdu)
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//        print("LIB <<<< (APDU RES SELECT DG7) <<<< : " + res.uppercased())
        
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        if util?.FindIndexOf(inputString:res.uppercased(), target: "990290008E08") == -1 && util?.FindIndexOf(inputString: res, target: "990262828E08") == -1 {
            
//            print("LIB >>>> SELECT DG7 UNSUCCESS")
            
        }else{
            
            // MARK: - Step 2 : Verify Res Apdu select DG11
            
            var verify = VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                
                // MARK: - Step 3 : Send APDU Read Binary for get length DG data
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "FF", SSC: SSCP, SKmac: SKmac)
//                print("LIB >>>> (APDU CMD GET LEN DG7) >>>> : " + apdu)
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//                print("LIB <<<< (APDU RES GET LEN DG7) <<<< : " + res.uppercased())
                
                // MARK: - Step 4 : Verify Res Apdu get len DG11
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                if verify {
                    
                    // MARK: - Step 5 : Read DG11
                    let len = CalculateLenAndOffsetDG7(APDU:res, SKenc: SKenc)
//                    print("LIB >>>> DG7 CHARACTER LEN : " + len[0])
//                    print("LIB >>>> DG7 OFFSET LEN : " + len[1])
                    
                    // MARK: - Step 5 : Get All Data DG3
                    SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                    apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset: len[1], HexLength: len[0], SSC: SSCP, SKmac: SKmac)
//                    print("LIB >>>> (APDU CMD READ DG7) >>>> : " + apdu)
                    res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//                    print("LIB <<<< (APDU RES READ DG7) <<<< : " + res.uppercased())
                    
                    // MARK: - Step 6 : Verify Res Apdu Read DG3
                    SSCP = (util?.IncrementHex(Hex:SSCP, Increment: 1))!
                    verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                    if verify {
                        let r = GetDataDG7(APDU: res, SKenc: SKenc)
//                        print("LIB >>>> DG 7 : " + r.dropLast(6))
                        let res = r.dropLast(6)
                        let djpg = UIImage(data: String(res).hexadecimal!)!.jpegData(compressionQuality: 1.0)
                        data?.signatureImage = djpg!.base64EncodedString()
                        
                    }else{
//                        print("LIB >>>> COMPARE RES APDU READ DG7 FAIL")
                        delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG7 FAIL",isError: true)
                    } // end of verify res apdu read dg3
                    
                    
                }else{
//                    print("LIB >>>> COMPARE RES APDU READ DG7 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG7 FAIL",isError: true)
                } // end of verify read dg7
            }else{
//                print("LIB >>>> COMPARE RES APDU SELECT DG7 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG7 FAIL",isError: true)
            } // end of verify select dg7
            
        }
        
//        print("""
//        
//        #####################################
//              End READ DATA GROUP 7 
//        #####################################
//        
//        """)
        
    }
    
    // MARK: - DG7 DATA MANAGEMENT
    func CalculateLenAndOffsetDG7(APDU:String,SKenc:String)->[String]{
        
        // MARK: - Step 1 Decrypt APDU Response
        var result = APDU.dropFirst(8).uppercased()
        if util?.FindIndexOf(inputString: String(result), target: "990290008E08") == -1 {
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990262828E08"))!))
        }else{
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990290008E08"))!))
        }
        let encResult = String((util?.TripleDesDecCBC(input: String(result), key: SKenc).dropFirst(0))!)
        
        // MARK: - Step 2 Calculate Length of All Data
        let allLength = encResult.count
//        print("LIB >>>> DG7 CHARACTER LEN: " + String(allLength, radix: 10))
        
//        // MARK: - Step 3 Get Number of Biometric Record
//        let IndexOfnumOfInstance = (util?.FindIndexOf(inputString: String(encResult), target: "0201"))! + 6
//        let numOfInstance = encResult.prefix(IndexOfnumOfInstance).suffix(2)
//        print("Num of Instance: " + numOfInstance)
        
        // MARK: - Step 4 Calculate Length of Header
        let headerLength = (util?.FindIndexOf(inputString: String(encResult), target: "5F4382"))! + 10
        
        // MARK: - Step 5 Calculate Template Header Length
        let encResultNoHeader = encResult.dropFirst(headerLength)
        
        let bioDataLength = encResultNoHeader.prefix(4)
        let offset = headerLength/2
        let offsetHex = String(format: "%02X", offset)

        return [String(bioDataLength),offsetHex]
        
    }
    
    func GetDataDG7(APDU:String,SKenc:String)->String{
        var result = APDU.uppercased()
        if util?.FindIndexOf(inputString: String(result), target: "99026A82") == -1 {
            if util?.FindIndexOf(inputString: String(result), target: "99029000") == -1 {
                result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990262828E08"))!))
            }else{
                result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990290008E08"))!))
            }
            result = CalculateDO87(result)
            result = String((util?.TripleDesDecCBC(input: String(result), key: SKenc).dropFirst(0))!)
        
            return result
        }else{
            return ""
        }
        
    }
    
    // MARK: - Data Group 8
    
    // MARK: - Data Group 9
    
    // MARK: - Data Group 10
    
    // MARK: - Data Group 11
    func readDG11() async {
        
//        print("""
//        
//        #####################################
//              BEGIN READ DATA GROUP 11 
//        #####################################
//        
//        """)
        
        // Step 1 : Consruct APDU for SELECT DG11
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG11.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        //print("LIB >>>> (APDU CMD SELECT DG11) >>>> : " + apdu)
//        print("LIB >>>> (APDU CMD SELECT DG11) >>>> ")
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//        print("LIB <<<< (APDU RES SELECT DG11) <<<< : " + res.uppercased())
        
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        if util?.FindIndexOf(inputString:res.uppercased(), target: "990290008E08") == -1 && util?.FindIndexOf(inputString: res, target: "990262828E08") == -1 {
            
//            print("LIB >>>> SELECT DG11 UNSUCCESS")
            
        }else{
            
            // Step 2 : COMPARE Res Apdu select DG11
            
            var verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                
                // Step 3 : Send APDU Read Binary for get length DG data
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "00", SSC: SSCP, SKmac: SKmac)
                //print("LIB >>>> (APDU CMD GET LEN DG11) >>>> : " + apdu)
//                print("LIB >>>> (APDU CMD GET DG11) >>>> ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//                print("LIB <<<< (APDU RES GET DG11) <<<< : " + res.uppercased())
                
                // Step 4 : Verify Res Apdu get len DG11
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                if verify {
                    
                    if res.uppercased().suffix(2) == "6A82" {
                        
                        data?.personalNumber = ""
                        data?.fullDateOfBirth = ""
                        data?.placeOfBirth = ""
                        data?.permanentAddress = ""
                        data?.telephone = ""
                        data?.profession = ""
                        data?.title = ""
                        data?.personelSummary = ""
                        
//                        print("LIB >>>> DG11 NOT FOUND")
                        
                    }else{
                        
                        // Step 5 : Read DG11
                        let dg11 = GetDataDG11(APDU:res, SKenc: SKenc)
//                        print("LIB >>>> DG11 : " + dg11)
                        
                        // Step 6 : Loop for each data
                        data?.personalNumber = SplitDataWithTags(dg: dg11, Tag: "5F10")
                        data?.fullDateOfBirth = SplitDataWithTags(dg: dg11, Tag: "5F2B")
                        data?.placeOfBirth = SplitDataWithTags(dg: dg11, Tag: "5F11").replacingOccurrences(of: "<", with: " ").capitalized
                        data?.permanentAddress = SplitDataWithTags(dg: dg11, Tag: "5F42").replacingOccurrences(of: "<", with: " ").capitalized
                        data?.telephone = SplitDataWithTags(dg: dg11, Tag: "5F12")
                        data?.profession = SplitDataWithTags(dg: dg11, Tag: "5F13")
                        data?.title = SplitDataWithTags(dg: dg11, Tag: "5F14").capitalized
                        data?.personelSummary = SplitDataWithTags(dg: dg11, Tag: "5F15")
//                        
//                        print("\n")
//                        print("Data Group 11 Data : ")
//                        print("Personal Number : \(data?.personalNumber ?? "")")
//                        print("Full Birth Date : \(data?.fullDateOfBirth ?? "")")
//                        print("Place of birth : \(data?.placeOfBirth ?? "")")
//                        print("Permanent Address : \(data?.permanentAddress ?? "")")
//                        print("Telephone : \(data?.telephone ?? "")")
//                        print("Title : \(data?.title ?? "")")
//                        print("\n")
                        
                        if data?.expireFlag == "Y" {
//                            print("Document is expried")
                        }else{
//                            print("Document is not expire")
                        }
                        
                    } // DG11 NOT FOUND
        
                    
                }else{
//                    print("LIB >>>> COMPARE RES APDU READ DG11 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG11 FAIL",isError: true)
                } // end of verify read dg11
            }else{
//                print("LIB >>>> COMPARE RES APDU SELECT DG11 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG11 FAIL",isError: true)
            } // end of verify select dg11
            
        }
        
        
//        print("""
//        
//        #####################################
//              End READ DATA GROUP 11 
//        #####################################
//        
//        """)
        
    }
    
    // MARK: - DG11 DATA MANAGEMENT
    
    func GetDataDG11(APDU:String,SKenc:String)->String{
        //var result = APDU.dropFirst(6)
        //var result = APDU.dropFirst(8)
        var result = APDU.uppercased()//getDataFromDO87(in: APDU).uppercased()
        if util?.FindIndexOf(inputString: String(result), target: "99029000") == -1 {
            if util?.FindIndexOf(inputString: String(result), target: "99026282") == -1 {
                result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99027001"))!))
            }else{
                result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99026282"))!))
            }
        }
        else{
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99029000"))!))
        }
        result = getDataFromDO87(in: result)
        result = String((util?.TripleDesDecCBC(input: String(result), key: SKenc).dropFirst(0))!)
    
        return String(result)
    }
    
    // MARK: - DATA GROUP 12
    func readDG12() async {
        
//        print("""
//        
//        #####################################
//              BEGIN READ DATA GROUP 12 
//        #####################################
//        
//        """)
        
        defer{
            
//            print("""
//            
//            #####################################
//                  End READ DATA GROUP 12
//            #####################################
//            
//            """)
            
        }
        
        // Step 1 : Consruct APDU for SELECT DG11
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG12.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        //print("LIB >>>> (APDU CMD SELECT DG11) >>>> : " + apdu)
//        print("LIB >>>> (APDU CMD SELECT DG12) >>>> ")
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//        print("LIB <<<< (APDU RES SELECT DG12) <<<< : " + res.uppercased())
        
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        if util?.FindIndexOf(inputString:res.uppercased(), target: "990290008E08") == -1 && util?.FindIndexOf(inputString: res, target: "990262828E08") == -1 {
            
//            print("LIB >>>> SELECT DG12 UNSUCCESS")
            
        }else{
            
            // Step 2 : COMPARE Res Apdu select DG12
            
            var verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                
                // Step 3 : Send APDU Read Binary for get length DG data
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "00", SSC: SSCP, SKmac: SKmac)
                //print("LIB >>>> (APDU CMD GET LEN DG11) >>>> : " + apdu)
//                print("LIB >>>> (APDU CMD GET DG12) >>>> ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
//                print("LIB <<<< (APDU RES GET DG12) <<<< : " + res.uppercased())
                
                // Step 4 : Verify Res Apdu get len DG11
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                if verify {
                    
                    if res.uppercased().suffix(2) == "6A82" {
                        
                        data?.personalNumber = ""
                        data?.fullDateOfBirth = ""
                        data?.placeOfBirth = ""
                        data?.permanentAddress = ""
                        data?.telephone = ""
                        data?.profession = ""
                        data?.title = ""
                        data?.personelSummary = ""
                        
//                        print("LIB >>>> DG12 NOT FOUND")
                        
                    }else{
                        
                        // Step 5 : Read DG12
                        let dg12 = GetDataDG12(APDU:res, SKenc: SKenc)
//                        print("LIB >>>> DG12 : " + dg12)
                        
                        // Step 6 : Loop for each data
                        data?.issuingAuthority = SplitDataWithTags(dg: dg12, Tag: "5F19")
                        data?.dateOfIssue = SplitDataWithTags(dg: dg12, Tag: "5F26")
                        data?.endorsements = SplitDataWithTags(dg: dg12, Tag: "5F1B")
                        data?.imageOfFrontDoc = SplitDataWithTags(dg: dg12, Tag: "5F1D")
                        data?.imageOfRearDoc = SplitDataWithTags(dg: dg12, Tag: "5F1E")
                        data?.dateTimeDocPersonalization = SplitDataWithTags(dg: dg12, Tag: "5F55")
                        data?.serialNumberDocPersonalizationSystem = SplitDataWithTags(dg: dg12, Tag: "5F56")
                        
//                        print("\n")
//                        print("Data Group 12 Data : ")
//                        print("Issuing Authority : " + (data?.issuingAuthority)!)
//                        print("Date of Issue : " + (data?.dateOfIssue)!)
//                        print("Endorsements : " + (data?.endorsements)!)
//                        print("Image Of Rear : " + ((data?.imageOfFrontDoc)!))
//                        print("Date and time of document personalized : " + (data?.dateTimeDocPersonalization)!)
//                        print("Serial Number of Personalization System : " + (data?.serialNumberDocPersonalizationSystem)!)
//                        print("\n")
                        
                    } // DG11 NOT FOUND
        
                    
                }else{
//                    print("LIB >>>> COMPARE RES APDU READ DG11 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG11 FAIL",isError: true)
                } // end of verify read dg11
            }else{
//                print("LIB >>>> COMPARE RES APDU SELECT DG11 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG11 FAIL",isError: true)
            } // end of verify select dg11
            
        }
        
        
    }
    
    // MARK: - DG12 DATA MANAGEMENT
    
    func GetDataDG12(APDU:String,SKenc:String)->String{
        //var result = APDU.dropFirst(6)
        //var result = APDU.dropFirst(8)
        //var result = getDataFromDO87(in: APDU).uppercased()
        var result:String = APDU.uppercased()
        if util?.FindIndexOf(inputString: String(result), target: "99029000") == -1 {
            if util?.FindIndexOf(inputString: String(result), target: "99026282") == -1 {
                result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99027001"))!))
            }else{
                result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99026282"))!))
            }
        }
        else{
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "99029000"))!))
        }
//        print("Before get data from DO87")
//        print(result)
        result = getDataFromDO87(in: result).uppercased()
//        print("After get data from DO87")
//        print(result)
        result = String((util?.TripleDesDecCBC(input: String(result), key: SKenc).dropFirst(0))!)
    
        return String(result)
    }
    

    
    // MARK: - START READ RFID
    public func AutoReadRFIDData(documentNo:String,dob:String,doe:String) {
        
        
        //let docnum = documentNo + getChecksum(data: documentNo)
        let docnum = appendDocNo(docNo:documentNo) + getChecksum(data: documentNo)
        let birth = dob + getChecksum(data: dob)
        let exp = doe + getChecksum(data: doe)
        let mrz = docnum.trimmingCharacters(in: .whitespacesAndNewlines) + birth.trimmingCharacters(in: .whitespacesAndNewlines) + exp.trimmingCharacters(in: .whitespacesAndNewlines)
        print(mrz)
        
        
        Task.init{
            
            let isSuccess = await BasicAccessControl(mrz: mrz)
            progress += eachProgress
            delegate?.onProgressReadPassportData(progress: progress)
            
            if isSuccess {
                
                let DGTAG:[String] = await readCommon()
                progress += eachProgress
                delegate?.onProgressReadPassportData(progress: progress)
                
                // Plus for external authen
                eachProgress += 1.0
                
                
                if DGTAG.contains("61") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("75") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("63") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("76") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("65") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("66") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("67") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("68") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("69") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("6A") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("6B") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("6C") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("6D") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("6E") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("6F") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("70") {
                    eachProgress += 1.0
                }
                
                if DGTAG.contains("77") {
                    eachProgress += 1.0
                }
                
                eachProgress = 1.0 / eachProgress
                
                if DGTAG.contains("6C") {
                    print("LIB >>>> CHIP SUPPORT DG12")
                    await readDG12()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG12")
                }
                
                if DGTAG.contains("61") {
                    print("LIB >>>> CHIP SUPPORT DG1")
                    await readDG1()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG1")
                }
                
                if DGTAG.contains("75") {
                    print("LIB >>>> CHIP SUPPORT DG2")
                    await readDG2()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG2")
                }
                
                
                if DGTAG.contains("63") {
                    print("LIB >>>> CHIP SUPPORT DG3")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG3")
                }
                
                if DGTAG.contains("76") {
                    print("LIB >>>> CHIP SUPPORT DG4")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG4")
                }
                
                if DGTAG.contains("65") {
                    print("LIB >>>> CHIP SUPPORT DG5")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG5")
                }
                
                if DGTAG.contains("66") {
                    print("LIB >>>> CHIP SUPPORT DG6")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG6")
                }
                
                if DGTAG.contains("67") {
                    print("LIB >>>> CHIP SUPPORT DG7")
                    await readDG7()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG7")
                }
                
                if DGTAG.contains("68") {
                    print("LIB >>>> CHIP SUPPORT DG8")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG8")
                }
                
                if DGTAG.contains("69") {
                    print("LIB >>>> CHIP SUPPORT DG9")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG9")
                }
                
                if DGTAG.contains("6A") {
                    print("LIB >>>> CHIP SUPPORT DG10")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG10")
                }
                
                if DGTAG.contains("6B") {
                    print("LIB >>>> CHIP SUPPORT DG11")
                    await readDG11()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG11")
                }
                
                
                if DGTAG.contains("6D") {
                    print("LIB >>>> CHIP SUPPORT DG13")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG13")
                }
                
                if DGTAG.contains("6E") {
                    print("LIB >>>> CHIP SUPPORT DG14")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG14")
                }
                
                if DGTAG.contains("6F") {
                    print("LIB >>>> CHIP SUPPORT DG15")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG15")
                }
                
                if DGTAG.contains("70") {
                    print("LIB >>>> CHIP SUPPORT DG16")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT DG16")
                }
                
                if DGTAG.contains("77") {
                    print("LIB >>>> CHIP SUPPORT SOD")
                }else{
                    print("LIB >>>> CHIP NOT SUPPORT SOD")
                }
                
                
                delegate?.onCompleteReadPassportData(data: data!)
               
            }

            rmngr.endCardSession()
        }
        
    }
    
    public func ReadRFIDData(documentNo:String,dob:String,doe:String,dg1:Bool,dg2:Bool,dg11:Bool) {
        
        
        //let docnum = documentNo + getChecksum(data: documentNo)
        let docnum = appendDocNo(docNo:documentNo) + getChecksum(data: documentNo)
        let birth = dob + getChecksum(data: dob)
        let exp = doe + getChecksum(data: doe)
        mrzKey = docnum.trimmingCharacters(in: .whitespacesAndNewlines) + birth.trimmingCharacters(in: .whitespacesAndNewlines) + exp.trimmingCharacters(in: .whitespacesAndNewlines)
        
        
        // Plus for external authen
        eachProgress += 2.0
        
        if dg1 {
            eachProgress += 1.0
        }
        
        if dg2 {
            eachProgress += 1.0
        }
        
        if dg11 {
            eachProgress += 1.0
        }
        
        
        eachProgress = 1.0 / eachProgress
        
        Task.init{
            
            // Check that support for PACE or not
            do{
                
                if isSmartCardInitialized! {
                    isCardSessionBegin = await rmngr.beginCardSession()
                    delegate?.onBeginCardSession(isSuccess: isCardSessionBegin!)
                }
                
                if isCardSessionBegin ??  false {
                    
                    let data = try await readCardAccess()
                    Logger.passportController.debug( "Read CardAccess - data \(binToHexRep(data))" )
                    let cardAccess = try CardAccess(data)
                    passport.cardAccess = cardAccess
                    
                    Logger.passportController.info( "Starting Password Authenticated Connection Establishment (PACE)" )
                    
                    let paceHandler = try PACEHandler( cardAccess: cardAccess, pc: self )
                    
                    try await paceHandler.doPACE(mrzKey: mrzKey )
                    passport.PACEStatus = .success
                    Logger.passportReader.debug( "PACE Succeeded" )
                    
                    _ = try await selectPassportApplication()
                    
                }else{
                    delegate?.onErrorOccur(errorMessage: "Card Session not started", isError: true)
                }
                
                if passport.PACEStatus != .success {
                    do{
                        try await doBACAuthentication(mrz: mrzKey )
                    }catch{
                        delegate?.onErrorOccur(errorMessage: "\(error)", isError: true)
                    }
                }
                
                try await readDataGroups()
                
//                try await doActiveAuthenticationIfNeccessary(tagReader : tagReader)
//
//                self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
//                self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true


                // If we have a masterlist url set then use that and verify the passport now
//                self.passport.verifyPassport(masterListURL: self.masterListURL, useCMSVerification: self.passiveAuthenticationUsesOpenSSL)

//                return self.passport
                
                Logger.passportController.debug("\(self.passport.documentNumber)")
                
                
                
            }catch{
                // PACE Failed
                delegate?.onErrorOccur(errorMessage: "\(error)", isError: true)
            }
            
//            let isSuccess = await BasicAccessControl(mrz: mrz)
//            progress += eachProgress
//            delegate?.onProgressReadPassportData(progress: progress)
//            
//            if isSuccess {
//                
//                // in case of checking full year with issue date of document
//                
//                await readDG12()
//                progress += eachProgress
//                delegate?.onProgressReadPassportData(progress: progress)
//                
//                
//                if dg1 {
//                    await readDG1()
//                    progress += eachProgress
//                    delegate?.onProgressReadPassportData(progress: progress)
//                }
//                
//                if dg2 {
//                    await readDG2()
//                    progress += eachProgress
//                    delegate?.onProgressReadPassportData(progress: progress)
//                }
//                
//                if dg11 {
//                    await readDG11()
//                    progress += eachProgress
//                    delegate?.onProgressReadPassportData(progress: progress)
//                }
//                
//                
//                delegate?.onCompleteReadPassportData(data: data!)
//               
//            }

            rmngr.endCardSession()
        }
        
    }
}


extension PassportController{
    
    func readCardAccess() async throws -> [UInt8]{
        // Info provided by @smulu
        // By default NFCISO7816Tag requirers a list of ISO/IEC 7816 applets (AIDs). Upon discovery of NFC tag the first found applet from this list is automatically selected (and you have no way of changing this).
        // This is a problem for PACE protocol becaues it requires reading parameters from file EF.CardAccess which lies outside of eMRTD applet (AID: A0000002471001) in the master file.
        
        // Now, the ICAO 9303 standard does specify command for selecting master file by sending SELECT APDU with P1=0x00, P2=0x0C and empty data field (see part 10 page 8). But after some testing I found out this command doesn't work on some passports (European passports) and although receiving success (sw=9000) from passport the master file is not selected.
        
        // After a bit of researching standard ISO/IEC 7816 I found there is an alternative SELECT command for selecting master file. The command doesn't differ much from the command specified in ICAO 9303 doc with only difference that data field is set to: 0x3F00. See section 6.11.3 of ISO/IEC 7816-4.
        // By executing above SELECT command (with data=0x3F00) master file should be selected and you should be able to read EF.CardAccess from passport.
        
        // First select master file
        
        
        let cmd : APDUCommand = APDUCommand(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x00, p2Parameter: 0x0C, data: Data([0x3f,0x00]), expectedResponseLength: -1)
        
        _ = try await send( cmd: cmd)
            
        // Now read EC.CardAccess
        let data = try await self.selectFileAndRead(tag: [0x01,0x1C])
        return data
    }
    
    func send( cmd: APDUCommand, useExtendedMode : Bool = false ) async throws -> ResponseAPDU {
        Logger.passportController.debug("TagReader - sending \(cmd)" )
        var toSend = cmd
        if let sm = secureMessaging {
            toSend = try sm.protect(apdu:cmd, useExtendedMode: useExtendedMode)
            Logger.passportController.debug("TagReader - [SM] \(toSend)" )
        }
        
//        var (data, sw1, sw2) = try await tag.sendCommand(apdu: toSend)
        var (data,sw1,sw2) = try await rmngr.transmitCardAPDUTuple(card: rmngr.card!, apdu: toSend)
        Logger.passportController.debug( "TagReader - Received response, size \(data.count)b" )

        // Some commands may have bigger response than expected. Read the whole response using INS 0xC0 (GET RESPONSE).
        while (sw1 == 0x61) {
            let getResponseCmd = APDUCommand(instructionClass: 0x0, instructionCode: 0xC0, p1Parameter: 0x0, p2Parameter: 0x0, data: Data(), expectedResponseLength: Int(sw2))
            let nextSegment: Data
            // Overwrite sw1 and sw2.
            (nextSegment, sw1, sw2) = try await rmngr.transmitCardAPDUTuple(card: rmngr.card!, apdu: getResponseCmd)
            Logger.passportController.debug("Read remaining data. Accumulated: \(data.count + nextSegment.count)b. Last batch \(nextSegment.count)b. Still remaining: \(sw2)b")
            data += nextSegment
        }

        var rep = ResponseAPDU(data: [UInt8](data), sw1: sw1, sw2: sw2)
        
        if let sm = self.secureMessaging {
            rep = try sm.unprotect(rapdu:rep)
            Logger.passportController.debug("\(String(format:"TagReader [SM - unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2))" )
        } else {
            Logger.passportController.debug("\(String(format:"TagReader [unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2))" )
            
        }
        
        if rep.sw1 != 0x90 && rep.sw2 != 0x00 {
            Logger.passportController.error( "Error reading tag: sw1 - 0x\(binToHexRep(sw1)), sw2 - 0x\(binToHexRep(sw2))" )
            let tagError: NFCPassportReaderError
            if (rep.sw1 == 0x63 && rep.sw2 == 0x00) {
                tagError = NFCPassportReaderError.InvalidMRZKey
            } else {
                let errorMsg = self.decodeError(sw1: rep.sw1, sw2: rep.sw2)
                Logger.passportController.error( "reason: \(errorMsg)" )
                tagError = NFCPassportReaderError.ResponseError( errorMsg, sw1, sw2 )
            }
            throw tagError
        }

        return rep
    }
    
    
    func selectFileAndRead( tag: [UInt8]) async throws -> [UInt8] {
        var resp = try await selectFile(tag: tag )
            
        // Read first 4 bytes of header to see how big the data structure is
//        guard let readHeaderCmd = APDUCommand(bytes:[0x00, 0xB0, 0x00, 0x00, 0x00, 0x00,0x04]) else {
//            throw NFCPassportReaderError.UnexpectedError
//        }
        let readHeaderCmd = APDUCommand(instructionClass: 0x00, instructionCode: 0xB0, p1Parameter: 0x00, p2Parameter: 0x00,data: Data([0x00]),expectedResponseLength: 0x0004);
        resp = try await self.send( cmd: readHeaderCmd )

        // Header looks like:  <tag><length of data><nextTag> e.g.60145F01 -
        // the total length is the 2nd value plus the two header 2 bytes
        // We've read 4 bytes so we now need to read the remaining bytes from offset 4
        let (len, o) = try! asn1Length([UInt8](resp.data[1..<4]))
        var remaining = Int(len)
        var amountRead = o + 1
        
        var data = [UInt8](resp.data[..<amountRead])
        
        Logger.tagReader.debug( "TagReader - Number of data bytes to read - \(remaining)" )
        
        var readAmount : Int = maxDataLengthToRead
        while remaining > 0 {
            if maxDataLengthToRead != 256 && remaining < maxDataLengthToRead {
                readAmount = remaining
            }

//            self.progress?( Int(Float(amountRead) / Float(remaining+amountRead ) * 100))
            let offset = intToBin(amountRead, pad:4)

            Logger.tagReader.debug( "TagReader - data bytes remaining: \(remaining), will read : \(readAmount)" )
            let cmd = APDUCommand(
                instructionClass: 00,
                instructionCode: 0xB0,
                p1Parameter: offset[0],
                p2Parameter: offset[1],
                data: Data(),
                expectedResponseLength: readAmount
            )
            resp = try await self.send( cmd: cmd )

            Logger.tagReader.debug( "TagReader - got resp - \(binToHexRep(resp.data, asArray: true)), sw1 : \(resp.sw1), sw2 : \(resp.sw2)" )
            data += resp.data
            
            remaining -= resp.data.count
            amountRead += resp.data.count
            Logger.tagReader.debug( "TagReader - Amount of data left to read - \(remaining)" )
        }
        
        return data
    }
    
    func selectFile( tag: [UInt8] ) async throws -> ResponseAPDU {
        
        let data : [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02] + tag
        let cmd = APDUCommand(bytes:data)!
        
        return try await send( cmd: cmd )
    }
    
    private func decodeError( sw1: UInt8, sw2:UInt8 ) -> String {

        let errors : [UInt8 : [UInt8:String]] = [
            0x62: [0x00:"No information given",
                   0x81:"Part of returned data may be corrupted",
                   0x82:"End of file/record reached before reading Le bytes",
                   0x83:"Selected file invalidated",
                   0x84:"FCI not formatted according to ISO7816-4 section 5.1.5"],
            
            0x63: [0x81:"File filled up by the last write",
                   0x82:"Card Key not supported",
                   0x83:"Reader Key not supported",
                   0x84:"Plain transmission not supported",
                   0x85:"Secured Transmission not supported",
                   0x86:"Volatile memory not available",
                   0x87:"Non Volatile memory not available",
                   0x88:"Key number not valid",
                   0x89:"Key length is not correct",
                   0xC:"Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)"],
            0x65: [0x00:"No information given",
                   0x81:"Memory failure"],
            0x67: [0x00:"Wrong length"],
            0x68: [0x00:"No information given",
                   0x81:"Logical channel not supported",
                   0x82:"Secure messaging not supported",
                   0x83:"Last command of the chain expected",
                   0x84:"Command chaining not supported"],
            0x69: [0x00:"No information given",
                   0x81:"Command incompatible with file structure",
                   0x82:"Security status not satisfied",
                   0x83:"Authentication method blocked",
                   0x84:"Referenced data invalidated",
                   0x85:"Conditions of use not satisfied",
                   0x86:"Command not allowed (no current EF)",
                   0x87:"Expected SM data objects missing",
                   0x88:"SM data objects incorrect"],
            0x6A: [0x00:"No information given",
                   0x80:"Incorrect parameters in the data field",
                   0x81:"Function not supported",
                   0x82:"File not found",
                   0x83:"Record not found",
                   0x84:"Not enough memory space in the file",
                   0x85:"Lc inconsistent with TLV structure",
                   0x86:"Incorrect parameters P1-P2",
                   0x87:"Lc inconsistent with P1-P2",
                   0x88:"Referenced data not found"],
            0x6B: [0x00:"Wrong parameter(s) P1-P2]"],
            0x6D: [0x00:"Instruction code not supported or invalid"],
            0x6E: [0x00:"Class not supported"],
            0x6F: [0x00:"No precise diagnosis"],
            0x90: [0x00:"Success"] //No further qualification
        ]
        
        // Special cases - where sw2 isn't an error but contains a value
        if sw1 == 0x61 {
            return "SW2 indicates the number of response bytes still available - (\(sw2) bytes still available)"
        } else if sw1 == 0x64 {
            return "State of non-volatile memory unchanged (SW2=00, other values are RFU)"
        } else if sw1 == 0x6C {
            return "Wrong length Le: SW2 indicates the exact length - (exact length :\(sw2))"
        }

        if let dict = errors[sw1], let errorMsg = dict[sw2] {
            return errorMsg
        }
        
        return "Unknown error - sw1: 0x\(binToHexRep(sw1)), sw2 - 0x\(binToHexRep(sw2)) "
    }
    
    func sendMSESetATMutualAuth( oid: String, keyType: UInt8 ) async throws -> ResponseAPDU {
        
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        let keyTypeBytes = wrapDO( b: 0x83, arr:[keyType])
        
        let data = oidBytes + keyTypeBytes
            
        let cmd = APDUCommand(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0xC1, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: -1)
        
        return try await send( cmd: cmd )
    }
    
    /// Sends a General Authenticate command.
    /// This command is the second command that is sent in the "AES" case.
    /// - Parameter data data to be sent, without the {@code 0x7C} prefix (this method will add it)
    /// - Parameter lengthExpected the expected length defaults to 256
    /// - Parameter isLast indicates whether this is the last command in the chain
    /// - Parameter completed the complete handler - returns the dynamic authentication data without the {@code 0x7C} prefix (this method will remove it) or an error
    func sendGeneralAuthenticate( data : [UInt8], lengthExpected : Int = 256, isLast: Bool) async throws -> ResponseAPDU {

        let wrappedData = wrapDO(b:0x7C, arr:data)
        let commandData = Data(wrappedData)
            
         // NOTE: Support of Protocol Response Data is CONDITIONAL:
         // It MUST be provided for version 2 but MUST NOT be provided for version 1.
         // So, we are expecting 0x7C (= tag), 0x00 (= length) here.
        
        // 0x10 is class command chaining
        let instructionClass : UInt8 = isLast ? 0x00 : 0x10
        let INS_BSI_GENERAL_AUTHENTICATE : UInt8 = 0x86
        
        let cmd : APDUCommand = APDUCommand(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: lengthExpected)
        var response : ResponseAPDU
        do {
            response = try await send( cmd: cmd )
            response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
        } catch {
            // If wrong length error
            if case NFCPassportReaderError.ResponseError(_, let sw1, let sw2) = error,
               sw1 == 0x67, sw2 == 0x00 {
                
                // Resend
                let cmd : APDUCommand = APDUCommand(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: 256)
                response = try await send( cmd: cmd )
                response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
            } else {
                throw error
            }
        }
        return response
    }
    
    func selectPassportApplication() async throws -> ResponseAPDU {
        // Finally reselect the eMRTD application so the rest of the reading works as normal
        Logger.tagReader.debug( "Re-selecting eMRTD Application" )
        let cmd : APDUCommand = APDUCommand(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x0C, data: Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]), expectedResponseLength: -1)
        
        let response = try await self.send( cmd: cmd)
        return response
    }
    
    func doBACAuthentication(mrz:String) async throws {
        self.currentlyReadingDataGroup = nil

        Logger.passportReader.info( "Starting Basic Access Control (BAC)" )
        
        self.passport.BACStatus = .failed

        self.bacHandler = BACHandler( pc: self )
        try await bacHandler?.performBACAndGetSessionKeys( mrzKey: mrz )
        Logger.passportReader.info( "Basic Access Control (BAC) - SUCCESS!" )

        self.passport.BACStatus = .success
    }
    
    func getChallenge() async throws -> ResponseAPDU{
        let cmd : APDUCommand = APDUCommand(instructionClass: 00, instructionCode: 0x84, p1Parameter: 0, p2Parameter: 0, data: Data(), expectedResponseLength: 8)
        
        return try await send( cmd: cmd )
    }
    
    func doMutualAuthentication( cmdData : Data ) async throws -> ResponseAPDU{
        let cmd : APDUCommand = APDUCommand(instructionClass: 00, instructionCode: 0x82, p1Parameter: 0, p2Parameter: 0, data: cmdData, expectedResponseLength: 256)

        return try await send( cmd: cmd )
    }
    
    
    func readDataGroups() async throws {
        
        // Read COM
        var DGsToRead = [DataGroupId]()

//        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(.COM, 0) )
        
        if let com = try await readDataGroup(dgId:.COM) as? COM {
            self.passport.addDataGroup( .COM, dataGroup:com )
            self.addDatagroupsToRead(com: com, to: &DGsToRead)
        }
        
        if DGsToRead.contains( .DG14 ) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                // Do Chip Authentication
                if let dg14 = try await readDataGroup(dgId:.DG14) as? DataGroup14 {
                    self.passport.addDataGroup( .DG14, dataGroup:dg14 )
                    let caHandler = ChipAuthenticationHandler(dg14: dg14, pc:self)
                     
                    if caHandler.isChipAuthenticationSupported {
                        do {
                            // Do Chip authentication and then continue reading datagroups
                            try await caHandler.doChipAuthentication()
                            self.passport.chipAuthenticationStatus = .success
                        } catch {
                            Logger.passportReader.info( "Chip Authentication failed - re-establishing BAC")
                            self.passport.chipAuthenticationStatus = .failed
                            
                            // Failed Chip Auth, need to re-establish BAC
                            try await doBACAuthentication(mrz: mrzKey)
                        }
                    }
                }
            }
        }

        // If we are skipping secure elements then remove .DG3 and .DG4
        if self.skipSecureElements {
            DGsToRead = DGsToRead.filter { $0 != .DG3 && $0 != .DG4 }
        }

        if self.readAllDatagroups != true {
            DGsToRead = DGsToRead.filter { dataGroupsToRead.contains($0) }
        }
        for dgId in DGsToRead {
//            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )
            if let dg = try await readDataGroup(dgId:dgId) {
                self.passport.addDataGroup( dgId, dataGroup:dg )
            }
        }
    }
    
    
    func readDataGroup(dgId : DataGroupId ) async throws -> DataGroup?  {

        self.currentlyReadingDataGroup = dgId
        Logger.passportReader.info( "Reading tag - \(dgId.getName())" )
        var readAttempts = 0
        var nfcPassportReaderError: NFCPassportReaderError
        
//        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )

        repeat {
            do {
                let response = try await readDataGroupU(dataGroup: dgId)
                let dg = try DataGroupParser().parseDG(data: response)
                return dg
            } catch let error as NFCPassportReaderError {
                Logger.passportReader.error( "TagError reading tag - \(error)" )
                nfcPassportReaderError = error

                // OK we had an error - depending on what happened, we may want to try to re-read this
                // E.g. we failed to read the last Datagroup because its protected and we can't
                let errMsg = error.value
                Logger.passportReader.error( "ERROR - \(errMsg)" )
                var redoBAC = false
                if errMsg == "Session invalidated" || errMsg == "Class not supported" || errMsg == "Tag connection lost" || errMsg == "Tag response error / no response" {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if self.caHandler != nil {
                        self.caHandler = nil
                        redoBAC = true
                    } else {
                        // Can't go any more!
                        throw error
                    }
                } else if errMsg == "Security status not satisfied" || errMsg == "File not found" {
                    // Can't read this element as we aren't allowed - remove it and return out so we re-do BAC
                    self.dataGroupsToRead.removeFirst()
                    redoBAC = true
                } else if errMsg == "SM data objects incorrect" || errMsg == "Class not supported" {
                    // Can't read this element security objects now invalid - and return out so we re-do BAC
                    redoBAC = true
                } else if errMsg.hasPrefix( "Wrong length" ) || errMsg.hasPrefix( "End of file" ) {  // Should now handle errors 0x6C xx, and 0x67 0x00
                    // OK passport can't handle max length so drop it down
                    self.reduceDataReadingAmount()
                    redoBAC = true
                } else if errMsg == "UnsupportedDataGroup" {
                    // OK, this DataGroup is not supported, lets skip it
                    Logger.passportReader.debug("Unsupported DataGroup - \(dgId.rawValue)")
                    return nil
                }
                
                if redoBAC {
                    // Redo BAC and try again
                    try await doBACAuthentication(mrz: mrzKey)
                } else {
                    // Some other error lets have another try
                }
            }
            readAttempts += 1
        } while ( readAttempts < 2 )

        // The error will be thrown after n attempts
        throw nfcPassportReaderError
    }
    
    

    
    internal func addDatagroupsToRead(com: COM, to DGsToRead: inout [DataGroupId]) {
        DGsToRead += com.dataGroupsPresent.compactMap { DataGroupId.getIDFromName(name:$0) }
        DGsToRead.removeAll { $0 == .COM }
        
        // SOD should not be present in COM, but just in case we check before adding it so its not read twice
        if !DGsToRead.contains(.SOD) { DGsToRead.insert(.SOD, at: 0) }
    }
    
    /// The MSE KAT APDU, see EAC 1.11 spec, Section B.1.
    /// This command is sent in the "DESede" case.
    /// - Parameter keyData key data object (tag 0x91)
    /// - Parameter idData key id data object (tag 0x84), can be null
    /// - Parameter completed the complete handler - returns the success response or an error
    func sendMSEKAT( keyData : Data, idData: Data? ) async throws -> ResponseAPDU {
        
        var data = keyData
        if let idData = idData {
            data += idData
        }
        
        let cmd : APDUCommand = APDUCommand(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA6, data: data, expectedResponseLength: 256)
        
        return try await send( cmd: cmd )
    }
    
    /// The  MSE Set AT for Chip Authentication.
    /// This command is the first command that is sent in the "AES" case.
    /// For Chip Authentication. We prefix 0x80 for OID and 0x84 for keyId.
    ///
    /// NOTE THIS IS CURRENTLY UNTESTED
    /// - Parameter oid the OID
    /// - Parameter keyId the keyId or {@code null}
    /// - Parameter completed the complete handler - returns the success response or an error
    func sendMSESetATIntAuth( oid: String, keyId: Int? ) async throws -> ResponseAPDU {
        
        let cmd : APDUCommand
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        
        if let keyId = keyId, keyId != 0 {
            let keyIdBytes = wrapDO(b:0x84, arr:intToBytes(val:keyId, removePadding: true))
            let data = oidBytes + keyIdBytes
            
            cmd = APDUCommand(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: 256)
            
        } else {
            cmd = APDUCommand(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(oidBytes), expectedResponseLength: 256)
        }
        
        return try await send( cmd: cmd )
    }
    
//    func sendMSESetATMutualAuth( oid: String, keyType: UInt8 ) async throws -> ResponseAPDU {
//        
//        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
//        let keyTypeBytes = wrapDO( b: 0x83, arr:[keyType])
//        
//        let data = oidBytes + keyTypeBytes
//            
//        let cmd = APDUCommand(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0xC1, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: -1)
//        
//        return try await send( cmd: cmd )
//    }
    
    func readDataGroupU( dataGroup: DataGroupId ) async throws -> [UInt8]  {
        guard let tag = dataGroup.getFileIDTag() else {
            throw NFCPassportReaderError.UnsupportedDataGroup
        }
        
        return try await selectFileAndRead(tag: tag )
    }
    
    
    func reduceDataReadingAmount() {
        if maxDataLengthToRead > 0xA0 {
            maxDataLengthToRead = 0xA0
        }
    }
    
    
//    func doActiveAuthenticationIfNeccessary( tagReader : TagReader) async throws {
//        guard self.passport.activeAuthenticationSupported else {
//            return
//        }
//        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.activeAuthentication)
//
//        Logger.passportReader.info( "Performing Active Authentication" )
//
//        let challenge = aaChallenge ?? generateRandomUInt8Array(8)
//        Logger.passportReader.debug( "Generated Active Authentication challange - \(binToHexRep(challenge))")
//        let response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: useExtendedMode)
//        self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
//    }
    
   
    
    
    
    
    
}
            

                                            
