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

public protocol PassportControllerDelegate{
    func onProgressReadPassportData(progress:Float)
    func onCompleteReadPassportData(data:PassportModel)
    func onBeginCardSession(isSuccess:Bool)
    func onErrorOccur(errorMessage:String,isError:Bool)
}

public class PassportController
{

    
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
    
    //MARK: - BASIC ACCESS CONTROL
    func BasicAccessControl(mrz:String) async -> Bool {
        
        print("""
        
        #####################################
          BEGIN EXTERNAL AUTHENTICATION STEP 
        #####################################
        
        """)
        
        // Step 1 : Hash MRZ Data with SHA1 Algorithm
        let mrzData = mrz.data(using: .utf8)
        let Kseed = util?.sha1HashData(data: mrzData!).prefix(32)
        print("LIB >>>> Kseed : " + Kseed!)
        
        // Step 2 / 3 : Calculate Kenc and Kmac from Kseed and adjust Parity
        let Key1 = util?.CalculateKey(Kseed: String(Kseed!))
        let Kenc = Key1![0]
        let Kmac = Key1![1]
        
        print("LIB >>>> Kenc : " + Kenc!)
        print("LIB >>>> Kmac : " + Kmac!)
        
        // Step 4 : Initial SmartCard
        

        if isSmartCardInitialized! {
            isCardSessionBegin = await rmngr.beginCardSession()
            delegate?.onBeginCardSession(isSuccess: isCardSessionBegin!)
        }
        
        if isCardSessionBegin ?? false {
            
            // Step 5 : Transmit APDU for SELECT DF of Passport
            //print("LIB >>>> (APDU CMD SELECT DF) >>>> : " + SELECTDFSTR)
            print("LIB >>>> (APDU CMD SELECT DF) >>>> ")
            var res = await rmngr.transmitCardAPDU(card:rmngr.card!,apdu: SELECTDFSTR2)
            print("LIB <<<< (APDU RES SELECT DF) <<<< : " + res)
            
            
            if res == "nil" {
                
                print("LIB >>>> SELECT PASSPORT DF UNSUCCESS \(res)")
                delegate?.onErrorOccur(errorMessage: "SELECT PASSPORT DF UNSUCCESS, RES : \(res.uppercased())", isError:true)
                print("""
                
                #####################################
                              THE END !!!
                #####################################
                
                """)
                rmngr.endCardSession()
                return false
            }else{
                
                if res.suffix(2) == "6700" {
                    
                    // Step 5.1 : Transmit APDU for SELECT DF of Passport
                    //print("LIB >>>> (APDU CMD SELECT DF) >>>> : " + SELECTDFSTR)
                    print("LIB >>>> (APDU CMD SELECT DF) >>>> ")
                    res = await rmngr.transmitCardAPDU(card:rmngr.card!,apdu: SELECTDFSTR)
                    print("LIB <<<< (APDU RES SELECT DF) <<<< : " + res)
                    
                }
                
                // Step 6 : Transmit Get Challenge APDU
                //print("LIB >>>> (APDU CMD GET CHALLENGE) >>>> : " + GETCHALLENGESTR)
                print("LIB >>>> (APDU CMD GET CHALLENGE) >>>> ")
                res = await rmngr.transmitCardAPDU(card:rmngr.card!,apdu: GETCHALLENGESTR)
                print("LIB <<<< (APDU RES GET CHALLENGE) <<<< : " + res.uppercased())
                if res.count <= 4 {
                    print("LIB >>>> GET CHALLENGE FROM CHIP UNSUCCESS, RES : \(res.uppercased())")
                    print("""
                    
                    #####################################
                                  THE END !!!
                    #####################################
                    
                    """)
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
                print("LIB >>>> S : " + S)
                
                // Step 9 : Get Eifd by Encrypt S with Kenc by 3DES CBC Algorithm
                let Eifd = util?.TripleDesEncCBC(input: S, key: Kenc!)
                print("LIB >>>> Eifd : " + Eifd!)
                
                // Step 10 : Get Mifd by Calculate Message Authentication Code Padding Method 2 over Eifd by Kmac
                let Mifd = util?.MessageAuthenticationCodeMethodTwo(input: Eifd!, key: Kmac!)
                print("LIB MSG >>>> Mifd : " + Mifd!)
                
                // Step 11 : Construct APDU Cmd for do External Authentication Cmd = Eifd concatinate with Mifd
                let apdu = "0082000028" + Eifd! + Mifd! + "28"
                
                // Step 12 : Send APDU command
                //print("LIB >>>> (APDU CMD EXTERNAL AUTH) >>>> : " + apdu)
                print("LIB >>>> (APDU CMD EXTERNAL AUTH) >>>> : ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                print("LIB <<<< (APDU RES EXTERNAL AUTH) <<<< : " + res.uppercased())
                
                if res.count <= 4 {
                    print("LIB >>>> EXTERNAL AUTHENTICATION UNSUCCESS")
                    print("""
                    
                    #####################################
                                  THE END !!!
                    #####################################
                    
                    """)
                    delegate?.onErrorOccur(errorMessage: "EXTERNAL AUTHENTICATION UNSUCCESS",isError: true)
                    rmngr.endCardSession()
                    return false
                }
                // Step 13 : Get Eic by Cut Off Mic from response and decrypt Eic to get R
                let Eic = res.uppercased().dropLast(20)
                print("LIB >>>> Eic : " + Eic)
                let R = util?.TripleDesDecCBC(input: String(Eic), key: Kenc!)
                print("LIB >>>> R : " + R!)
          
                // Step 14 : Get Kic and SSC from R
                let Kic = R!.dropFirst(32)
                print("LIB >>>> Kic : " + Kic)
                let a = R?.dropLast(32)
                let b = a!.dropLast(16)
                let c = a!.dropFirst(16)
                SSCP = String(b.dropFirst(8) + c.dropFirst(8))
                print("LIB >>>> SSC : " + SSCP)
          
                // Step 15 : Calculate KSseed by XOR Kic with Kifd
                let SKseed = util?.XOR(Data1: String(Kic), Data2: Kifd!)
          
                // Step 16 : Calculate KSenc and KSmac from SKeed
                let SKey = util?.CalculateKey(Kseed: SKseed!)
                SKenc = SKey![0]!
                SKmac = SKey![1]!
                print("LIB >>>> SKenc : " + SKenc)
                print("LIB >>>> SKmac : " + SKmac)
          
                print("""
                
                #####################################
                  END EXTERNAL AUTHENTICATION STEP
                #####################################
                
                """)
                return true
                
            } // Select DF
            
        }else{
            delegate?.onErrorOccur(errorMessage: "BEGIN CARD SESSION FAIL && RFID NOT FOUND",isError: false)
            print("LIB >>>> BEGIN CARD SESSION FAIL && RFID NOT FOUND")
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
                        return false
                    }else{
                        DropIndex = RAPDU.count - (util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08"))!
                        print(DropIndex)
                    }
                }else{
                    DropIndex = RAPDU.count - (util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08"))!
                    print(DropIndex)
                }
                
            }else{
                DropIndex = RAPDU.count - (util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08"))!
                print(DropIndex)
            }
            
            var K = SSC + RAPDU.dropLast(DropIndex-8) + "80"
            while(K.count % 16 != 0){
                K.append("00")
            }
            let CC = self.util?.MessageAuthenticationCodeMethodOne(input: K, key: Key)
            if util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08") == -1 {
                if util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08") == -1 {
                    DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990270018E08"))!
                    print(DropIndex)
                }else{
                    DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990262828E08"))!
                    print(DropIndex)
                }
            }else{
                DropIndex = (util?.FindIndexOf(inputString: String(RAPDU), target: "990290008E08"))!
                print(DropIndex)
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
        print("LIB >>>> DO87 Data : \(result)")
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
           
           print("""
           
           #####################################
                   BEGIN READ EF.COM 
           #####################################
           
           """)
           
           // Step 1 : Construct APDU CMD for SELECT COM
           SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
           var apdu = ConstructAPDUforSelectDF(DG: FileID.Common.rawValue, SKenc: SKenc, SKmac: SKmac, SSCP: SSCP)
           print("LIB >>>> (APDU CMD SELECT EF.COM) >>>> : " + apdu)
           print("LIB >>>> (APDU CMD SELECT EF.COM) >>>> ")
           var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
           print("LIB <<<< (APDU RES SELECT EF.COM) <<<< : " + res.uppercased())
           
           // Step 2 : Verify Res Apdu select common
           SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
           var verify = VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
           if verify
           {
               // Step 3 : Send APDU Read Binary for get length com data
               SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
               apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "FF", SSC: SSCP, SKmac: SKmac)
               //print("LIB >>>> (APDU CMD GET LEN DG1) >>>> : " + apdu)
               print("LIB >>>> (APDU CMD GET LEN EF.COM) >>>> ")
               res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
               print("LIB <<<< (APDU RES GET LEN EF.COM) <<<< : " + res.uppercased())
               
               // Step 4 : Verify Res Apdu get com
               SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
               verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
               if verify {
                   // Step 5 : Get Len of DG1 from Response
                   let com = GetDataCOM(APDU:res, SKenc: SKenc)
                   print("\n")
                   print("DG List : ")
                   com.forEach { i in
                       print(DGTAG[i]!)
                   }
                   print("\n")
                   print("""
                   
                   #####################################
                           END READ EF.COM 
                   #####################################
                   
                   """)
                   
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

        print("""
        
        #####################################
              BEGIN READ DATA GROUP 1 
        #####################################
        
        """)
        
        // Step 1 : Consruct APDU Cmd for SELECT DG1
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = self.ConstructAPDUforSelectDF(DG:FileID.DG1.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        //print("LIB >>>> (APDU CMD SELECT DG1) >>>> : " + apdu)
        print("LIB >>>> (APDU CMD SELECT DG1) >>>> ")
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
        print("LIB <<<< (APDU RES SELECT DG1) <<<< : " + res.uppercased())
        
        // Step 2 : Verify Res Apdu select DG1
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        var verify = VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
        if verify {
            
            // Step 3 : Send APDU Read Binary for get length DG data
            SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
            apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "04", SSC: SSCP, SKmac: SKmac)
            //print("LIB >>>> (APDU CMD GET LEN DG1) >>>> : " + apdu)
            print("LIB >>>> (APDU CMD GET LEN DG1) >>>> ")
            res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
            print("LIB <<<< (APDU RES GET LEN DG1) <<<< : " + res.uppercased())
            
            // Step 4 : Verify Res Apdu get len DG1
            SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
            verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                
                // Step 5 : Get Len of DG1 from Response
                let len = CalculateLenDG1(APDU:res, SKenc: SKenc)
                print("LIB >>>> DG1 LEN : " + len)
                
                
                // Step 6 : Construct APDU For Read DG1 Data
                SSCP = (self.util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = self.ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "05", HexLength:len , SSC: SSCP, SKmac: SKmac)
                //print("LIB >>>> (APDU CMD READ DG1) >>>> : " + apdu)
                print("LIB >>>> (APDU CMD READ DG1) >>>> ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                print("LIB <<<< (APDU RES READ DG1) <<<< : " + res.uppercased())
                
                // Step 7 : Verify RES APDU Read Data DG1
                SSCP = (self.util?.IncrementHex(Hex:SSCP, Increment: 1))!
                verify = self.VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                if verify {
                    let data1 = GetDataDG1(APDU: res, SKenc: SKenc)
                    print("LIB >>>> DG1 : " + data1)
                    data?.documentCode = String(data1.prefix(2))
                    var data2 = data1.dropFirst(2)
                    data?.issueState = Constant.getCountryFromCode(countryCode: String(data2.prefix(3)))
                    data?.countryCode = String(data2.prefix(3))
                    data2 = data2.dropFirst(3)
                    data?.holderFullName = String(data2.prefix(31)).capitalized
                    let fullName = String(data2.prefix(31))
                    print(data?.holderFullName ?? "None")
                    let splitname = fullName.split(separator: "<", omittingEmptySubsequences: false)
                    print(splitname)
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
                    if let d = data?.dateOfIssue,data?.dateOfIssue != "" {
                        let issueYear = Int((d.prefix(4).dropFirst(2)))
                        let exYear = Int(expireDate.prefix(2))
                        if abs(issueYear! - exYear!) <= 10  {
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
                    
                    let exp = util?.isExpired(expirationDate: (data?.dateOfExpiry)!,format: "yyyyMMdd")
                    if exp! {
                        print("Document is expried")
                        data?.expireFlag = "Y"
                    }else{
                        print("Document is not expire")
                        data?.expireFlag = "N"
                    }
                    
                    
                    print("\n")
                    print("Data Group 1 Data : ")
                    print("Document Type : Passport" )
                    print("countyCode : \(data?.countryCode ?? "")")
                    print("Issue State : \(data?.issueState ?? "")")
                    print("Fullname : \(data?.holderFullName ?? "")")
                    print("Firstname : \(data?.holderFirstName ?? "")")
                    print("Middlename : \(data?.holderMiddleName ?? "")")
                    print("Lastname : \(data?.holderLastName ?? "")")
                    print("Document number : \(data?.documentNumber ?? "")")
                    print("Nationality : \(data?.nationality ?? "")")
                    print("Birth Date : \(data?.dateOfBirth ?? "")")
                    print("Expiry Date : \(data?.dateOfExpiry ?? "")")
                    print("Sex : \(data?.sex ?? "")")
                    print("Optional Data : \(data?.optionalData ?? "")")
                    print("\n")
                    
                }else{
                    print("LIB >>>> COMPARE RES APDU READ DG1 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG1 FAIL",isError:true)
                } // end of verify cc read dg1
                
            }else{
                print("LIB >>>> COMPARE RES APDU GET LEN DG1 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU GET LEN DG1 FAIL",isError: true)
            } // end of verify get dg1 len
        }else{
            print("LIB >>>> COMPARE RES APDU SELECT DG1 FAIL")
            delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG1 FAIL",isError: true)
        } // end of verify select dg1
        
        print("""
        
        #####################################
                END READ DATA GROUP 1 
        #####################################
        
        """)
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
        
        print("""
        
        #####################################
              BEGIN READ DATA GROUP 2 
        #####################################
        
        """)

        // Step 1 : Consruct APDU for SELECT DG2
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG2.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        //print("LIB >>>> (APDU CMD SELECT DG2) >>>> : " + apdu)
        print("LIB >>>> (APDU CMD SELECT DG2) >>>> ")
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
        print("LIB <<<< (APDU RES SELECT DG2) <<<< : " + res.uppercased())
        
        // Step 2 : Verify RES APDU Select DG2
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        var verify = VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
        if verify {
            
            // Step 3 : Send APDU Get Len DG2
            SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
            apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "30", SSC: SSCP, SKmac: SKmac)
            print("LIB >>>> (APDU CMD GET LEN DG2) >>>> ")
            //print("LIB >>>> (APDU CMD GET LEN DG2) >>>> : " + apdu)
            res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
            print("LIB <<<< (APDU RES GET LEN DG2) <<<< : " + res.uppercased())
            
            // Step 4 : Verify Res APDU Get Len DG2
            SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
            verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                let len = CalculateLenDG2(APDU:res, SKenc: SKenc)
                print("LIB >>>> DG2 LEN : " + len[0])
                print("LIB >>>> DG2 OFFSET : " + len[1])
                
                // Step 5 : Get All Data DG2
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset: len[1], HexLength: len[0], SSC: SSCP, SKmac: SKmac)
                //print("LIB >>>> (APDU CMD READ DG2) >>>> : " + apdu)
                print("LIB >>>> (APDU CMD READ DG2) >>>> ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                print("LIB <<<< (APDU RES READ DG2) <<<< : " + res.uppercased())
                
                // Step 6 : Verify Res Apdu Read DG2
                SSCP = (util?.IncrementHex(Hex:SSCP, Increment: 1))!
                verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                var r:String = ""
                var rr:String = ""
                if verify {
                    let arr = GetDataDG2(APDU: res, SKenc: SKenc)
                    r = arr[0]
                    rr = arr[1]
                    let allLen = (UInt32(len[0],radix: 16)! * 2) - 100 //- 1000
                    print("LIB >>>> DG2 CHARACTER LEN : \(allLen)")
                    if r.count < allLen {
        
                        print("LIB >>>> DG2 FOUND REMAIN")
                        var re:String = ""
                        var re2:String = ""
                        // Step 7 : Get Remain Data DG2
                        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                        //apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset:"00", HexLength: "0384", SSC: SSCP, SKmac: SKmac)
                        //print("LIB >>>> (APDU CMD READ DG2) >>>> : " + apdu)
                        apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset:"00", HexLength: len[0], SSC: SSCP, SKmac: SKmac)
                        print("LIB >>>> (APDU CMD READ DG2) >>>> ")
                        res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                        print("LIB <<<< (APDU RES READ DG2) <<<< : " + res.uppercased())

                        // Step 6 : Verify Res Apdu Read DG2
                        SSCP = (util?.IncrementHex(Hex:SSCP, Increment: 1))!
                        verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                        if verify {
                            let arr = GetRemainDataDG2(APDU: res, SKenc: SKenc)
                            re.append(arr[0])
                            re2.append(arr[1])
                        }else{
                            print("LIB >>>> COMPARE RES APDU READ REMAIN DG2 FAIL")
                            delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ REMAIN DG2 FAIL",isError: true)
                        } // end of verify res apdu read ramin dg2
                        
                        // Loop for get all remain data
                        while re.count < allLen {
                            
                            // Step 7 : Get Remain Data DG2
                            let new = re.count/2
                            var newOffset = String(new,radix: 16)
                            while newOffset.count < 4 {
                                newOffset = "0" + newOffset
                            }
                            SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                            apdu = ConstructAPDUforReadBinaryExtend(HexBlock: String(newOffset.dropLast(2)), HexOffset: String(newOffset.dropFirst(2)), HexLength: len[0], SSC: SSCP, SKmac: SKmac)
                            print("LIB >>>> (APDU CMD READ DG2) >>>> ")
                            //print("LIB >>>> (APDU CMD READ DG2) >>>> : " + apdu)
                            res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                            print("LIB <<<< (APDU RES READ DG2) <<<< : " + res.uppercased())
                            
                            // Step 6 : Verify Res Apdu Read DG2
                            SSCP = (util?.IncrementHex(Hex:SSCP, Increment: 1))!
                            verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                            if verify {
                                let arr = GetRemainDataDG2(APDU: res, SKenc: SKenc)
                                re.append(arr[0])
                                re2.append(arr[1])
                            }else{
                                print("LIB >>>> COMPARE RES APDU READ REMAIN DG2 FAIL")
                                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ REMAIN DG2 FAIL",isError: true)
                                data?.faceImage = ""
                                break
                            } // end of verify res apdu read ramin dg2
                        }
                        // JP2 = 170 = Format
                        //var re1 = String(re.dropFirst(170))
                        var re1 = ""
                        if util?.FindIndexOf(inputString: re, target: "0000000C6A502020") != -1 {
                            re1 = String(re.dropFirst((util?.FindIndexOf(inputString: re, target: "0000000C6A502020"))!))
                            if let image = UIImage(data: re1.hexadecimal!) {
                                print("LIB >>>> FACE DATA WITH TEMPLATE (JP2000 FORMAT) : ")
                                print(re)
                                print("LIB >>>> FACE RAW (JP2000 FORMAT) : ")
                                print(re1)
                                let djpg = image.jpegData(compressionQuality: 1.0)
                                data?.faceImage = djpg?.base64EncodedString()
                            }else{
                                data?.faceImage = ""
                            }
                        }else if util?.FindIndexOf(inputString: re, target: "FFD8FFE000104A464946") != -1{
                            
                            // JFIF Format
                            re1 = String(re.dropFirst((util?.FindIndexOf(inputString: re, target: "FFD8FFE000104A464946"))!))
                            print("LIB >>>> FACE DATA WITH TEMPLATE (JFIF FORMAT) : ")
                            print(re)
                            print("LIB >>>> FACE RAW (JFIF FORMAT) : ")
                            print(re1)
                            
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
                         
                    }else{
                        //let r2 = r.dropFirst(92)
                        if util?.FindIndexOf(inputString: r, target: "0000000C6A502020") != -1 {
                            
                            let r2 = String(r.dropFirst((util?.FindIndexOf(inputString: r, target: "0000000C6A502020"))!))
                            //let rr2 = rr.dropFirst(92)
                            let rr2 = String(rr.dropFirst((util?.FindIndexOf(inputString: rr, target: "0000000C6A502020"))!))
                            if let image = UIImage(data: String(r2).hexadecimal!){
                                print("LIB >>>> FACE DATA WITH TEMPLATE (JP2000 FORMAT) : ")
                                print(r)
                                print("LIB >>>> FACE RAW (JP2000 FORMAT) : ")
                                print(r2)
                                let djpg = image.jpegData(compressionQuality: 1.0)
                                data?.faceImage = djpg?.base64EncodedString()
                            }else if let image = UIImage(data: String(rr2).hexadecimal!){
                                print("LIB >>>> FACE DATA WITH TEMPLATE (JP2000 FORMAT) : ")
                                print(r)
                                print("LIB >>>> FACE RAW (JP2000 FORMAT) : ")
                                print(r2)
                                let djpg = image.jpegData(compressionQuality: 1.0)
                                data?.faceImage = djpg?.base64EncodedString()
                            }else{
                                data?.faceImage = ""
                            }
                            
                        }else if util?.FindIndexOf(inputString: r, target: "FFD8FFE000104A464946") != -1 {
//                            let r2 = r.dropFirst(74)
//                            let rr2 = rr.dropFirst(74)
                            let r2 = String(r.dropFirst((util?.FindIndexOf(inputString: r, target: "FFD8FFE000104A464946"))!))
                            let rr2 = String(rr.dropFirst((util?.FindIndexOf(inputString: rr, target: "FFD8FFE000104A464946"))!))
                            if let image = UIImage(data:String(r2).hexadecimal!){
                                print("LIB >>>> FACE DATA WITH TEMPLATE(JFIF FORMAT) : ")
                                print(r)
                                print("LIB >>>> FACE RAW (JFIF FORMAT) : ")
                                print(r2)
                                let djpg = image.jpegData(compressionQuality: 1.0)
                                data?.faceImage = djpg?.base64EncodedString()
                            }else if let image = UIImage(data: String(rr2).hexadecimal!){
                                print("LIB >>>> FACE DATA WITH TEMPLATE(JFIF FORMAT) : ")
                                print(r)
                                print("LIB >>>> FACE RAW (JFIF FORMAT) : ")
                                print(r2)
                                let djpg = image.jpegData(compressionQuality: 1.0)
                                data?.faceImage = djpg?.base64EncodedString()
                            }
                            else{
                                data?.faceImage = ""
                            }
                        }else{
                            data?.faceImage = ""
                        }
                    } // end of get dg2 data
                    
                }else{
                    print("LIB >>>> COMPARE RES APDU READ DG2 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG2 FAIL",isError: true)
                    data?.faceImage = ""
                } // end of verify res apdu read dg2
                
            }else{
                print("LIB >>>> COMPARE RES APDU GET LEN DG2 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU GET LEN DG2 FAIL",isError: true)
            } // end of verify res apdu get len dg2

        }else{
            print("LIB >>>> COMPARE RES APDU SELECT DG2 FAIL")
            delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG2 FAIL",isError: true)
        } // end of verify res apdu select dg2
        
        print("""
        
        #####################################
               END READ DATA GROUP 2 
        #####################################
        
        """)

    }
    
    // MARK: - DG2 DATA MANAGEMENT
    func CalculateLenDG2(APDU:String,SKenc:String)->[String]{
        //var result = APDU.dropFirst(6)
        var result = APDU.uppercased()//getDataFromDO87(in: APDU).uppercased()
        result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990290008E08"))!))
        //print("result 1 : " + result)
        result = getDataFromDO87(in: result)
        let encResult = util?.TripleDesDecCBC(input: String(result), key: SKenc)
        print("LIB >>>>  CALCULATE DG2 LEN ENC RESULT : " + encResult!)
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
        print("LIB >>>> GET DATA DG2 ENC : ")
        print(result1)
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
            print("LIB >>>> DECRYPT BEFORE DROP : ")
            print(nofix)
            //result = result.dropLast(10)
            //result1 = trimHexStringToLength(hexString: String(result), targetLength: 1796)
            result1 = trimTrailing80(from: String(nofix))
            result2 = trimTrailing80(from: String(fix))
            print("LIB >>>> DECRYPT RESULT : ")
            print(result1)
        }else{
            result = String(result.dropLast(result.count - (self.util?.FindIndexOf(inputString: String(result), target: "990290008E"))!))
            var nofix = getDataFromDO87(in: result)
            var fix = String(result.dropFirst(10))
            nofix = String((util?.TripleDesDecCBC(input: String(nofix), key: SKenc).dropFirst(4))!)
            fix = String((util?.TripleDesDecCBC(input: String(fix), key: SKenc).dropFirst(4))!)
            print("LIB >>>> DECRYPT BEFORE DROP : ")
            print(nofix)
            //result = result.dropLast(2)
            //result1 = trimHexStringToLength(hexString: String(result), targetLength: 1796)
            result1 = trimTrailing80(from: nofix)
            result2 = trimTrailing80(from: fix)
            print("LIB >>>> DECRYPT RESULT : ")
            print(result1)
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
        
        print("""
        
        #####################################
              BEGIN READ DATA GROUP 7 
        #####################################
        
        """)
        
        // MARK: - Step 1 : Consruct APDU for SELECT DG7
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG7.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        print("LIB >>>> (APDU CMD SELECT DG7) >>>> : " + apdu)
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
        print("LIB <<<< (APDU RES SELECT DG7) <<<< : " + res.uppercased())
        
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        if util?.FindIndexOf(inputString:res.uppercased(), target: "990290008E08") == -1 && util?.FindIndexOf(inputString: res, target: "990262828E08") == -1 {
            
            print("LIB >>>> SELECT DG7 UNSUCCESS")
            
        }else{
            
            // MARK: - Step 2 : Verify Res Apdu select DG11
            
            var verify = VerifySelectRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                
                // MARK: - Step 3 : Send APDU Read Binary for get length DG data
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "FF", SSC: SSCP, SKmac: SKmac)
                print("LIB >>>> (APDU CMD GET LEN DG7) >>>> : " + apdu)
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                print("LIB <<<< (APDU RES GET LEN DG7) <<<< : " + res.uppercased())
                
                // MARK: - Step 4 : Verify Res Apdu get len DG11
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                if verify {
                    
                    // MARK: - Step 5 : Read DG11
                    let len = CalculateLenAndOffsetDG7(APDU:res, SKenc: SKenc)
                    print("LIB >>>> DG7 CHARACTER LEN : " + len[0])
                    print("LIB >>>> DG7 OFFSET LEN : " + len[1])
                    
                    // MARK: - Step 5 : Get All Data DG3
                    SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                    apdu = ConstructAPDUforReadBinaryExtend(HexBlock: "00", HexOffset: len[1], HexLength: len[0], SSC: SSCP, SKmac: SKmac)
                    print("LIB >>>> (APDU CMD READ DG7) >>>> : " + apdu)
                    res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                    print("LIB <<<< (APDU RES READ DG7) <<<< : " + res.uppercased())
                    
                    // MARK: - Step 6 : Verify Res Apdu Read DG3
                    SSCP = (util?.IncrementHex(Hex:SSCP, Increment: 1))!
                    verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
                    if verify {
                        let r = GetDataDG7(APDU: res, SKenc: SKenc)
                        print("LIB >>>> DG 7 : " + r.dropLast(6))
                        let res = r.dropLast(6)
                        let djpg = UIImage(data: String(res).hexadecimal!)!.jpegData(compressionQuality: 1.0)
                        data?.signatureImage = djpg!.base64EncodedString()
                        
                    }else{
                        print("LIB >>>> COMPARE RES APDU READ DG7 FAIL")
                        delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG7 FAIL",isError: true)
                    } // end of verify res apdu read dg3
                    
                    
                }else{
                    print("LIB >>>> COMPARE RES APDU READ DG7 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG7 FAIL",isError: true)
                } // end of verify read dg7
            }else{
                print("LIB >>>> COMPARE RES APDU SELECT DG7 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG7 FAIL",isError: true)
            } // end of verify select dg7
            
        }
        
        print("""
        
        #####################################
              End READ DATA GROUP 7 
        #####################################
        
        """)
        
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
        print("LIB >>>> DG7 CHARACTER LEN: " + String(allLength, radix: 10))
        
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
        
        print("""
        
        #####################################
              BEGIN READ DATA GROUP 11 
        #####################################
        
        """)
        
        // Step 1 : Consruct APDU for SELECT DG11
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG11.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        //print("LIB >>>> (APDU CMD SELECT DG11) >>>> : " + apdu)
        print("LIB >>>> (APDU CMD SELECT DG11) >>>> ")
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
        print("LIB <<<< (APDU RES SELECT DG11) <<<< : " + res.uppercased())
        
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        if util?.FindIndexOf(inputString:res.uppercased(), target: "990290008E08") == -1 && util?.FindIndexOf(inputString: res, target: "990262828E08") == -1 {
            
            print("LIB >>>> SELECT DG11 UNSUCCESS")
            
        }else{
            
            // Step 2 : COMPARE Res Apdu select DG11
            
            var verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                
                // Step 3 : Send APDU Read Binary for get length DG data
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "00", SSC: SSCP, SKmac: SKmac)
                //print("LIB >>>> (APDU CMD GET LEN DG11) >>>> : " + apdu)
                print("LIB >>>> (APDU CMD GET DG11) >>>> ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                print("LIB <<<< (APDU RES GET DG11) <<<< : " + res.uppercased())
                
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
                        
                        print("LIB >>>> DG11 NOT FOUND")
                        
                    }else{
                        
                        // Step 5 : Read DG11
                        let dg11 = GetDataDG11(APDU:res, SKenc: SKenc)
                        print("LIB >>>> DG11 : " + dg11)
                        
                        // Step 6 : Loop for each data
                        data?.personalNumber = SplitDataWithTags(dg: dg11, Tag: "5F10")
                        data?.fullDateOfBirth = SplitDataWithTags(dg: dg11, Tag: "5F2B")
                        data?.placeOfBirth = SplitDataWithTags(dg: dg11, Tag: "5F11").capitalized
                        data?.permanentAddress = SplitDataWithTags(dg: dg11, Tag: "5F42")
                        data?.telephone = SplitDataWithTags(dg: dg11, Tag: "5F12")
                        data?.profession = SplitDataWithTags(dg: dg11, Tag: "5F13")
                        data?.title = SplitDataWithTags(dg: dg11, Tag: "5F14").capitalized
                        data?.personelSummary = SplitDataWithTags(dg: dg11, Tag: "5F15")
                        
                        print("\n")
                        print("Data Group 11 Data : ")
                        print("Personal Number : \(data?.personalNumber ?? "")")
                        print("Full Birth Date : \(data?.fullDateOfBirth ?? "")")
                        print("Place of birth : \(data?.placeOfBirth ?? "")")
                        print("Permanent Address : \(data?.permanentAddress ?? "")")
                        print("Telephone : \(data?.telephone ?? "")")
                        print("Title : \(data?.title ?? "")")
                        print("\n")
                        
                        if data?.expireFlag == "Y" {
                            print("Document is expried")
                        }else{
                            print("Document is not expire")
                        }
                        
                    } // DG11 NOT FOUND
        
                    
                }else{
                    print("LIB >>>> COMPARE RES APDU READ DG11 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG11 FAIL",isError: true)
                } // end of verify read dg11
            }else{
                print("LIB >>>> COMPARE RES APDU SELECT DG11 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG11 FAIL",isError: true)
            } // end of verify select dg11
            
        }
        
        
        print("""
        
        #####################################
              End READ DATA GROUP 11 
        #####################################
        
        """)
        
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
        
        print("""
        
        #####################################
              BEGIN READ DATA GROUP 12 
        #####################################
        
        """)
        
        // Step 1 : Consruct APDU for SELECT DG11
        SSCP = (util?.IncrementHex(Hex: String(SSCP), Increment: 1))!
        var apdu = ConstructAPDUforSelectDF(DG:FileID.DG12.rawValue,SKenc: SKenc,SKmac: SKmac,SSCP: SSCP)
        //print("LIB >>>> (APDU CMD SELECT DG11) >>>> : " + apdu)
        print("LIB >>>> (APDU CMD SELECT DG12) >>>> ")
        var res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
        print("LIB <<<< (APDU RES SELECT DG12) <<<< : " + res.uppercased())
        
        SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
        if util?.FindIndexOf(inputString:res.uppercased(), target: "990290008E08") == -1 && util?.FindIndexOf(inputString: res, target: "990262828E08") == -1 {
            
            print("LIB >>>> SELECT DG12 UNSUCCESS")
            
        }else{
            
            // Step 2 : COMPARE Res Apdu select DG12
            
            var verify = VerifyReadBinaryRAPDU(APDU: res, SSC: SSCP, Key: SKmac)
            if verify {
                
                // Step 3 : Send APDU Read Binary for get length DG data
                SSCP = (util?.IncrementHex(Hex: SSCP, Increment: 1))!
                apdu = ConstructAPDUforReadBinary(HexBlock: "00", HexOffset: "00", HexLength: "00", SSC: SSCP, SKmac: SKmac)
                //print("LIB >>>> (APDU CMD GET LEN DG11) >>>> : " + apdu)
                print("LIB >>>> (APDU CMD GET DG12) >>>> ")
                res = await rmngr.transmitCardAPDU(card: rmngr.card!, apdu: apdu)
                print("LIB <<<< (APDU RES GET DG12) <<<< : " + res.uppercased())
                
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
                        
                        print("LIB >>>> DG12 NOT FOUND")
                        
                    }else{
                        
                        // Step 5 : Read DG12
                        let dg12 = GetDataDG12(APDU:res, SKenc: SKenc)
                        print("LIB >>>> DG12 : " + dg12)
                        
                        // Step 6 : Loop for each data
                        data?.issuingAuthority = SplitDataWithTags(dg: dg12, Tag: "5F19")
                        data?.dateOfIssue = SplitDataWithTags(dg: dg12, Tag: "5F26")
                        data?.endorsements = SplitDataWithTags(dg: dg12, Tag: "5F1B")
                        data?.imageOfFrontDoc = SplitDataWithTags(dg: dg12, Tag: "5F1D")
                        data?.imageOfRearDoc = SplitDataWithTags(dg: dg12, Tag: "5F1E")
                        data?.dateTimeDocPersonalization = SplitDataWithTags(dg: dg12, Tag: "5F55")
                        data?.serialNumberDocPersonalizationSystem = SplitDataWithTags(dg: dg12, Tag: "5F56")
                        
                        print("\n")
                        print("Data Group 12 Data : ")
                        print("Issuing Authority : " + (data?.issuingAuthority)!)
                        print("Date of Issue : " + (data?.dateOfIssue)!)
                        print("Endorsements : " + (data?.endorsements)!)
                        print("Image Of Rear : " + ((data?.imageOfFrontDoc)!))
                        print("Date and time of document personalized : " + (data?.dateTimeDocPersonalization)!)
                        print("Serial Number of Personalization System : " + (data?.serialNumberDocPersonalizationSystem)!)
                        print("\n")
                        
                    } // DG11 NOT FOUND
        
                    
                }else{
                    print("LIB >>>> COMPARE RES APDU READ DG11 FAIL")
                    delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU READ DG11 FAIL",isError: true)
                } // end of verify read dg11
            }else{
                print("LIB >>>> COMPARE RES APDU SELECT DG11 FAIL")
                delegate?.onErrorOccur(errorMessage: "COMPARE RES APDU SELECT DG11 FAIL",isError: true)
            } // end of verify select dg11
            
        }
        
        print("""
        
        #####################################
              End READ DATA GROUP 12 
        #####################################
        
        """)
        
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
        print("Before get data from DO87")
        print(result)
        result = getDataFromDO87(in: result).uppercased()
        print("After get data from DO87")
        print(result)
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
        let mrz = docnum.trimmingCharacters(in: .whitespacesAndNewlines) + birth.trimmingCharacters(in: .whitespacesAndNewlines) + exp.trimmingCharacters(in: .whitespacesAndNewlines)
        print(mrz)
        
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
            
            let isSuccess = await BasicAccessControl(mrz: mrz)
            progress += eachProgress
            delegate?.onProgressReadPassportData(progress: progress)
            
            if isSuccess {
                
                // in case of checking full year with issue date of document
                
                await readDG12()
                progress += eachProgress
                delegate?.onProgressReadPassportData(progress: progress)
                
                
                if dg1 {
                    await readDG1()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }
                
                if dg2 {
                    await readDG2()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }
                
                if dg11 {
                    await readDG11()
                    progress += eachProgress
                    delegate?.onProgressReadPassportData(progress: progress)
                }
                
                
                delegate?.onCompleteReadPassportData(data: data!)
               
            }

            rmngr.endCardSession()
        }
        
    }
}
            

                                            
