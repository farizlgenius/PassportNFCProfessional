//
//  Utility.swift
//  PassportLib
//
//  Created by Far-iz Lengha on 8/11/2567 BE.
//

import Foundation
import CommonCrypto
import CryptoKit

class Utility{
    
    init(){}
    /*
    ######################### Utility is below ###############################
     */
    // MARK: 3DES Encryption
    // 3DES Encryption
    func TripleDesEncCBC(input:String,key:String) -> String {
        // Divide Input to 64 bit Block
        let strArr:[String] = DivideInputToEach64BitBlock(HexInput: input)
        // Divided Key
        let index = key.index(key.startIndex,offsetBy: 16)
        let firstKey:String = String(key[..<index])
        let secondKey:String = String(key[index...])
        // Set count for loop array
        let count = 0...(strArr.count-1)
        var result:[String] = []
        // 1st Round
        for i in count {
            if i == 0 {
                result.append(DESEncECB(Input: DESDecECB(Input: DESEncCBC(Input: strArr[i], key: firstKey), key: secondKey), key: firstKey))
            }else{
                result.append(DESEncECB(Input: DESDecECB(Input: DESEncCBC(Input: strArr[i], key: firstKey,Iv: result[i-1]), key: secondKey), key: firstKey))
            }
        }
        return result.joined().uppercased()
    }

    // 3DES Decryption
    func TripleDesDecCBC(input:String,key:String) -> String {
        // Divide Input to 64 bit Block
        let strArr:[String] = DivideInputToEach64BitBlock(HexInput: input)
        // Divided Key
        let index = key.index(key.startIndex,offsetBy: 16)
        let firstKey:String = String(key[..<index])
        let secondKey:String = String(key[index...])
        // Set count for loop array
        let count = 0...(strArr.count-1)
        var result:[String] = []
        // 1st Round
        for i in count {
            if i == 0 {
                result.append(DESDecCBC(Input: DESEncECB(Input: DESDecECB(Input: strArr[i], key: firstKey), key: secondKey), key: firstKey))
            }else{
                result.append(DESDecCBC(Input: DESEncECB(Input: DESDecECB(Input: strArr[i], key: firstKey), key: secondKey), key: firstKey,Iv: strArr[i-1]))
            }
        }
        return result.joined().uppercased()
    }

    // MARK: MAC Algorithm
    func MessageAuthenticationCodeMethodOne(input:String,key:String)->String{
        // Divided key
        let index = key.index(key.startIndex,offsetBy: 16)
        let firstKey:String = String(key[..<index])
        let secondKey:String = String(key[index...])
        //Perform Des CBC mode for full length
        let first = DESEncCBC(Input: input, key: firstKey)
        // Divide Input to 64 bit Block
        let strArr:[String] = DivideInputToEach64BitBlock(HexInput: first)
        //Perform full on remain
        let result = DESEncCBC(Input: DESDecCBC(Input: strArr[strArr.count-1], key: secondKey), key: firstKey)
        return result.uppercased()
    }

    func MessageAuthenticationCodeMethodTwo(input:String,key:String)->String{
        // Bit Padding
        let input2 = input + "8000000000000000"
        // Divided key
        let index = key.index(key.startIndex,offsetBy: 16)
        let firstKey:String = String(key[..<index])
        let secondKey:String = String(key[index...])
        //Perform Des CBC mode for full length
        let first = DESEncCBC(Input: input2, key: firstKey)
        // Divide Input to 64 bit Block
        let strArr:[String] = DivideInputToEach64BitBlock(HexInput: first)
        //Perform full on remain
        let result = DESEncCBC(Input: DESDecCBC(Input: strArr[strArr.count-1], key: secondKey), key: firstKey)
        return result.uppercased()
    }

    func DivideInputToEach64BitBlock(HexInput:String)->[String]{
        return HexInput.split(by: 16)
    }

    func DivideInputToEach8BitBlock(HexInput:String)->[String]{
        return HexInput.split(by: 8)
    }

    func DESEncCBC(Input:String,key:String,Iv:String = "0000000000000000")->String{
        let Option = UInt32(kCCEncrypt)
        let Algorithm = UInt32(kCCAlgorithmDES)
        let Key = key.hexadecimal! as NSData
        let KeyLength = size_t(kCCKeySizeDES)
        let Data = Input.hexadecimal! as NSData
        let iv = Iv.hexadecimal! as NSData
        let cryptData1 = NSMutableData(length: Int(Data.length))!
        var numBytesEncrypted :size_t = 0
        let cryptoStatus = CCCrypt(Option,Algorithm,0,Key.bytes,KeyLength,iv.bytes, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
        if cryptoStatus >= 0 && UInt32(cryptoStatus) == UInt32(kCCSuccess) {
            //Convert NSMutualData to NSData to Data
            let data = NSData(data: cryptData1 as Data) as Data
            return data.hexadecimal
            
        }else{
            return ""
        }
    }

    func DESDecCBC(Input:String,key:String,Iv:String = "0000000000000000")->String{
        //MARK: Round 1 - Encryption
        let Option = UInt32(kCCDecrypt)
        let Algorithm = UInt32(kCCAlgorithmDES)
        let Key = key.hexadecimal! as NSData
        let KeyLength = size_t(kCCKeySizeDES)
        let Data = Input.hexadecimal! as NSData
        let iv = Iv.hexadecimal! as NSData
        let cryptData1 = NSMutableData(length: Int(Data.length))!
        var numBytesEncrypted :size_t = 0
        let cryptoStatus = CCCrypt(Option,Algorithm,0,Key.bytes,KeyLength,iv.bytes, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
        if cryptoStatus >= 0 && UInt32(cryptoStatus) == UInt32(kCCSuccess) {
            //Convert NSMutualData to NSData to Data
            let data = NSData(data: cryptData1 as Data) as Data
            return data.hexadecimal
            
        }else{
            return ""
        }
    }

    func DESEncECB(Input:String,key:String)->String{
        let Option = UInt32(kCCEncrypt)
        let Algorithm = UInt32(kCCAlgorithmDES)
        let Key = key.hexadecimal! as NSData
        let KeyLength = size_t(kCCKeySizeDES)
        let Data = Input.hexadecimal! as NSData
        let cryptData1 = NSMutableData(length: Int(Data.length))!
        var numBytesEncrypted :size_t = 0
        let cryptoStatus = CCCrypt(Option,Algorithm,UInt32(kCCOptionECBMode),Key.bytes,KeyLength,nil, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
        if cryptoStatus >= 0 && UInt32(cryptoStatus) == UInt32(kCCSuccess) {
            //Convert NSMutualData to NSData to Data
            let data = NSData(data: cryptData1 as Data) as Data
            return data.hexadecimal
            
        }else{
            return "fail"
        }
    }

    func DESDecECB(Input:String,key:String)->String{
        let Option = UInt32(kCCDecrypt)
        let Algorithm = UInt32(kCCAlgorithmDES)
        let Key = key.hexadecimal! as NSData
        let KeyLength = size_t(kCCKeySizeDES)
        let Data = Input.hexadecimal! as NSData
        let cryptData1 = NSMutableData(length: Int(Data.length))!
        var numBytesEncrypted :size_t = 0
        let cryptoStatus = CCCrypt(Option,Algorithm,UInt32(kCCOptionECBMode),Key.bytes,KeyLength,nil, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
        if cryptoStatus >= 0 && UInt32(cryptoStatus) == UInt32(kCCSuccess) {
            //Convert NSMutualData to NSData to Data
            let data = NSData(data: cryptData1 as Data) as Data
            return data.hexadecimal
            
        }else{
            return "fail"
        }
    }

    // Adjust parity bit for key
    func AdjustParity(key:String)->String {
        let binArr = DivideInputToEach8BitBlock(HexInput: key.hexaToBinary)
        var result:[String] = []
        var result2:[String] = []
        for data in binArr {
            var count = 0
            var binn:[Character] = []
            for bit in data {
                binn.append(bit)
                if bit == "1" {
                    count += 1
                }
            }
            if count % 2 == 0{
                if binn[binn.count-1] == "1" {
                    binn[binn.count-1] = "0"
                }else{
                    binn[binn.count-1] = "1"
                }
            }
            result.append(String(binn))
        }
        for bin in result {
            result2.append(binToHex(bin)!)
        }
        return result2.joined()
    }


    // Binary to hex
    func binToHex(_ bin : String) -> String? {
        // binary to integer:
        guard let num = UInt64(bin, radix: 2) else { return nil }
        // integer to hex:
        let hex = String(num, radix: 16,uppercase: true) // (or false)
        if hex.count < 2 {
            let h = "0" + hex
            return h
        }
        return hex
    }
    
    // SHA1 Hash function
    func sha1HashData(data:Data) -> String{
        let hashData = Insecure.SHA1.hash(data: data)
        let hashString = hashData.compactMap{
            String(format: "%02X", $0)
        }.joined()
        return hashString
    }
    
    //Random hex 8 byte and 16 byte
    func RandomHex(numDigit:Int)->String{
        let hexStr = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"]
        var result = ""
        for _ in 0..<numDigit {
            result = result + hexStr[Int.random(in: 0..<16)]
        }
        return result
    }
    
    // XOR
    func XOR(Data1: String,Data2:String) -> String {
        var result:[String] = []
        let d1str = Data1.hexaToBinary.map{ String($0) }
        let d2str = Data2.hexaToBinary.map{ String($0) }
        for i in 0..<d1str.count {
            if d1str[i] == d2str[i] {
                result.append("0")
            }else{
                result.append("1")
            }
        }
        let result2 = result.joined()
        let result3 = result2.split(by: 8)
        var result4:[String] = []
        result3.forEach{
            data in
            result4.append(binToHex(data)!)
        }
        
        return result4.joined()
    }
    
    // Calculate Key
    func CalculateKey(Kseed:String)->[String?]{
        // Step 2 : Calculate Kenc and Kmac from Kseed
        let c1:String = Kseed + "00000001"
        let c2:String = Kseed + "00000002"
        let Kenc = sha1HashData(data: c1.hexadecimal!).prefix(32)
        let Kmac = sha1HashData(data: c2.hexadecimal!).prefix(32)
        
        // Step 3 : Adjust key parity
        let KencA = AdjustParity(key: String(Kenc))
        let KmacA = AdjustParity(key: String(Kmac))
        
        return [KencA,KmacA]
    }
    
    func IncrementHex(Hex:String,Increment:UInt64)->String{
        let p1 = Hex.dropLast(8)
        let p2 = Hex.dropFirst(8)
        let num2 = UInt64(p2,radix: 16)! + Increment
        let newStr = String(format: "%08X", num2)
        return p1 + newStr
    }
    
    func FindIndexOf(inputString:String,target:String)->Int{
        if let range = inputString.range(of: target) {
           let startingIndex = inputString.distance(from: inputString.startIndex, to: range.lowerBound)
//           let endingIndex = inputString.distance(from: inputString.startIndex, to: range.upperBound)
//           print("Input string: \(inputString)")
//           print("Starting index of '\(target)' is: \(startingIndex)")
//           print("Ending index of '\(target)' is: \(endingIndex)")
            return startingIndex
        } else {
            print("LIB >>>> NOT FOUND \(target.uppercased())")
            return -1
        }
    }
    
    func FindLastIndexOf(inputString:String,target:String)->Int{
        if let range = inputString.range(of: target) {
           let endingIndex = inputString.distance(from: inputString.startIndex, to: range.upperBound)
//           print("Input string: \(inputString)")
//           print("Starting index of '\(target)' is: \(startingIndex)")
//           print("Ending index of '\(target)' is: \(endingIndex)")
            return endingIndex
        } else {
            print("LIB >>>> NOT FOUND \(target.uppercased())")
            return -1
        }
    }
    
    // Convert Hex String to ASCII
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
    
    
}


// Hex String to Data
extension String {
    
    /// Create `Data` from hexadecimal string representation
    ///
    /// This creates a `Data` object from hex string. Note, if the string has any spaces or non-hex characters (e.g. starts with '<' and with a '>'), those are ignored and only hex characters are processed.
    ///
    /// - returns: Data represented by this hexadecimal string.
    
    var hexadecimal: Data? {
        var data = Data(capacity: count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }
        
        guard data.count > 0 else { return nil }
        
        return data
    }
    
    func split(by length: Int) -> [String] {
            var startIndex = self.startIndex
            var results = [Substring]()

            while startIndex < self.endIndex {
                let endIndex = self.index(startIndex, offsetBy: length, limitedBy: self.endIndex) ?? self.endIndex
                results.append(self[startIndex..<endIndex])
                startIndex = endIndex
            }

            return results.map { String($0) }
        }
    
}


// Data to Hex String
extension Data {
    
    /// Hexadecimal string representation of `Data` object.
    
    var hexadecimal: String {
        return map { String(format: "%02x", $0) }
            .joined()
    }
    
    public mutating func xor(key: Data) {
        for i in 0..<self.count {
            self[i] ^= key[i % key.count]
        }
    }


}

// Hex to binary
extension String {
    typealias Byte = UInt8
    var hexaToBytes: [Byte] {
        var start = startIndex
        return stride(from: 0, to: count, by: 2).compactMap { _ in   // use flatMap for older Swift versions
            let end = index(after: start)
            defer { start = index(after: end) }
            return Byte(self[start...end], radix: 16)
        }
    }
    var hexaToBinary: String {
        return hexaToBytes.map {
            let binary = String($0, radix: 2)
            return repeatElement("0", count: 8-binary.count) + binary
        }.joined()
    }
}

// Hex to Uint8 Array
extension String {
    var hexaData: Data { .init(hexa) }
    var hexaBytes: [UInt8] { .init(hexa) }
    private var hexa: UnfoldSequence<UInt8, Index> {
        sequence(state: startIndex) { startIndex in
            guard startIndex < self.endIndex else { return nil }
            let endIndex = self.index(startIndex, offsetBy: 2, limitedBy: self.endIndex) ?? self.endIndex
            defer { startIndex = endIndex }
            return UInt8(self[startIndex..<endIndex], radix: 16)
        }
    }
}
