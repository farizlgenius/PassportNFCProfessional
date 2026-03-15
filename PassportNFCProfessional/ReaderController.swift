//
//  ReaderController.swift
//  PassportLib
//
//  Created by honorsupplying on 11/24/24.
//

import Foundation
import CryptoTokenKit

public protocol ReaderControllerDelegate {
    func onErrorOccur(errorMessage:String,isError:Bool)
}

public class ReaderController
{
    // Reader Controller Properties
    var mngr:TKSmartCardSlotManager?
    var card:TKSmartCard?
    var slot:TKSmartCardSlot?
    public var delegate:ReaderControllerDelegate?
    var isPassport:Bool
    
    public init(isPassport:Bool){
        mngr = TKSmartCardSlotManager.default
        self.isPassport = isPassport
    }
    
    public func initSmartCard() async ->Bool{
        let readerName = getReader()
        slot = await mngr?.getSlot(withName: readerName)
        if slot != nil {
//            print("LIB >>>> INIT SMART CARD SUCCESS")
            return true
        }
//        print("INIT SMART CARD UNSUCCESS")
        delegate?.onErrorOccur(errorMessage: "INIT SMART CARD UNSUCCESS", isError: true)
        return false
    }
    
    // get reader name
    public func getReader()->String{
        if (mngr?.slotNames.count)! > 0 {
            
//            if isPassport {
//                for reader in mngr!.slotNames {
//                    if reader == "Feitian R502   " {
//                        return "Feitian R502   "
//                    }
//                }
//                
//                print("LIB >>>> READER : " + (mngr?.slotNames[0])!)
//                //print(mngr?.slotNames)
//                return (mngr?.slotNames[0])!
//                
//            }else{
//                for reader in mngr!.slotNames {
//                    if reader == "Feitian SCR301" {
//                        return "Feitian SCR301"
//                    }
//                }
//                
//                print("LIB >>>> READER : " + (mngr?.slotNames[0])!)
//                //print(mngr?.slotNames)
//                return (mngr?.slotNames[0])!
//            }
            
            for reader in mngr!.slotNames {
                if reader == "Feitian R502   " {
                    return "Feitian R502   "
                }else if reader == "Circle CIR315 Dual" {
                    return "Circle CIR315 Dual"
                }
            }
            
//            print("LIB >>>> NO READER ATTACHED")
            delegate?.onErrorOccur(errorMessage: "NO READER ATTACHED", isError: true)
            return "No Reader"
            
        }else{
//            print("LIB >>>> NO READER ATTACHED")
            delegate?.onErrorOccur(errorMessage: "NO READER ATTACHED", isError: true)
            return "No Reader"
        }
    }
    
        
    // begin smart card session
    func beginCardSession() async -> Bool {
        card = slot!.makeSmartCard()
        if let card = card {
            do {
//                print("LIB >>>> BEGIN CARD SESSION SUCCESS")
                return try await card.beginSession()
            } catch {
//                print("LIB >>>> BEGIN CARD SESSION FAIL && NO CARD FOUND")
                //delegate?.onErrorOccur(errorMessage: "Begin Card Session Fail, No Smart Card Found", isError: true)
                return false
            }
        }else{
//            print("LIB >>>> MAKE SMART CARD SLOT FAIL")
            //delegate?.onErrorOccur(errorMessage: "Make Smart Card Slot Fail !!!", isError: true)
            return false
        }
        
    }
    
    // Transmit APDU to Card
    func transmitCardAPDU(card:TKSmartCard,apdu:String) async -> String {
        let data = NSData(bytes: apdu.hexaBytes, length: apdu.hexaData.count)
        do{
            let res = try await card.transmit(data as Data)
            return res.hexadecimal
        } catch {
            return "nil"
        }
    }
    
    // End Card Session
    func endCardSession(){
        if card != nil {
            card!.endSession()
            card = nil
            slot = nil
            //mngr = nil
//            print("LIB >>>> END CARD SESSION SUCCESS")
        }else{
//            print("LIB >>> END CARD SESSION FAIL")
        }
        
    }
}
