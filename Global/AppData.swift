//
//  AppData.swift
//  PassportNFCProfessional
//
//  Created by honorsupplying on 6/2/26.
//
import Foundation

final class AppData{
    static let shared = AppData()

        private init() {}
    
     var progress:Float = 0.0
     var eachProgress:Float = 0.0
}
