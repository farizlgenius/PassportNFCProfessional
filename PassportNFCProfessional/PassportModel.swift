//
//  PassportDataModel.swift
//  PassportLib
//
//  Created by Far-iz Lengha on 18/11/2567 BE.
//

import Foundation

public struct PassportModel{
    
    // DG1
    public var documentCode:String?
    public var issueState:String?
    public var holderFullName:String?
    public var holderFirstName:String?
    public var holderMiddleName:String?
    public var holderLastName:String?
    public var documentNumber:String?
    public var docNumCheckDigit:String?
    public var nationality:String?
    public var countryCode:String?
    public var dateOfBirth:String?
    public var dateOfBirthCheckDigit:String?
    public var sex:String?
    public var dateOfExpiry:String?
    public var dateOfExpiryCheckDigit:String?
    public var optionalData:String?
    public var compositeCheckDigit:String?
    
    // DG2
    public var faceImage:String?
    
    // DG7
    public var signatureImage:String?
    
    // DG11
    public var personalNumber:String?
    public var fullDateOfBirth:String?
    public var placeOfBirth:String?
    public var permanentAddress:String?
    public var telephone:String?
    public var profession:String?
    public var title:String?
    public var personelSummary:String?
    
    // DG12
    public var issuingAuthority:String?
    public var dateOfIssue:String?
    public var endorsements:String?
    public var imageOfFrontDoc:String?
    public var imageOfRearDoc:String?
    public var dateTimeDocPersonalization:String?
    public var serialNumberDocPersonalizationSystem:String?
    
    // Expire Flag
    public var expireFlag:String = "N"
    
}



