//
//  CryptoManager.swift
//  CryptoExample
//
//  Created by Dugong on 2020/06/02.
//  Copyright © 2020 Dugong. All rights reserved.
//

import Foundation

func seedEncryption(message: String, key: String?, iv: String?) -> String {
    guard let input = message.data(using: .utf8), let key = key?.data(using: .utf8), let iv = iv?.data(using: .utf8) else {
        fatalError("암호화 데이타가 적절하지 않음")
    }
    var inputBytes = [UInt8](input)
    var keyBytes = [UInt8](key)
    var ivBytes = [UInt8](iv)

    var outBytes = [UInt8](repeating: 0, count: inputBytes.count + Int(SEED_BLOCK_SIZE))

    let outlen = KISA_SEED_CBC_ENCRYPT(&keyBytes, &ivBytes, &inputBytes, UInt32(inputBytes.count), &outBytes)

    if outlen == 0 {
        fatalError("암호화 실패")
    }

    return Data(bytes: outBytes, count: Int(outlen)).base64EncodedString()
}

func seedDecryption(message: String, key: String?, iv: String?) -> String {
    guard let input = message.data(using: .utf8), let inputData = Data(base64Encoded: input, options: .ignoreUnknownCharacters), let key = key?.data(using: .utf8), let iv = iv?.data(using: .utf8) else {
        fatalError("복호화 데이타가 적절하지 않음")
    }

    var inputBytes = [UInt8](inputData)
    var keyBytes = [UInt8](key)
    var ivBytes = [UInt8](iv)

    var outBytes = [UInt8](repeating: 0, count: input.count + Int(SEED_BLOCK_SIZE))

    let outlen = KISA_SEED_CBC_DECRYPT(&keyBytes, &ivBytes, &inputBytes, UInt32(inputBytes.count), &outBytes)

    if outlen == 0 {
        fatalError("복호화 실패")
    }

    guard let decMessage =  String(data: Data(bytes: outBytes, count: Int(outlen)), encoding: .utf8) else {
        fatalError("인코딩 에러")
    }
    print(decMessage)
    return decMessage
}

func getHexaString(bytes: [UInt8]) -> String {
    return bytes.map({ String(format: "%02X", $0)}).joined()
}

func createPK() -> Result<[AnyHashable: Any], CFError>{
    var error: Unmanaged<CFError>?

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 1024
    ]

    let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    if error != nil {
        return .failure(error as! CFError)
    }

    let publicKey = SecKeyCopyPublicKey(privateKey!)

    let pubStringKey = SecKeyCopyExternalRepresentation(publicKey!, &error)
    if error != nil {
        return .failure(error as! CFError)
    }

    let privStringKey = SecKeyCopyExternalRepresentation(privateKey!, &error)
    if error != nil {
        return .failure(error as! CFError)
    }

    let result = [
        "privateKey": privateKey!,
        "publicKey": publicKey!,
        "pubStringKey": (pubStringKey! as Data).base64EncodedString(),
        "privStringKey": (privStringKey! as Data).base64EncodedString()
        ] as [AnyHashable: Any]

    print(result)
    return .success(result)
}


func rsaEncryption(message: String, publicKey: SecKey) -> String {
    let blockSize = SecKeyGetBlockSize(publicKey)
    var messageEncrypted = [UInt8](repeating: 0, count: blockSize)
    var messageEncryptedSize = blockSize
    let result = SecKeyEncrypt(publicKey, .PKCS1, message, message.count, &messageEncrypted, &messageEncryptedSize)
    if result != noErr {
        fatalError("암호화 실패")
    }
    return Data(bytes: messageEncrypted, count: messageEncryptedSize).base64EncodedString()
}

func rsaDecryption(message: String, privateKey: SecKey) -> String {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        fatalError("publickey 추론 실패")
    }

    guard let input = message.data(using: .utf8), let inputData = Data(base64Encoded: input, options: .ignoreUnknownCharacters) else {
        fatalError("복호화 데이타가 적절하지 않음")
    }

    var inputBytes = [UInt8](inputData)
    let blockSize = SecKeyGetBlockSize(publicKey)
    var messageDecrypted = [UInt8](repeating: 0, count: blockSize)
    var messageDecryptedSize = blockSize
    let result = SecKeyDecrypt(privateKey, .PKCS1, &inputBytes, inputBytes.count, &messageDecrypted, &messageDecryptedSize)

    if result != noErr {
        fatalError("암호화 실패")
    }

    guard let decMessage =  String(data: Data(bytes: messageDecrypted, count: messageDecryptedSize), encoding: .utf8) else {
        fatalError("인코딩 에러")
    }
    print(decMessage)
    return decMessage
}
