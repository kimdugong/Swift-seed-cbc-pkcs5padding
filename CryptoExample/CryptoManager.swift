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
    let inputUint8Pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: inputBytes.count)
    inputUint8Pointer.initialize(from: &inputBytes, count: inputBytes.count)

    var keyBytes = [UInt8](key)
    let keyUint8Pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: keyBytes.count)
    keyUint8Pointer.initialize(from: &keyBytes, count: keyBytes.count)

    var ivBytes = [UInt8](iv)
    let ivUint8Pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: ivBytes.count)
    ivUint8Pointer.initialize(from: &ivBytes, count: ivBytes.count)

    var outBytes = [UInt8](repeating: 0, count: Int(SEED_BLOCK_SIZE) + 1)

    let result = KISA_SEED_CBC_ENCRYPT(keyUint8Pointer, ivUint8Pointer, inputUint8Pointer, UInt32(inputBytes.count), &outBytes)

    if result == 0 {
        fatalError("암호화 실패")
    }
    return Data(bytes: outBytes, count: Int(result)).base64EncodedString()
}

func seedDecryption(message: String, key: String?, iv: String?) -> String {
    guard let input = message.data(using: .utf8), let inputData = Data(base64Encoded: input, options: .ignoreUnknownCharacters), let key = key?.data(using: .utf8), let iv = iv?.data(using: .utf8) else {
        fatalError("복호화 데이타가 적절하지 않음")
    }

    var inputBytes = [UInt8](inputData)
    let inputUint8Pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: inputBytes.count)
    inputUint8Pointer.initialize(from: &inputBytes, count: inputBytes.count)

    var keyBytes = [UInt8](key)
    let keyUint8Pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: keyBytes.count)
    keyUint8Pointer.initialize(from: &keyBytes, count: keyBytes.count)

    var ivBytes = [UInt8](iv)
    let ivUint8Pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: ivBytes.count)
    ivUint8Pointer.initialize(from: &ivBytes, count: ivBytes.count)

    var outBytes = [UInt8](repeating: 0, count: Int(SEED_BLOCK_SIZE) + 1)

    let result = KISA_SEED_CBC_DECRYPT(keyUint8Pointer, ivUint8Pointer, inputUint8Pointer, UInt32(inputBytes.count), &outBytes)

    if result == 0 {
        fatalError("복호화 실패")
    }

    guard let digest =  String(data: Data(bytes: outBytes, count: Int(result)), encoding: .utf8) else {
        fatalError("인코딩 에러")
    }
    return digest
}
