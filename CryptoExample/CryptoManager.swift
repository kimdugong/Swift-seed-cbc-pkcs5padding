//
//  CryptoManager.swift
//  CryptoExample
//
//  Created by Dugong on 2020/06/02.
//  Copyright © 2020 Dugong. All rights reserved.
//

import Foundation

struct CryptoManager {

    
    /// SEED-CBC 메시지 암호화
    /// - Parameters:
    ///   - message: 원문
    ///   - key: 비밀키
    ///   - iv: 초기화벡터
    /// - Returns: Base64로 인코딩된 암호문
    static func seedEncryption(message: String, key: String?, iv: String?) -> String {
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


    /// SEED-CBC 메시지 복호화
    /// - Parameters:
    ///   - message: Base64로 인코딩된 암호문
    ///   - key: 비밀키
    ///   - iv: 초기화벡터
    /// - Returns: 복호화된 원문
    static func seedDecryption(message: String, key: String?, iv: String?) -> String {
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


    /// 대칭키 생성
    /// - Returns:
    ///     - success: result Dictionary
    ///         - "privateKey": 비공개키
    ///         - "publicKey": 공개키
    ///         - "pubStringKey": 비공개키 Base64로 인코딩된 외부 표현형
    ///         - "privStringKey": 공개키 Base64로 인코딩된 외부 표현형
    ///     - failure: CFERROR
    ///
    static func createPK() -> Result<[AnyHashable: Any], CFError>{
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

        print("------public key info------")
        print(publicKey!)
        print(pubStringKey!)
        print((pubStringKey! as Data).base64EncodedString())
        print("------public key info------")

        print("------private key info------")
        print(privateKey!)
        print(privStringKey!)
        print((privStringKey! as Data).base64EncodedString())
        print("------private key info------")

        let result = [
            "privateKey": privateKey!,
            "publicKey": publicKey!,
            "pubStringKey": (pubStringKey! as Data).base64EncodedString(),
            "privStringKey": (privStringKey! as Data).base64EncodedString()
            ] as [AnyHashable: Any]

        return .success(result)
    }


    /// RSA 메시지 암호화
    /// - Parameters:
    ///   - message: 원문
    ///   - publicKey: 공개키
    /// - Returns: Base64로 인코딩된 암호문
    static func rsaEncryption(message: String, publicKey: SecKey) -> String {
        let blockSize = SecKeyGetBlockSize(publicKey)
        var messageEncrypted = [UInt8](repeating: 0, count: blockSize)
        var messageEncryptedSize = blockSize
        let result = SecKeyEncrypt(publicKey, .PKCS1, message, message.count, &messageEncrypted, &messageEncryptedSize)
        if result != noErr {
            print(result)
            fatalError("암호화 실패")
        }
        return Data(bytes: messageEncrypted, count: messageEncryptedSize).base64EncodedString()
    }


    /// RSA 메시지 복호화
    /// - Parameters:
    ///   - message: Base64로 인코딩된 자신의 공개키로 암호화된 암호문
    ///   - privateKey: 비공개키
    /// - Returns: 복호화된 원문
    static func rsaDecryption(message: String, privateKey: SecKey) -> String {
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
}
