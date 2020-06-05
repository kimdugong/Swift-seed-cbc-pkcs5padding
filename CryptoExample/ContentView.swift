//
//  ContentView.swift
//  CryptoExample
//
//  Created by Dugong on 2020/06/01.
//  Copyright © 2020 Dugong. All rights reserved.
//

import SwiftUI

struct ContentView: View {
    @ObservedObject var keyboard = KeyboardResponder()

    // SEED-CBC
    @State private var base64Key: String = ""
    @State private var base64Iv: String = ""

    @State private var message1: String = "-SEED-CBC-MESSAGE-TEST"

    @State private var encMessage1: String = ""
    @State private var decMessage1: String = ""

    @State private var key = "[B@2a5ca609"
    @State private var iv = "INICISKPAYKEYIV."

    // RSA
    @State private var message2: String = "-RSA-MESSAGE-TEST-"

    @State private var encMessage2: String = ""
    @State private var decMessage2: String = ""

    @State private var privateKey: SecKey?
    @State private var publicKey: SecKey?
    @State private var pubKey: String = ""
    @State private var privKey: String = ""

    var body: some View {
        Form {
            seedCbcSection()
            rsaSection()
        }
        .padding(.bottom, keyboard.currentHeight)
        .animation(.easeOut(duration: keyboard.duration))
    }

    private func seedCbcSection() -> some View {
        Group {
            Section (header: Text("seed-cbc 대칭키 암호화")) {
                HStack {
                    Text("Message").foregroundColor(.gray)
                    TextField("평문", text: $message1)
                }
                HStack {
                    Text("SymentricKey").foregroundColor(.gray)
                    TextField("대칭키", text: $key)
                }
                HStack {
                    Text("InitializationVector").foregroundColor(.gray)
                    TextField("초기화벡터", text: $iv)
                }
            }
            Section {
                Button(action: {
                    self.base64Key = Data(bytes: self.key, count: self.key.count).base64EncodedString()
                }) {
                    Text("1. 키 인코딩 하기")
                }
                TextField("1. 키 인코딩 하기 결과", text: $base64Key)
                Button(action: {
                    self.base64Iv = Data(bytes: self.iv, count: self.iv.count).base64EncodedString()
                }) {
                    Text("2. iv 인코딩하기")
                }
                TextField("2. iv 인코딩하기 결과", text: $base64Iv)
                Button(action: {
                    self.encMessage1 = CryptoManager.seedEncryption(message: self.message1, key: self.base64Key, iv: self.base64Iv)
                }) {
                    Text("3. 대칭키로 암호화")
                }
                TextField("3. 대칭키로 암호화 결과", text: $encMessage1)
                Button(action: {
                    self.decMessage1 = CryptoManager.seedDecryption(message: self.encMessage1, key: self.base64Key, iv: self.base64Iv)
                }) {
                    Text("4. 대칭키로 복호화")
                }
                TextField("4. 대칭키로 복호화 결과", text: $decMessage1)
            }
        }
    }

    private func rsaSection() -> some View {
        Group{
            Section (header: Text("RSA 비대칭키 암호화")) {
                HStack {
                    Text("Message").foregroundColor(.gray)
                    TextField("평문", text: $message2)
                }
                HStack {
                    Text("PublicKey").foregroundColor(.gray)
                    TextField("공개키", text: $pubKey).font(.system(size: 8))
                }
                HStack {
                    Text("PrivateKey").foregroundColor(.gray)
                    TextField("비공개키", text: $privKey).font(.system(size: 8))
                }
            }
            Section {
                Button(action: {
                    let result = CryptoManager.createPK()
                    switch result {
                    case .success(let result):
                        guard let privKey = result["privateKey"], let pubKey = result["publicKey"],let pubStringKey = result["pubStringKey"] as? String, let privStringKey = result["privStringKey"] as? String else {
                            fatalError()
                        }
                        self.privateKey = (privKey as! SecKey)
                        self.publicKey = (pubKey as! SecKey)
                        self.pubKey = pubStringKey
                        self.privKey = privStringKey

                    case .failure(let error):
                        print(error)
                        break
                    }
                }) {
                    Text("1. 비대칭키 생성")
                }
                TextField("1. 공개키 결과", text: $pubKey)
                Button(action: {
                    guard let publicKey = self.publicKey else {
                        fatalError("공개키 없음")
                    }
                    self.encMessage2 = CryptoManager.rsaEncryption(message: self.message2, publicKey: publicKey)
                }) {
                    Text("2. 공개키 암호화")
                }
                TextField("2. 암호화 결과", text: $encMessage2)
                Button(action: {
                    guard let privateKey = self.privateKey else {
                        fatalError("공개키 없음")
                    }
                    self.decMessage2 = CryptoManager.rsaDecryption(message: self.encMessage2, privateKey: privateKey)
                }) {
                    Text("3. 개인키 복호화")
                }
                TextField("3. 복호화 결과", text: $decMessage2)
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
