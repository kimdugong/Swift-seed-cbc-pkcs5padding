//
//  ContentView.swift
//  CryptoExample
//
//  Created by Dugong on 2020/06/01.
//  Copyright © 2020 Dugong. All rights reserved.
//

import SwiftUI

struct ContentView: View {
    @State private var symentricKey: String = ""
    @State private var base64iv: String = ""

    @State private var message: String = "this is very secret!"

    @State private var encMessage: String = ""
    @State private var decMessage: String = ""

    private let key: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    private let iv: [UInt8] = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]

    var body: some View {
        Form {
            Section {
                TextField("평문", text: $message)
            }
            Section (header: Text("seed-cbc 대칭키 암호화")){
                Button(action: {
                    self.symentricKey = Data(bytes: self.key, count: self.key.count).base64EncodedString()
                }) {
                    Text("1. 키인코딩 하기")
                }
                TextField("1. 키인코딩 하기 결과", text: $symentricKey)
                Button(action: {
                    self.base64iv = Data(bytes: self.iv, count: self.iv.count).base64EncodedString()
                }) {
                    Text("2. iv 인코딩하기")
                }
                TextField("2. iv 인코딩하기 결과", text: $base64iv)
                Button(action: {
                    self.encMessage = seedEncryption(message: self.message, key: self.symentricKey, iv: self.base64iv)
                }) {
                    Text("2. 대칭키로 암호화")
                }
                TextField("2. 대칭키로 암호화 결과", text: $encMessage)
                Button(action: {
                    self.decMessage = seedDecryption(message: self.encMessage, key: self.symentricKey, iv: self.base64iv)
                }) {
                    Text("3. 대칭키로 복호화")
                }
                TextField("3. 대칭키로 복호화 결과", text: $decMessage)
            }

            Section {
                Text("seed-cbc 대칭키 암호화")
                Button(action: {
                    print(self.symentricKey)
                }) {
                    Text("1. 키생성 하기")
                }
                TextField("1. 키생성 하기 결과", text: $symentricKey)
            }


            Section {
                Text("seed-cbc 대칭키 암호화")
                Button(action: {
                    print(self.symentricKey)
                }) {
                    Text("1. 키생성 하기")
                }
                TextField("1. 키생성 하기 결과", text: $symentricKey)
            }


            Section {
                Text("seed-cbc 대칭키 암호화")
                Button(action: {
                    print(self.symentricKey)
                }) {
                    Text("1. 키생성 하기")
                }
                TextField("1. 키생성 하기 결과", text: $symentricKey)
            }


            Section {
                Text("seed-cbc 대칭키 암호화")
                Button(action: {
                    print(self.symentricKey)
                }) {
                    Text("1. 키생성 하기")
                }
                TextField("1. 키생성 하기 결과", text: $symentricKey)
            }


        }

    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
