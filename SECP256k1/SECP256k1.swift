//
//  SECP256k1.swift
//
//  Created by Boris Polania on 2/19/18.
//  Copyright © 2018 Boris Polania. All rights reserved.
//

import UIKit

class SECP256k1: NSObject {
    
    func privateKeyVerify(privateKey: Data) -> Bool {
        let bint = BDouble.init(privateKey.hexEncodedString(), radix: 16)
        if bint == nil || bint == 0 {
           return false
        }
        return true
    }
    
    func privateKeyExport (privateKey: Data) -> Data {
        if privateKeyVerify(privateKey: privateKey) {
            return privateKey
        } else {
            return Data()
        }
    }

}
