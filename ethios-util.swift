//
//  ethios-util.swift
//
//  Created by Boris Polania on 2/9/18.
//  Copyright © 2018 Boris Polania. All rights reserved.
//

import UIKit
import SwiftKeccak

class ethios_util: NSObject {
    
    /**
     * the max integer that this VM can handle (a BDouble)
     * @var BDouble MAX_INTEGER
     */
    let MAX_INTEGER = BDouble("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", radix:16)!
    
    /**
     * 2^256 (a BDouble)
     * @var BDouble TWO_POW256
     */
    let TWO_POW256 = BDouble("10000000000000000000000000000000000000000000000000000000000000000", radix:16)!
    
    /**
     * SHA3-256 hash of null (a String)
     * @var String SHA3_NULL_S
     */
    let SHA3_NULL_S = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    
    /**
     * SHA3-256 hash of null (a Data)
     * @var Data SHA3_NULL
     */
    var SHA3_NULL : Data
    
    /**
     * SHA3-256 of an RLP of an empty array (a String)
     * @var String SHA3_RLP_ARRAY_S
     */
    let SHA3_RLP_ARRAY_S = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
    
    /**
     * SHA3-256 of an RLP of an empty array (a Buffer)
     * @var Data SHA3_RLP_ARRAY
     */
    var SHA3_RLP_ARRAY : Data
    
    /**
     * SHA3-256 hash of the RLP of null  (a String)
     * @var String SHA3_RLP_S
     */
    let SHA3_RLP_S = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    
    /**
     * SHA3-256 hash of the RLP of null (a Buffer)
     * @var Data SHA3_RLP
     */
    var SHA3_RLP : Data
    
    override init() {
        SHA3_NULL = SHA3_NULL_S.hexadecimal()!
        SHA3_RLP_ARRAY = SHA3_RLP_ARRAY_S.hexadecimal()!
        SHA3_RLP = SHA3_RLP_S.hexadecimal()!
    }
    
    /**
     * Returns data filled with 0s
     * @method zeros
     * @param Int numberOfBytes the number of bytes the buffer should be
     * @return Data
     */
    func zeros(numberOfBytes: Int) -> Data {
        var data = Data(capacity: numberOfBytes)
        data.withUnsafeMutableBytes {(bytes: UnsafeMutablePointer<UInt8>)->Void in
            bytes.initialize(to: 0)
        }
        return data
    }
    
    /**
     * Returns a zero address
     * @method zeroAddress
     * @return String
     */
    func zeroAddress() -> String {
        let zeroAddress = zeros(numberOfBytes:20)
        return Format.hex(toString: zeroAddress)
    }
    
    /**
     * Pads a `Data` with zeros till it has `length` bytes.
     * @method setLength
     * @param Data msg the value to pad
     * @param Int length the number of bytes the output should be
     * @param Bool [right=false] whether to start padding form the left or right
     * @return Data
     */
    
    func setLength(msg: Data, length: Int, right: Bool) -> Data {
        var newMsg : Data
        let _zeros = zeros(numberOfBytes:length)
        if right {
            newMsg = msg
            newMsg.append(_zeros)
        } else {
            newMsg = _zeros
            newMsg.append(msg)
        }
        return newMsg
    }
    
    /**
     * Trims leading zeros from a `Data` object
     * @method trimZeroes
     * @param Data data to be trimmed
     * @return Data
     */
    
    func trimZeroes(data: Data) -> Data {
        var values = [UInt8](repeating:0, count:data.count)
        data.copyBytes(to: &values, count: data.count)
        var counter = 0
        for index in 0...values.count {
            if values[index] == 0 {
                counter += 1
            } else {
                break
            }
        }
        let range = Range(0..<counter)
        values.removeSubrange(range)
        return Data.init(bytes: values)
    }
    /**
     * Attempts to turn a value into a `Data` object. As input it supports `Data`, `String`, `Int`, `Double`, nil, `BigInt` and `BigDouble`.
     * @method convertToData
     * @param Any obj the value
     * @return Data
     */
    func convertToData(obj: Any?) -> Data? {
        if let isData = obj as? Data {
            return isData
        }
        else {
            if let isString = obj as? String {
                return isString.data(using: .utf8)!
            } else if var isInteger = obj as? Int {
                return Data(bytes: &isInteger, count: MemoryLayout.size(ofValue: isInteger))
            } else if var isDouble = obj as? Double {
                return Data(bytes: &isDouble, count: MemoryLayout.size(ofValue: isDouble))
            } else if var isFloat = obj as? Float {
                return Data(bytes: &isFloat, count: MemoryLayout.size(ofValue: isFloat))
            } else if obj == nil {
                return Data.init(count: 0)
            } else if var isBigInt = obj as? BInt {
                return Data(bytes: &isBigInt, count: MemoryLayout.size(ofValue: isBigInt))
            } else if var isBigDouble = obj as? BDouble {
                return Data(bytes: &isBigDouble, count: MemoryLayout.size(ofValue: isBigDouble))
            } else {
                return nil
            }
        }
    }
    
    /**
     * Converts `Data` to a BigInt
     * @method convertToBigInt
     * @param Data data
     * @return BInt
     */
    func convertToBigInt(data: Data) -> BInt {
        let hexString = data.hexEncodedString()
        return BInt.init(hexString, radix: 16)!
    }
    
    /**
     * Converts `Data` to a BigDouble
     * @method convertToBigDouble
     * @param Data data
     * @return BDouble
     */
    func convertToBigDouble(data: Data) -> BDouble {
        let hexString = data.hexEncodedString()
        return BDouble.init(hexString, radix: 16)!
    }
    
    /**
     * Converts a `Data` into a hex `String`
     * @method convertToHexString
     * @param Data data
     * @return String
     */
    func convertToHexString(data: Data) -> String {
        return data.hexEncodedString()
    }
    
    /**
     * Creates SHA-3 (keccak256) hash of the input
     * @method SHA3
     * @param Any (String | Data) as the input data
     * @return Data
     */
    func SHA3(input: Any) -> Data {
        if let isString = input as? String {
            return keccak256(isString)
        } else if let isData = input as? Data {
            return keccak256(isData)
        } else {
            return SHA3_NULL
        }
    }
    
    /**
     * Creates SHA256 hash of the input
     * @method SHA256
     * @param Data a the input data
     * @return Data
     */
    func SHA256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash)
    }
    
    /**
     * Creates RIPEMD160 hash of the input
     * @method RIPMED160
     * @param Any (String | Data) as the input data
     * @param Bool padded whether it should be padded to 256 bits or not
     * @return Data
     */
    func RIPMED160(input: Any, padded: Bool) -> Data {
        var md = RIPEMD160()
        if let isString = input as? String {
            let hash = SHA256(data: isString.data(using: .utf8)!)
            md.update(data: hash)
        } else if let isData = input as? Data {
            md.update(data: isData)
        }
        var final = md.finalize() //unpadded at this point
        if padded {
            final = setLength(msg: final, length: 32, right: true)
        }
        return final
    }
    
    /**
     * Creates SHA-3 hash of the RLP encoded version of the input
     * @method RLPHash
     * @param Any (String | Data) as the input data
     * @return Data
     */
    func RLPHash(input: Any) -> Data {
        return RLP.encode(SHA3(input: input))
    }
    
    /**
     * Checks if the private key satisfies the rules of the curve secp256k1.
     * @param {Buffer} privateKey
     * @return {Boolean}
     */
    
    

}

