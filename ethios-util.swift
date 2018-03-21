//
//  ethios-util.swift
//
//  Created by Boris Polania on 2/9/18.
//  Copyright © 2018 Boris Polania. All rights reserved.
//

import UIKit
import SwiftKeccak

class ethios_util: NSObject {
    
    enum utilError: Error {
        case failedToGeneratePublicFromPrivateKey
        case failedToGenerateAddressFromPrivateKey
        case failedToImportPublicKey
        case failedToSignMessage
        case failedToRecoverPublicKey
        case invalidRecoveryId
        case invalidSignatureLenght
    }
    
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
        SHA3_NULL = SHA3_NULL_S.hexadecimal
        SHA3_RLP_ARRAY = SHA3_RLP_ARRAY_S.hexadecimal
        SHA3_RLP = SHA3_RLP_S.hexadecimal
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
        return "0x" + Format.hex(toString: zeroAddress)
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
     * @param Data privateKey
     * @return Bool
     */
    func isPrivateKeyValid(privateKey: Data) -> Bool {
        let secp256k1 = SECP256k1()
        secp256k1.setPrivateKey(privateKey: privateKey)
        return secp256k1.privateKeyVerify()
    }
    
    /**
     * Checks if the public key satisfies the rules of the curve secp256k1
     * and the requirements of Ethereum.
     * @param Data publicKey data object
     * @return Bool
     */
    func isPublicKeyValid(publicKey: Data) -> Bool {
        let secp256k1 = SECP256k1()
        do {
            try secp256k1.publicKeyParse(publicKey: publicKey)
            return true
        } catch {
            return false
        }
    }
    
    /**
     * Returns the ethereum address of a given public key.
     * Accepts "Ethereum public keys" and SEC1 encoded keys.
     * @param Data pubKey
     * @return Data
     */
    func publicKeyToAddress(publicKey: Data) -> Data {
        var pub = publicKey
        pub.remove(at: pub.startIndex)
        var sha3 = self.SHA3(input: publicKey)
        sha3.remove(at: -20)
        return sha3
    }
    
    /**
     * Returns the ethereum public key of a given private key
     * @param Data privateKey A private key must be 256 bits wide
     * @throw utilError.failedToGeneratePublicFromPrivateKey if secp256k1.publicKeyCreate fails
     * @return Data
     */
    func getPublicFromPrivateKey(privateKey: Data) throws -> Data {
        let secp256k1 = SECP256k1()
        secp256k1.setPrivateKey(privateKey: privateKey)
        do {
            try secp256k1.publicKeyCreate()
            return secp256k1.getPublicKey()
        } catch {
            throw utilError.failedToGeneratePublicFromPrivateKey
        }
    }
    
    /**
     * Converts a public key to the Ethereum format.
     * @param Data publicKey
     * @return Data
     */
    func importPublicKey(publicKey: Data) throws -> Data {
        let secp256k1 = SECP256k1()
        do {
            try secp256k1.publicKeyParse(publicKey: publicKey)
            return secp256k1.getPublicKey()
        } catch {
            throw utilError.failedToImportPublicKey
        }
    }
    
    /**
     * ECDSA sign
     * @param Data message to be signed
     * @param Data privateKey
     * @throws utilError.failedToSignMessage
     * @return Data signed message
     */
    func ECSign(message: Data, privateKey: Data) throws -> Data {
        let secp256k1 = SECP256k1()
        secp256k1.setPrivateKey(privateKey: privateKey)
        do {
            let nonce = try secp256k1.generateNonce(lenght: 4)
            return try secp256k1.sign(message: message, nonceGenerationFunction: nil, nonceGenerationData: nonce)
        } catch {
            throw utilError.failedToSignMessage
        }
    }
    
    /**
     * Returns the keccak-256 hash of `message`, prefixed with the header used by the `eth_sign` RPC call.
     * The output of this function can be fed into `ecsign` to produce the same signature as the `eth_sign`
     * call for a given `message`, or fed to `ecrecover` along with a signature to recover the public key
     * used to produce the signature.
     * @param message Data object with the message to be hashed
     * @returns Data hashed message
     */
    func hashMessage(message: Data) -> Data {
        var prefix = Data("0019".hexadecimal)
        prefix.append("Ethereum Signed Message:\n".data(using: String.Encoding.utf8)!)
        prefix.append(String(message.count).data(using: String.Encoding.utf8)!)
        var result = Data(prefix)
        result.append(message)
        return result
    }
    
    /**
     * ECDSA public key recovery from signature
     * @param Data signature
     * @param Data message
     * @throws utilError.failedToRecoverPublicKey
     * @returns a Data object with publicKey
     */
    func publicKeyFromSignature(signature: Data, message: Data) throws -> Data {
        let secp256k1 = SECP256k1()
        do {
            return try secp256k1.recoverKeyFromSignature(signature: signature, message: message)
        } catch {
            throw utilError.failedToRecoverPublicKey
        }
    }
    
    /**
     * Convert signature parameters into the format of `eth_sign` RPC method
     * @param Int v
     * @param Data r
     * @param Data s
     * @throws utilError.invalidRecoveryId
     * @return Hex String with the signature
     */
    func convertSignatureToRPCFormat(v : Int, r : Data, s : Data) throws -> String {
        // NOTE: with potential introduction of chainId this might need to be updated
        if (v != 27 && v != 28) {
            throw utilError.invalidRecoveryId
        }
        // the RPC eth_sign method uses the 65 byte format used by Bitcoin
        // FIXME: this might change in the future - https://github.com/ethereum/go-ethereum/issues/2053
        var result = Data(self.setLength(msg: r, length: r.count, right: false))
        result.append(self.setLength(msg: s, length: s.count, right: false))
        result.append(self.convertToData(obj: (v-27))!)
        return result.hexString
    }
    
    /**
     * Convert signature format of the `eth_sign` RPC method to signature parameters
     * all because of a bug in geth: https://github.com/ethereum/go-ethereum/issues/2053
     * @param Data signature
     * @return [String : Any] dictionary
     */
    func convertSignatureFromRPCFormat(signature: Data) throws -> [String : Any] {
        // NOTE: with potential introduction of chainId this might need to be updated
        if (signature.count != 65) {
            throw utilError.invalidSignatureLenght
        }
        var v = signature[64]
        // support both versions of `eth_sign` responses
        if (v < 27) {
            v += 27
        }
        var sig = signature
        
        return [
            "v": v,
            "r": sig.removeSubrange(Range(32..<64)),
            "s": sig.removeSubrange(Range(0..<32))
        ]
    }
    
    /**
     * Returns the ethereum address of a given private key.
     * @param Data privateKey A private key must be 256 bits wide
     * @return Data object with the address
     */
    func privateKeyToAddress(privateKey: Data) throws -> Data {
        do {
            return try self.publicKeyToAddress(publicKey: self.getPublicFromPrivateKey(privateKey: privateKey))
        } catch {
            throw utilError.failedToGenerateAddressFromPrivateKey
        }
    }
    
    /**
     * Checks if the address is a valid. Accepts checksummed addresses too
     * @param String address
     * @return Boolean success/fail
     */
    func isAddressValid(address: String) -> Bool {
        let pattern = "0x[0-9a-fA-F]{40}$"
        if address.range(of: pattern, options: .regularExpression, range: nil, locale: nil) != nil {
            return true
        }
        return false
    }
    
    /**
     * Checks if a given address is a zero address
     * @method isZeroAddress
     * @param String address
     * @return Bool
     */
    func isZeroAddress(address: String) -> Bool {
        return self.zeroAddress() == self.addHexPrefix(string: address)
    }
    
    /**
     * Returns a checksummed address
     * @param String address
     * @return String checksummed address
     */
    func generateChecksumAddress(address: String) -> String {
        let addressWithoutPrefix = self.stripHexPrefix(string: address).lowercased()
        let hash = self.SHA3(input: addressWithoutPrefix)
        var result = "0x"
        
        for index in 0..<hash.count {
            if hash[index] >= 8 {
                result += String(addressWithoutPrefix[addressWithoutPrefix.index(addressWithoutPrefix.startIndex, offsetBy: index)]).uppercased()
            } else {
                result += String(addressWithoutPrefix[addressWithoutPrefix.index(addressWithoutPrefix.startIndex, offsetBy: index)])
            }
        }
        return result
    }
    
    /**
     * Checks if the address is a valid checksummed address
     * @param Data the address to verify
     * @return Bool
     */
    func isValidChecksumAddress(address: String) -> Bool {
        return self.isAddressValid(address: address) && self.generateChecksumAddress(address: address) == address
    }
    
    /**
     * Generates an address of a newly created contract
     * @param Data from the address which is creating this new address
     * @param Data nonce the nonce of the from account
     * @return Data
     */
    func generateAddress(from: String, nonce: String) -> Data {
        // in RLP we want to encode null in the case of zero nonce
        // read the RLP documentation for an answer if you dare
        let _from = from.hexadecimal
        let _nonce = BDouble(nonce, radix:16)
        var nonceData = nonce.hexadecimal
        if (_nonce?.isZero())! {
            nonceData = Data()
        }
        // Only take the lower 160bits of the hash
        let rlphash = self.RLPHash(input: [_from,nonceData])
        return rlphash.subdata(in: Range(rlphash.count - 20..<rlphash.count))
    }
    
    /**
     * Returns true if the supplied address belongs to a precompiled account
     * @param String address
     * @return Bool
     */
    func isAddressPrecompiled(address: String) -> Bool {
        let a = self.trimZeroes(data: address.hexadecimal)
        return a.count == 1 && a[0] > 0 && a[0] < 5
    }
    
    /**
     * Checks if a string does not already start with "0x"
     * @param String string
     * @return Bool
     */
    func isHexPrefixed(string: String) -> Bool {
        let start = String.Index(encodedOffset: 0)
        let end = string.index(string.startIndex, offsetBy: 2)
        if String(string[start..<end]) == "0x" {
            return true
        }
        return  false
    }
    
    /**
     * Adds "0x" to a given `String` if it does not already start with "0x"
     * @param String str
     * @return String
     */
    func addHexPrefix(string: String) -> String {
        return self.isHexPrefixed(string:string) ? string : "0x" + string
    }
    
    /**
     * Validate ECDSA signature
     * @param Data v
     * @param Data r
     * @param Data s
     * @param Bool homestead
     * @return Bool
     */
    func isValidSignature(v : Int, r : Data, s : Data, homestead : Bool) -> Bool {
        let SECP256K1_N_DIV_2 = BDouble("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", radix:16)
        let SECP256K1_N = BDouble("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", radix:16)
        if (r.count != 32 || s.count != 32) {
            return false
        }
        if (v != 27 && v != 28) {
            return false
        }
        let _r = BDouble(r.hexString, radix: 16)
        let _s = BDouble(s.hexString, radix: 16)
        if (_r!.isZero() || _r! > SECP256K1_N! || _s!.isZero() || _s! > SECP256K1_N!) {
            return false
        }
        if ((homestead == false) && (_s! > SECP256K1_N_DIV_2!)) {
            return false
        }
        return true
    }
    
    /**
     * Converts a `Data` object to JSON
     * @param Data data
     * @return JSON Object
     */
    func dataToJSON(data: Data) -> Any! {
        return try? JSONSerialization.jsonObject(with: data, options: [])
    }
    
    /**
     * Removes "0x" from a given `String` if it starts with "0x"
     * @param String str
     * @return String
     */
    func stripHexPrefix(string: String) -> String {
        let start = String.Index(encodedOffset: 0)
        let end = string.index(string.startIndex, offsetBy: string.count)
        return self.isHexPrefixed(string:string) ? String(string[start..<end]) : string
    }
    
}

