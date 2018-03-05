//
//  SECP256k1.swift
//
//  Created by Boris Polania on 2/19/18.
//  Copyright © 2018 Boris Polania. All rights reserved.
//

import UIKit
import secp256k1

class SECP256k1: NSObject {
    
    // Keys
    var secp256k1Context : OpaquePointer
    var privateKey : UnsafePointer<UInt8>
    var publicKey = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity:64)
    
    init(privateKey: UnsafePointer<UInt8>) {
        secp256k1Context = secp256k1_context_create(UInt32(SECP256K1_FLAGS_TYPE_CONTEXT))
        self.privateKey = privateKey
    }
    
    /**
     * the max integer that can represent a Private Key (a BDouble)
     * @var BDouble MAX_INTEGER
     */
    let MAX_INTEGER = BDouble("ffffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", radix:16)!
    
    //mark: Keys
    func getPrivateKey() -> Data {
        let buffer = UnsafeBufferPointer(start: privateKey, count: 64);
        return Data(buffer: buffer)
    }
    
    func getPublicKey() -> Data {
        let buffer = UnsafeBufferPointer(start: publicKey, count: 64);
        return Data(buffer: buffer)
    }
    
    func setPrivateKey(privateKey: UnsafePointer<UInt8>) {
        self.privateKey = privateKey
    }
    
    func privateKeyVerify() -> Bool {
        let result = Int(secp256k1_ec_seckey_verify(secp256k1Context, privateKey)) as NSNumber
        return result.boolValue
    }
    
    func publicKeyCreate () -> Bool {
        if privateKeyVerify() {
            let result = Int(secp256k1_ec_pubkey_create(secp256k1Context, publicKey, privateKey)) as NSNumber
            return result.boolValue
        } else {
            return false
        }
    }
    
    func publicKeyParse(publicKey: Data, length: Int) -> Bool {
        var result = NSNumber.init(value: 0)
        _ = publicKey.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_pubkey_parse(secp256k1Context, self.publicKey, uint8Pointer, length)) as NSNumber
        }
        return result.boolValue
    }
    
    func publicKeyTweakAdd(tweak: Data) -> Bool {
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_pubkey_tweak_add(secp256k1Context, self.publicKey, uint8Pointer)) as NSNumber
        }
        return result.boolValue
    }
    
    func publicKeyTweakMul(tweak: Data) -> Bool {
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_pubkey_tweak_mul(secp256k1Context, self.publicKey, uint8Pointer)) as NSNumber
        }
        return result.boolValue
    }
    
    func privateKeyTweakAdd(tweak: Data) -> Bool {
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_privkey_tweak_add(secp256k1Context, UnsafeMutablePointer<UInt8>.init(mutating: self.privateKey), uint8Pointer)) as NSNumber
        }
        return result.boolValue
    }
    
    func privateKeyTweakMul(tweak: Data) -> Bool {
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_privkey_tweak_mul(secp256k1Context, UnsafeMutablePointer<UInt8>.init(mutating: self.privateKey), uint8Pointer)) as NSNumber
        }
        return result.boolValue
    }
    
    func publicKeyCombine(keysToCombine: [Data], numberOfKeys: Int) -> Bool {
        var result = NSNumber.init(value: 0)
        let data = NSKeyedArchiver.archivedData(withRootObject: keysToCombine)
        _ = data.withUnsafeBytes {(secp256k1PubkeyPointer: UnsafePointer<UnsafePointer<secp256k1_pubkey>?>) in
            result = Int(secp256k1_ec_pubkey_combine(secp256k1Context, self.publicKey, secp256k1PubkeyPointer, numberOfKeys)) as NSNumber
        }
        return result.boolValue
    }
    
    func publicKeyNegate() -> Bool {
        var result = NSNumber.init(value: 0)
        result = secp256k1_ec_pubkey_negate(secp256k1Context, self.publicKey) as NSNumber
        return result.boolValue
    }
    
    func privateKeyNegate() -> Bool {
        var result = NSNumber.init(value: 0)
        result = secp256k1_ec_privkey_negate(secp256k1Context, UnsafeMutablePointer<UInt8>.init(mutating: self.privateKey)) as NSNumber
        return result.boolValue
    }
    
    //mark: Signature
    func signatureNormalize(signatureToNormalize: Data) -> Data {
        let normalizedSignature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = signatureToNormalize.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            _ = Int(secp256k1_ecdsa_signature_normalize(secp256k1Context, normalizedSignature, secp256k1SignaturePointer)) as NSNumber
        }
        let buffer = UnsafeBufferPointer(start: normalizedSignature, count: 64);
        return Data(buffer: buffer)
    }
    
    func signatureDERSerialization(signatureToSerialize: Data) -> (Data,Data) {
        let serialization = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        let serializationLength = UnsafeMutablePointer<Int>.allocate(capacity: 8)
        _ = signatureToSerialize.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            _ = Int(secp256k1_ecdsa_signature_serialize_der(secp256k1Context, serialization, serializationLength, secp256k1SignaturePointer)) as NSNumber
        }
        let serializationBuffer = UnsafeBufferPointer(start: serialization, count: 64);
        let serializationLengthBuffer = UnsafeBufferPointer(start: serializationLength, count: 64);
        return (Data(buffer: serializationBuffer),Data(buffer: serializationLengthBuffer))
    }
    
    func signatureCompactSerialization(signatureToSerialize: Data) -> Data {
        let serialization = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        _ = signatureToSerialize.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            _ = Int(secp256k1_ecdsa_signature_serialize_compact(secp256k1Context, serialization, secp256k1SignaturePointer)) as NSNumber
        }
        let buffer = UnsafeBufferPointer(start: serialization, count: 64);
        return Data(buffer: buffer)
    }
    
    func signatureDERParsing(signatureToParse: Data, length: Int) -> Data {
        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = signatureToParse.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<UInt8>) in
            _ = Int(secp256k1_ecdsa_signature_parse_der(secp256k1Context, signature, secp256k1SignaturePointer, length)) as NSNumber
        }
        let buffer = UnsafeBufferPointer(start: signature, count: 64);
        return Data(buffer: buffer)
    }
    
    func signatureCompactParsing(signatureToParse: Data) -> Data {
        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = signatureToParse.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<UInt8>) in
            _ = Int(secp256k1_ecdsa_signature_parse_compact(secp256k1Context, signature, secp256k1SignaturePointer)) as NSNumber
        }
        let buffer = UnsafeBufferPointer(start: signature, count: 64);
        return Data(buffer: buffer)
    }
    
    func verifySignature(signatureToVerify: Data, message: Data) -> Bool {
        var result = NSNumber.init(value: 0)
        _ = signatureToVerify.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            _ = message.withUnsafeBytes {(messagePointer: UnsafePointer<UInt8>) in
                result = Int(secp256k1_ecdsa_verify(secp256k1Context, secp256k1SignaturePointer, messagePointer, self.publicKey)) as NSNumber
            }
        }
        return result.boolValue
    }
    
    func sign(message: Data, nonceGenerationFunction: secp256k1_nonce_function!, nonceGenerationData: Data) -> Data {
        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = message.withUnsafeBytes {(messagePointer: UnsafePointer<UInt8>) in
            _ = nonceGenerationData.withUnsafeBytes {(nonceGenerationDataPointer: UnsafePointer<UInt8>) in
                _ = Int(secp256k1_ecdsa_sign(secp256k1Context, signature, messagePointer, self.privateKey, nonceGenerationFunction, nonceGenerationDataPointer)) as NSNumber
            }
        }
        let buffer = UnsafeBufferPointer(start: signature, count: 64);
        return Data(buffer: buffer)
    }
}

