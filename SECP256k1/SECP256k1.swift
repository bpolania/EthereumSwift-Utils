//
//  SECP256k1.swift
//
//  Created by Boris Polania on 2/19/18.
//  Copyright © 2018 Boris Polania. All rights reserved.
//

import UIKit
import secp256k1

class SECP256k1: NSObject {
    
    var secp256k1Context : OpaquePointer
    var privateKey = UnsafePointer<UInt8>.init(bitPattern: 0)!
    var publicKey = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity:64)
    
    enum contextError: Error {
        case contextRandomizeFailed
        case contextRandomizeFailedWrongSeedSize
    }
    
    enum keyError: Error {
        case keyVerificationFailed
        case keyCreationFailed
        case keyParsingFailed
        case keyParsingFailedWrongKeySize
        case keyParsingFailedWrongHeader
        case keyCombinationFailed
        case keyNegationFailed
        case keyRecoveryFailed
        case tweakFailed
        case tweakFailedWrongTweakSize
    }
    
    enum signatureError: Error {
        case signatureNormalizationAlreadyNormalized
        case signatureSerializationFailed
        case signatureParsingFailed
        case signatureVerificationFailed
        case signingFailed
        case signingFailedWrongMessageSize
    }
    
    enum nonceError: Error {
        case nonceGenerationError
    }
    
    /**
     
     Initialize the class with a SECP256k1 context with the SECP256K1_CONTEXT_NONE flag.
     
     */
    override init() {
        secp256k1Context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))
    }
    
    //mark: Context
    
    /**
     
     - Parameter flag:  Int with which parts of the context to initialize.
     The possible values are `SECP256K1_CONTEXT_VERIFY`,
     `SECP256K1_CONTEXT_SIGN` and `SECP256K1_CONTEXT_NONE`
     
     */
    func createContext(flag: Int) {
        secp256k1Context = secp256k1_context_create(UInt32((flag)))
    }
    
    /**
     
     - Parameter context:  OpaquePointer a SECP256k1 context
     
     */
    func setContext(context: OpaquePointer) {
        secp256k1Context = context
    }
    
    /**
     
     - Return: the current context
     
     */
    func getContext() -> OpaquePointer {
        return secp256k1Context
    }
    
    /**
     
     Copies a secp256k1 context object.
     
     - Returns: an OpaquePointer with a clone of the Context
     
     */
    func cloneContext() -> OpaquePointer {
        return secp256k1_context_clone(secp256k1Context)
    }
    
    /**
     
     Destroy a secp256k1 context object.
     
     - Parameter context: the context to be destroyed
     
     */
    func destroyContext(context: OpaquePointer) {
        secp256k1_context_destroy(context)
    }
    
    /**
     
     Updates the context randomization to protect against side-channel leakage.
     
     While secp256k1 code is written to be constant-time no matter what secret
     values are, it's possible that a future compiler may output code which isn't,
     and also that the CPU may not emit the same radio frequencies or draw the same
     amount power for all values.
     
     This function provides a seed which is combined into the blinding value: that
     blinding value is added before each multiplication (and removed afterwards) so
     that it does not affect function results, but shields against attacks which
     rely on any input-dependent behaviour.
     
     You should call this after initialization, `createNewContext` or
     `cloneContext`, and may call this repeatedly afterwards.
     
     - Parameter seed: 32-byte random seed
     
     - Throws: contextError.contextRandomizeFailed if the `secp256k1_context_randomize` returns 0
     - Throws: throw contextError.contextRandomizeFailedWrongSeedSize if the seed size is greater than 32 bytes
     
     */
    func contextRandomize(seed: Data) throws {
        if seed.count > 32 {
            throw contextError.contextRandomizeFailedWrongSeedSize
        }
        var result = NSNumber.init(value: 0)
        _ = seed.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_context_randomize(secp256k1Context, uint8Pointer)) as NSNumber
        }
        if !result.boolValue {
            throw contextError.contextRandomizeFailed
        }
    }
    
    //mark: Keys
    
    /**
     
     Gets the Private Key as a Swift Data Object
     
     - Returns: a Data object with the private key
     
     */
    func getPrivateKey() -> Data {
        let buffer = UnsafeBufferPointer(start: privateKey, count: 64);
        return Data(buffer: buffer)
    }
    
    /**
     
     Sets the Private Key
     
     - Parameter privateKey: a Data object with the private key
     
     */
    func setPrivateKey(privateKey: Data) {
        _ = privateKey.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            self.privateKey = uint8Pointer
        }
    }
    
    /**
     
     Gets the Public Key as a Swift Data Object
     
     - Returns: a Data object with the private key
     
     */
    func getPublicKey() -> Data {
        let buffer = UnsafeBufferPointer(start: publicKey, count: 64);
        return Data(buffer: buffer)
    }
    
    /**
     
     Verify an ECDSA private key.
     
     - Throws: keyError.keyVerificationFailed if function `secp256k1_ec_seckey_verify` returns 0
     
     */
    func privateKeyVerify() -> Bool {
        let result = Int(secp256k1_ec_seckey_verify(secp256k1Context, privateKey)) as NSNumber
        if !result.boolValue {
            return false
        }
        return true
    }
    
    /**
     
     Compute the public key for a secret key and stores it in the `publicKey` property
     if function `secp256k1_ec_pubkey_create` returns 1
     
     - Throws: keyError.keyVerificationFailed if function `secp256k1_ec_pubkey_create` returns 0
     
     */
    func publicKeyCreate() throws {
        let isPrivateKeyValid = privateKeyVerify()
        if isPrivateKeyValid {
            let result = Int(secp256k1_ec_pubkey_create(secp256k1Context, publicKey, privateKey)) as NSNumber
            if !result.boolValue {
                throw keyError.keyCreationFailed
            }
        }
    }
    
    /**
     
     Parse a variable-length public key and stores it in `publicKey`
     if function `secp256k1_ec_pubkey_parse` returns 1
     
     This function supports parsing compressed (33 bytes, header byte 0x02 or
     0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes, header
     byte 0x06 or 0x07) format public keys.
     
     - Parameter publicKey: the public key to be parsed
     - Parameter length: the length of the public key to be parsed
     
     - Throws:  keyError.keyParsingFailed if function `secp256k1_ec_pubkey_parse` returns 0
     - Throws:  keyError.keyParsingFailedWrongKeySize if `publicKey` size is not either 33 or 65
     - Throws:  keyError.keyParsingFailedWrongHeader if `publicKey` size is 33 bytes and the
     first byte (header) is not either 0x02 or 0x03 or if `publicKey` size is 65 bytes
     and the first byte is not either 0x04, 0x06 or 0x07.
     
     */
    func publicKeyParse(publicKey: Data) throws {
        let header = publicKey[0]
        if publicKey.count == 33 {
            if header != 0x02 || header != 0x03 {
                throw keyError.keyParsingFailedWrongHeader
            }
        } else if publicKey.count == 65 {
            if header != 0x04 || header != 0x06 || header != 0x07 {
                throw keyError.keyParsingFailedWrongHeader
            }
        } else {
            throw keyError.keyParsingFailedWrongKeySize
        }
        
        var result = NSNumber.init(value: 0)
        _ = publicKey.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_pubkey_parse(secp256k1Context, self.publicKey, uint8Pointer, publicKey.count)) as NSNumber
        }
        if !result.boolValue {
            throw keyError.keyParsingFailed
        }
    }
    
    /**
     
     Tweak a public key by adding tweak times the generator to it.
     
     - Parameter tweak: a 32-byte Data object
     
     - Throws:  keyError.tweakFailed if the the tweak was out of range (chance of around 1 in 2^128 for
     uniformly random 32-byte arrays, or if the resulting public key would be invalid (only
     when the tweak is the complement of the corresponding private key).
     - Throws:  keyError.tweakFailedWrongTweakSize if the tweak size is different from 32 bytes
     
     */
    func publicKeyTweakAdd(tweak: Data) throws {
        if tweak.count != 32 {
            throw keyError.tweakFailedWrongTweakSize
        }
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_pubkey_tweak_add(secp256k1Context, self.publicKey, uint8Pointer)) as NSNumber
        }
        if !result.boolValue {
            throw keyError.tweakFailed
        }
    }
    
    /**
     
     Tweak a public key by multiplying it by a tweak value.
     
     - Parameter tweak: a 32-byte Data object
     
     - Throws:  keyError.tweakFailed if the tweak was out of range (chance of around 1 in 2^128 for
     uniformly random 32-byte arrays, or equal to zero.
     - Throws:  keyError.tweakFailedWrongTweakSize if the tweak size is different from 32 bytes
     
     */
    func publicKeyTweakMul(tweak: Data) throws {
        if tweak.count != 32 {
            throw keyError.tweakFailedWrongTweakSize
        }
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_pubkey_tweak_mul(secp256k1Context, self.publicKey, uint8Pointer)) as NSNumber
        }
        if !result.boolValue {
            throw keyError.tweakFailed
        }
    }
    
    /**
     
     Tweak a private key by adding tweak to it.
     
     - Parameter tweak: a 32-byte Data object
     
     - Throws:  keyError.tweakFailed if the tweak was out of range (chance of around 1 in 2^128 for
     uniformly random 32-byte arrays, or if the resulting private key would be invalid
     (only when the tweak is the complement of the private key).
     - Throws:  keyError.tweakFailedWrongTweakSize if the tweak size is different from 32 bytes
     
     */
    func privateKeyTweakAdd(tweak: Data) throws {
        if tweak.count != 32 {
            throw keyError.tweakFailedWrongTweakSize
        }
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_privkey_tweak_add(secp256k1Context, UnsafeMutablePointer<UInt8>.init(mutating: self.privateKey), uint8Pointer)) as NSNumber
        }
        if !result.boolValue {
            throw keyError.tweakFailed
        }
    }
    
    
    /**
     
     Tweak a private key by multiplying it by a tweak.
     
     - Parameter: tweak a 32-byte Data object
     
     - Throws:  keyError.tweakFailed if the tweak was out of range (chance of around 1 in 2^128 for
     uniformly random 32-byte arrays, or equal to zero.
     - Throws:  keyError.tweakFailedWrongTweakSize if the tweak size is different from 32 bytes
     
     */
    func privateKeyTweakMul(tweak: Data) throws {
        if tweak.count != 32 {
            throw keyError.tweakFailedWrongTweakSize
        }
        var result = NSNumber.init(value: 0)
        _ = tweak.withUnsafeBytes {(uint8Pointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ec_privkey_tweak_mul(secp256k1Context, UnsafeMutablePointer<UInt8>.init(mutating: self.privateKey), uint8Pointer)) as NSNumber
        }
        if !result.boolValue {
            throw keyError.tweakFailed
        }
    }
    
    /**
     
     Add a number of public keys together.
     
     - Parameter keysToCombine: a 32-byte Data object
     
     - Throws:  keyError.keyCombinationFailed if the sum of the public keys is not valid
     
     */
    func publicKeyCombine(keysToCombine: [Data]) throws {
        var result = NSNumber.init(value: 0)
        let data = NSKeyedArchiver.archivedData(withRootObject: keysToCombine)
        _ = data.withUnsafeBytes {(secp256k1PubkeyPointer: UnsafePointer<UnsafePointer<secp256k1_pubkey>?>) in
            result = Int(secp256k1_ec_pubkey_combine(secp256k1Context, self.publicKey, secp256k1PubkeyPointer, keysToCombine.count)) as NSNumber
        }
        if !result.boolValue {
            throw keyError.keyCombinationFailed
        }
    }
    
    /**
     
     Negates a public key in place.
     
     - Throws:  keyError.keyCombinationFailed if the negation fails
     
     */
    func publicKeyNegate() throws {
        var result = NSNumber.init(value: 0)
        result = secp256k1_ec_pubkey_negate(secp256k1Context, self.publicKey) as NSNumber
        if !result.boolValue {
            throw keyError.keyNegationFailed
        }
    }
    
    /**
     
     Negates a private key in place.
     
     - Throws:  keyError.keyCombinationFailed if the negation fails
     
     */
    func privateKeyNegate() throws {
        var result = NSNumber.init(value: 0)
        result = secp256k1_ec_privkey_negate(secp256k1Context, UnsafeMutablePointer<UInt8>.init(mutating: self.privateKey) ) as NSNumber
        if !result.boolValue {
            throw keyError.keyNegationFailed
        }
    }
    
    //mark: Signature
    
    /**
     
     Convert a signature to a normalized lower-S form.
     
     With ECDSA a third-party can forge a second distinct signature of the same
     message, given a single initial signature, but without knowing the key. This
     is done by negating the S value modulo the order of the curve, 'flipping'
     the sign of the random point R which is not included in the signature.
     
     Forgery of the same message isn't universally problematic, but in systems
     where message malleability or uniqueness of signatures is important this can
     cause issues. This forgery can be blocked by all verifiers forcing signers
     to use a normalized form.
     
     The lower-S form reduces the size of signatures slightly on average when
     variable length encodings (such as DER) are used and is cheap to verify,
     making it a good choice. Security of always using lower-S is assured because
     anyone can trivially modify a signature after the fact to enforce this
     property anyway.
     
     The lower S value is always between 0x1 and
     0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
     inclusive.
     
     No other forms of ECDSA malleability are known and none seem likely, but
     there is no formal proof that ECDSA, even with this additional restriction,
     is free of other malleability. Commonly used serialization schemes will also
     accept various non-unique encodings, so care should be taken when this
     property is required for an application.
     
     The `sign` function will by default create signatures in the
     lower-S form, and `verifySignature` will not accept others. In case
     signatures come from a system that cannot enforce this property,
     this `signatureNormalize` must be called before verification.
     
     - Parameter signatureToNormalize:  a Data object with the signature to check/normalize.
     
     - Throws:  signatureError.signatureNormalizationAlreadyNormalized if the signature
     was already normalized.
     
     - Returns: a Data object with the normalized form of the signature.
     
     */
    func signatureNormalize(signatureToNormalize: Data) throws -> Data {
        var result = NSNumber.init(value: 0)
        let normalizedSignature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = signatureToNormalize.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            result = Int(secp256k1_ecdsa_signature_normalize(secp256k1Context, normalizedSignature, secp256k1SignaturePointer)) as NSNumber
        }
        if !result.boolValue {
            throw signatureError.signatureNormalizationAlreadyNormalized
        }
        let buffer = UnsafeBufferPointer(start: normalizedSignature, count: 64)
        return Data(buffer: buffer)
    }
    
    /**
     
     Serialize an ECDSA signature in DER format.
     
     - Parameter signatureToSerialize:  a Data object with the signature to serialize.
     
     - Throws:  signatureError.signatureSerializationFailed if the wasn't enough space
     to serialize.
     
     - Returns: a Data tuple with the DER serialization and the length of output.
     
     */
    func signatureDERSerialization(signatureToSerialize: Data) throws -> (Data,Data) {
        var result = NSNumber.init(value: 0)
        let serialization = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        let serializationLength = UnsafeMutablePointer<Int>.allocate(capacity: 8)
        _ = signatureToSerialize.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            result = Int(secp256k1_ecdsa_signature_serialize_der(secp256k1Context, serialization, serializationLength, secp256k1SignaturePointer)) as NSNumber
        }
        let serializationBuffer = UnsafeBufferPointer(start: serialization, count: 64)
        let serializationLengthBuffer = UnsafeBufferPointer(start: serializationLength, count: 64)
        if !result.boolValue {
            throw signatureError.signatureSerializationFailed
        }
        return (Data(buffer: serializationBuffer),Data(buffer: serializationLengthBuffer))
    }
    
    
    /**
     
     Serialize an ECDSA signature in compact (64 byte) format.
     
     See `signatureCompactParsing` for details about the encoding.
     
     - Parameter signatureToSerialize:  a Data object with the signature to serialize.
     
     - Throws:  signatureError.signatureSerializationFailed if the wasn't enough space
     to serialize.
     
     - Returns: a Data object with the 64-byte compact serialization.
     
     */
    func signatureCompactSerialization(signatureToSerialize: Data) throws -> Data {
        var result = NSNumber.init(value: 0)
        let serialization = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        _ = signatureToSerialize.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            result = Int(secp256k1_ecdsa_signature_serialize_compact(secp256k1Context, serialization, secp256k1SignaturePointer)) as NSNumber
        }
        let buffer = UnsafeBufferPointer(start: serialization, count: 64)
        if !result.boolValue {
            throw signatureError.signatureSerializationFailed
        }
        return Data(buffer: buffer)
    }
    
    /**
     
     Parse a DER ECDSA signature.
     
     This function will accept any valid DER encoded signature, even if the
     encoded numbers are out of range.
     
     After the call, sig will always be initialized. If parsing failed or the
     encoded numbers are out of range, signature validation with it is
     guaranteed to fail for every message and public key.
     
     - Parameter signatureToParse:  a Data object with the signature to be parsed.
     
     - Throws:  signatureError.signatureParsingFailed if the signature the
     signature couldn't be parsed.
     
     - Returns: a Data object with the parsed signature.
     
     */
    func signatureDERParsing(signatureToParse: Data) throws -> Data {
        var result = NSNumber.init(value: 0)
        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = signatureToParse.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ecdsa_signature_parse_der(secp256k1Context, signature, secp256k1SignaturePointer, signatureToParse.count)) as NSNumber
        }
        if !result.boolValue {
            throw signatureError.signatureParsingFailed
        }
        let buffer = UnsafeBufferPointer(start: signature, count: 64)
        return Data(buffer: buffer)
    }
    
    /**
     
     Parse an ECDSA signature in compact (64 bytes) format.
     
     The signature must consist of a 32-byte big endian R value, followed by a
     32-byte big endian S value. If R or S fall outside of [0..order-1], the
     encoding is invalid. R and S with value 0 are allowed in the encoding.
     
     After the call, sig will always be initialized. If parsing failed or R or
     S are zero, the resulting sig value is guaranteed to fail validation for any
     message and public key.
     
     - Parameter signatureToParse:  a Data object with the signature to be parsed.
     
     - Throws:  signatureError.signatureParsingFailed if the signature the
     signature couldn't be parsed.
     
     - Returns: a Data object with the parsed signature.
     
     */
    func signatureCompactParsing(signatureToParse: Data) throws -> Data {
        var result = NSNumber.init(value: 0)
        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = signatureToParse.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<UInt8>) in
            result = Int(secp256k1_ecdsa_signature_parse_compact(secp256k1Context, signature, secp256k1SignaturePointer)) as NSNumber
        }
        let buffer = UnsafeBufferPointer(start: signature, count: 64)
        if !result.boolValue {
            throw signatureError.signatureParsingFailed
        }
        return Data(buffer: buffer)
    }
    
    /**
     
     Verify an ECDSA signature.
     
     To avoid accepting malleable signatures, only ECDSA signatures in lower-S
     form are accepted.
     
     If you need to accept ECDSA signatures from sources that do not obey this
     rule, `signatureNormalize` to the signature prior to
     validation, but be aware that doing so results in malleable signatures.
     
     For details, see the comments for that function.
     
     - Parameter signatureToVerify:  a Data object with the signature being verified.
     
     - Throws:  signatureError.signatureParsingFailed if the signature is incorrect or
     unparseable
     
     */
    func verifySignature(signatureToVerify: Data, message: Data) throws {
        var result = NSNumber.init(value: 0)
        _ = signatureToVerify.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_signature>) in
            _ = message.withUnsafeBytes {(messagePointer: UnsafePointer<UInt8>) in
                result = Int(secp256k1_ecdsa_verify(secp256k1Context, secp256k1SignaturePointer, messagePointer, self.publicKey)) as NSNumber
            }
        }
        if !result.boolValue {
            throw signatureError.signatureVerificationFailed
        }
    }
    
    /**
     
     Create an ECDSA signature.
     
     The created signature is always in lower-S form. See
     `signatureNormalize` for more details.
     
     - Parameter message:  a Data object with the 32-byte message hash being signed .
     - Parameter nonceGenerationFunction:   a nonce generation function. If NULL, `secp256k1_nonce_function_default`
     is used. The two possible values are `secp256k1_nonce_function_default`
     and `secp256k1_nonce_function_rfc6979`
     - Parameter nonceGenerationData: a Data object with arbitrary data used by the nonce generation function.
     
     - Throws: signatureError.signingFailed if the nonce generation function failed, or the private key was invalid.
     
     - Returns: a Data object with the signature.
     
     */
    func sign(message: Data, nonceGenerationFunction: secp256k1_nonce_function!, nonceGenerationData: Data) throws -> Data {
        if message.count != 32 {
            throw signatureError.signingFailedWrongMessageSize
        }
        var result = NSNumber.init(value: 0)
        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 64)
        _ = message.withUnsafeBytes {(messagePointer: UnsafePointer<UInt8>) in
            _ = nonceGenerationData.withUnsafeBytes {(nonceGenerationDataPointer: UnsafePointer<UInt8>) in
                result = Int(secp256k1_ecdsa_sign(secp256k1Context, signature, messagePointer, self.privateKey, nonceGenerationFunction, nonceGenerationDataPointer)) as NSNumber
            }
        }
        let buffer = UnsafeBufferPointer(start: signature, count: 64)
        if !result.boolValue {
            throw signatureError.signingFailed
        }
        return Data(buffer: buffer)
    }
    
    /**
     
     ECDSA public key recovery from signature
     
     - Parameter signature: Data
     - Parameter message Data
     
     - Throws: keyError.keyRecoveryFailed if the ecp256k1 ecdsa recover function failed
     
     - Returns: a Data object with publicKey
     
     */
    func recoverKeyFromSignature(signature: Data, message: Data) throws -> Data {
        var result = NSNumber.init(value: 0)
        _ = signature.withUnsafeBytes {(secp256k1SignaturePointer: UnsafePointer<secp256k1_ecdsa_recoverable_signature>) in
            _ = message.withUnsafeBytes {(messagePointer: UnsafePointer<UInt8>) in
                result = Int(secp256k1_ecdsa_recover(secp256k1Context, publicKey, secp256k1SignaturePointer, messagePointer)) as NSNumber
            }
        }
        if !result.boolValue {
            throw keyError.keyRecoveryFailed
        }
        let buffer = UnsafeBufferPointer(start: publicKey, count: 64);
        return Data(buffer: buffer)
    }
    
    /**
     
     Generates a random nonce of the specified lenght.
     
     - Parameter lenght: the lenght of the nonce
     
     - Returns: a Data object with the nonce.
     
     */
    func generateNonce(lenght: Int) throws -> Data {
        let nonce = NSMutableData(length: lenght)
        let result = SecRandomCopyBytes(kSecRandomDefault, nonce!.length, nonce!.mutableBytes)
        if result == errSecSuccess {
            return nonce! as Data
        } else {
            throw nonceError.nonceGenerationError
        }
    }
}

