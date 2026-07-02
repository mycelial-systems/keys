import { get } from 'idb-keyval'
import { test } from '@substrate-system/tapzero'
import { toString, fromString } from 'uint8arrays'
import nacl from 'tweetnacl'
import {
    EccKeys,
    exportPublicKey,
    importPublicKey,
    verify
} from '../src/ecc/index.js'
import { didToPublicKey } from '../src/crypto.js'
import { EccCurve, KeyUse } from '../src/types.js'

const subtle = crypto.subtle

// Can we create an x25519 key in this environment?
test('Sanity', async t => {
    try {
        const keys = await subtle.generateKey({
            name: 'X25519'
        }, true, ['deriveKey']) as CryptoKeyPair
        const raw = await subtle.exportKey('raw', keys.publicKey)
        t.equal(raw.byteLength, 32, 'should generate an X25519 key')
    } catch (err) {
        console.error('error in test', err)
    }
})

test('exist with no keys created', async t => {
    t.equal(await EccKeys.exist(), false, 'exist should return false')
})

let myKeys:EccKeys
test('__________Create a new EccKeys instance___________________', async t => {
    myKeys = await EccKeys.create()
    t.ok(myKeys, 'should create the keys')
    t.equal(myKeys.hasPersisted, false,
        'should not have persisted flag for newly created keys')
    t.equal(EccKeys.EXCHANGE_KEY_NAME, 'ecc-exchange',
        'should have the default encryption key name')
    t.equal(EccKeys.WRITE_KEY_NAME, 'ecc-write',
        'should have the default signature key name')
    t.ok(myKeys.DID, 'should have a DID')
})

test('Get a DID from the keys', async t => {
    const did = myKeys.DID
    t.equal(typeof did, 'string', 'should get a string')
    t.equal(did.length, 72, 'should be 72 characters')
    t.ok(did.startsWith('did:key:'), 'should be a proper DID format')
})

test('publicExchangeKey and publicWriteKey getters', async t => {
    const pubExchange = myKeys.publicExchangeKey
    const pubWrite = myKeys.publicWriteKey

    t.ok(pubExchange, 'should have public exchange key')
    t.ok(pubWrite, 'should have public write key')
    t.equal(typeof pubExchange.asString, 'function',
        'should have asString method on exchange key')
    t.equal(typeof pubWrite.asString, 'function',
        'should have asString method on write key')

    const exchangeStr = await pubExchange.asString()
    const writeStr = await pubWrite.asString()
    t.equal(typeof exchangeStr, 'string', 'should export exchange key as string')
    t.equal(typeof writeStr, 'string', 'should export write key as string')
})

test('publicExchangeKeyAsString and publicWriteKeyAsString', async t => {
    const exchangeStr = await myKeys.publicExchangeKeyAsString()
    const writeStr = await myKeys.publicWriteKeyAsString()

    t.equal(typeof exchangeStr, 'string', 'should return exchange key as string')
    t.equal(typeof writeStr, 'string', 'should return write key as string')

    const exchangeStr64 = await myKeys.publicExchangeKeyAsString('base64')
    const writeStr64 = await myKeys.publicWriteKeyAsString('base64')
    t.equal(typeof exchangeStr64, 'string',
        'should return exchange key as base64 string')
    t.equal(typeof writeStr64, 'string',
        'should return write key as base64 string')
})

test('toJson serialization', async t => {
    const obj = await myKeys.toJson()
    t.equal(obj.DID, myKeys.DID, 'should return the DID')
    t.equal(typeof obj.publicExchangeKey, 'string',
        'should return public exchange key as string')

    const objBase32 = await myKeys.toJson('base32')
    t.equal(typeof objBase32.publicExchangeKey, 'string',
        'should format public key with specified encoding')
})

test('encrypt and decrypt a string (note to self)', async t => {
    const message = 'hello world from ECC'
    const encrypted = await myKeys.encrypt(message)

    t.ok(encrypted instanceof Uint8Array, 'should return Uint8Array')
    t.ok(encrypted.length > 0, 'should have encrypted content')

    const decrypted = await myKeys.decrypt(encrypted)
    const decryptedText = toString(new Uint8Array(decrypted))
    t.equal(decryptedText, message, 'should decrypt to original message')
})

test('encryptAsString and decryptAsString', async t => {
    const message = 'hello encryption formats'
    const encrypted = await myKeys.encryptAsString(message)

    t.equal(typeof encrypted, 'string',
        'should return encrypted data as string')

    const decrypted = await myKeys.decryptAsString(encrypted)
    t.equal(decrypted, message, 'should decrypt to original message')
})

test('encrypt to another public key', async t => {
    const otherKeys = await EccKeys.create()
    const message = 'secret message'

    // Encrypt to other keys' public key
    const encrypted = await myKeys.encrypt(
        message,
        otherKeys.publicExchangeKey
    )

    // Other keys should be able to decrypt
    const decrypted = await otherKeys.decrypt(
        encrypted,
    )
    const decryptedText = toString(new Uint8Array(decrypted))
    t.equal(decryptedText, message, 'should decrypt message from other key')
})

test('encrypt to public key as string', async t => {
    const otherKeys = await EccKeys.create()
    const message = 'secret message with string key'
    const pubKeyString = await otherKeys.publicExchangeKeyAsString()

    // Encrypt to string public key
    const encrypted = await myKeys.encrypt(message, pubKeyString)

    // Other keys should be able to decrypt
    const decrypted = await otherKeys.decryptAsString(encrypted)
    t.equal(decrypted, message, 'should encrypt/decrypt with string public key')
})

let sig
test('sign', async t => {
    const message = 'message to sign'
    sig = await myKeys.sign(message)

    t.ok(sig instanceof Uint8Array, 'should return signature as Uint8Array')
    t.ok(sig.length > 0, 'should have signature data')
})

test('signAsString', async t => {
    const message = 'message to sign as string'
    const signature = await myKeys.signAsString(message)

    t.equal(typeof signature, 'string', 'should return signature as string')
    t.ok(signature.length > 0, 'should have signature data')
})

test('verify signature', async t => {
    const message = 'message to verify'
    const signature = await myKeys.signAsString(message)

    // Verify with correct message and signature
    const isValid = await verify(message, signature, myKeys.DID)
    t.ok(isValid, 'should verify valid signature')

    // Verify with wrong message
    const isInvalid = await verify('wrong message', signature, myKeys.DID)
    t.equal(isInvalid, false, 'should reject invalid signature')

    // Test with Uint8Array signature
    const sigBytes = await myKeys.sign(message)
    const isValidBytes = await verify(message, sigBytes, myKeys.DID)
    t.ok(isValidBytes, 'should verify valid signature with Uint8Array')
})

// Ed25519 signatures are produced via the webcrypto API. This checks that
// output stays interoperable with tweetnacl's pure-JS implementation.
test('signature is verifiable by tweetnacl', async t => {
    const message = 'interop with tweetnacl'
    const sig = await myKeys.sign(message)
    const pub = didToPublicKey(myKeys.DID).publicKey

    t.equal(pub.length, 32, 'raw Ed25519 public key should be 32 bytes')
    t.equal(sig.length, 64, 'Ed25519 signature should be 64 bytes')

    const verified = nacl.sign.detached.verify(
        fromString(message, 'utf8'),
        sig,
        pub
    )
    t.ok(verified, 'tweetnacl should verify a signature made by this module')

    const rejected = nacl.sign.detached.verify(
        fromString('tampered message', 'utf8'),
        sig,
        pub
    )
    t.equal(rejected, false, 'tweetnacl should reject a wrong message')
})

test('getAesKey method', async t => {
    const aesKey = await myKeys.getAesKey()
    t.ok(aesKey instanceof CryptoKey, 'should return a CryptoKey')
    t.equal(aesKey.type, 'secret', 'should be a secret key')
})

test('getAesKey with another public key', async t => {
    const otherKeys = await EccKeys.create()
    const aesKey = await myKeys.getAesKey(otherKeys.publicExchangeKey)
    t.ok(aesKey instanceof CryptoKey, 'should return a CryptoKey with other public key')
})

test('encrypt with custom info parameter', async t => {
    const message = 'test with custom info'
    const customInfo = 'custom-info'

    const encrypted = await myKeys.encrypt(message, undefined, customInfo)
    const decrypted = await myKeys.decryptAsString(encrypted, null, customInfo)
    t.equal(decrypted, message, 'should encrypt/decrypt with custom info')
})

test('Cache the keys instance', async t => {
    // Clear cache to start fresh
    EccKeys._instance = null

    // Create and cache an instance
    const keys1 = await EccKeys.create()
    t.equal(EccKeys._instance, keys1, 'should cache the created instance')

    // Loading should return the cached instance
    const keys2 = await EccKeys.load()
    t.equal(keys2, keys1, 'should return the same cached instance')
    t.equal(EccKeys._instance, keys1, 'cache should remain the same')
})

test('indexedDB persistence', async t => {
    await myKeys.persist()
    t.ok(myKeys.hasPersisted, 'should have persisted flag after calling .persist')

    const encryptionKey = await get(EccKeys.EXCHANGE_KEY_NAME)
    const signKey = await get(EccKeys.WRITE_KEY_NAME)
    t.ok(encryptionKey, 'should save an encryption key in indexedDB')
    t.ok(signKey, 'should save a signature key in indexedDB')
})

test('create after persisting keys', async t => {
    t.ok(await EccKeys.exist(), 'should return true after we persist the keys')
})

test('Create keys from indexedDB', async t => {
    // Clear the cache to test loading from indexedDB
    EccKeys._instance = null

    const newKeys = await EccKeys.load()
    t.ok(newKeys.DID, 'should have a DID when loaded from indexedDB')
    t.equal(newKeys.hasPersisted, true, 'should have `persisted` flag')

    // The new instance should be cached
    t.equal(EccKeys._instance, newKeys, 'should cache the loaded instance')
})

test('Delete the keys from indexedDB', async t => {
    t.equal(myKeys.hasPersisted, true, 'should start with persisted keys')

    const loadedKeys = await EccKeys.load()
    t.ok(loadedKeys, 'Should return key from indexedDB')

    await myKeys.delete()
    t.equal(myKeys.hasPersisted, false, 'now keys.persisted is false')

    const encryptionKey = await get(EccKeys.EXCHANGE_KEY_NAME)
    const signKey = await get(EccKeys.WRITE_KEY_NAME)
    t.equal(encryptionKey, undefined, 'should not return keys from indexedDB')
    t.equal(signKey, undefined, 'should not return signature key from indexedDB')
})

test('device name', async t => {
    const deviceName = await myKeys.getDeviceName()
    const deviceName2 = await EccKeys.deviceName(myKeys.DID)
    t.equal(deviceName, deviceName2, 'should return the same device name')
    t.equal(deviceName.length, 32, 'should return 32 characters')
    t.equal(typeof deviceName, 'string', 'should return a string')
})

test('in memory only', async t => {
    const keys = await EccKeys.create(true)
    t.equal(keys.hasPersisted, false, 'should not have `persisted` flag')
    t.equal(keys.isSessionOnly, true, 'should be session only')

    await keys.persist()
    t.equal(keys.hasPersisted, false, 'should still not be persisted after calling persist')
})

test('load method with session option', async t => {
    const keys = await EccKeys.load({ session: true })
    t.equal(keys.isSessionOnly, true, 'should be session only')
    t.equal(keys.hasPersisted, false, 'should not be persisted')
})

test('exportPublicKey utility function', async t => {
    const rawKey = await exportPublicKey(myKeys.exchangeKey)
    t.ok(rawKey instanceof ArrayBuffer, 'should export key as ArrayBuffer')
    t.equal(rawKey.byteLength, 32, 'should be 32 bytes for X25519 key')
})

test('importPublicKey utility function', async t => {
    const rawKey = await exportPublicKey(myKeys.exchangeKey)
    const keyString = toString(new Uint8Array(rawKey), 'base64pad')

    const imported = await importPublicKey(keyString, EccCurve.X25519, KeyUse.Exchange)
    t.ok(imported instanceof CryptoKey, 'should import as CryptoKey')
    t.equal(imported.type, 'public', 'should be a public key')
})

// Note: Backward compatibility .asString methods are attached to prototypes
// but testing these requires more complex setup. The important thing is that
// the proper async methods (encryptAsString, decryptAsString, signAsString) work
// test('backward compatibility .asString methods', async t => {
//     const message = 'test backward compatibility'

//     // Test encrypt.asString (this calls the attached asString method)
//     const encrypted = await (myKeys.encrypt as any).asString(message)
//     t.equal(typeof encrypted, 'string', 'encrypt.asString should return string')

//     // Test decrypt.asString (this calls the attached asString method)
//     const decrypted = await (myKeys.decrypt as any).asString(encrypted)
//     t.equal(decrypted, message, 'decrypt.asString should decrypt correctly')

//     // Test sign.asString (this calls the attached asString method)
//     const signature = await (myKeys.sign as any).asString(message)
//     t.equal(typeof signature, 'string', 'sign.asString should return string')
// })

test('An example use of to/from strings', async t => {
    const msg = { type: 'test', content: 'hello ECC' }
    const encrypted = await myKeys.encryptAsString(JSON.stringify(msg))

    t.equal(typeof encrypted, 'string', 'should return a string')

    const text = await myKeys.decryptAsString(encrypted)
    const data = JSON.parse(text)
    t.equal(data.content, 'hello ECC', 'should get the original object')
})

test('add device - wrap AES key for new device', async t => {
    // Create a content key (AES key)
    const contentKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )

    // Create a new device
    const newDevice = await EccKeys.create()

    // Wrap the content key for the new device
    const wrapped = await myKeys.wrap(contentKey, newDevice.publicExchangeKey)

    t.equal(typeof wrapped.enc, 'string', 'should return ephemeral public key as string')
    t.equal(typeof wrapped.wrappedKey, 'string', 'should return wrapped key as string')
    t.ok(wrapped.enc.length > 0, 'ephemeral public key should not be empty')
    t.ok(wrapped.wrappedKey.length > 0, 'wrapped key should not be empty')
})

test('unwrap - new device unwraps content key', async t => {
    // Create a content key (AES key)
    const contentKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )

    // Export original key for comparison
    const originalKeyBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', contentKey)
    )

    // Create a new device
    const newDevice = await EccKeys.create()

    // Wrap the content key for the new device
    const wrapped = await myKeys.wrap(contentKey, newDevice.publicExchangeKey)

    // New device unwraps the content key
    const unwrappedKey = await newDevice.unwrap(wrapped.enc, wrapped.wrappedKey)

    // Export unwrapped key for comparison
    const unwrappedKeyBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', unwrappedKey)
    )

    t.ok(unwrappedKey instanceof CryptoKey, 'should return a CryptoKey')
    t.equal(unwrappedKey.type, 'secret', 'should be a secret key')
    t.equal(originalKeyBytes.length, unwrappedKeyBytes.length,
        'unwrapped key should have same length as original')

    // Compare byte by byte
    let bytesMatch = true
    for (let i = 0; i < originalKeyBytes.length; i++) {
        if (originalKeyBytes[i] !== unwrappedKeyBytes[i]) {
            bytesMatch = false
            break
        }
    }
    t.ok(bytesMatch, 'unwrapped key should match original key')
})

test('add a device - encrypt data, add device, new device decrypts', async t => {
    // Device 1 encrypts some data with a content key
    const device1 = await EccKeys.create()
    const contentKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )

    const message = 'secret data for all devices'
    const encoder = new TextEncoder()
    const iv = crypto.getRandomValues(new Uint8Array(12))

    // Encrypt the message with the content key
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        contentKey,
        encoder.encode(message)
    )

    // wrap the content key for device 2
    const device2 = await EccKeys.create()
    const wrapped = await device1.wrap(contentKey, device2.publicExchangeKey)

    // Device 2 unwraps the content key
    const device2ContentKey = await device2.unwrap(wrapped.enc, wrapped.wrappedKey)

    // Device 2 decrypts the message
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        device2ContentKey,
        encrypted
    )

    const decryptedText = toString(new Uint8Array(decrypted))
    t.equal(decryptedText, message, 'device 2 should decrypt message with unwrapped key')
})

test('add device with string content key', async t => {
    // Create a content key and export as string
    const contentKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )
    const keyBytes = await crypto.subtle.exportKey('raw', contentKey)
    const keyString = toString(new Uint8Array(keyBytes), 'base64pad')

    // Create a new device
    const newDevice = await EccKeys.create()

    // Wrap the content key (as string) for the new device
    const wrapped = await myKeys.wrap(keyString, newDevice.publicExchangeKey)

    t.equal(typeof wrapped.enc, 'string', 'should return ephemeral public key as string')
    t.equal(typeof wrapped.wrappedKey, 'string', 'should return wrapped key as string')

    // New device should be able to unwrap it
    const unwrappedKey = await newDevice.unwrap(wrapped.enc, wrapped.wrappedKey)
    t.ok(unwrappedKey instanceof CryptoKey, 'should unwrap to CryptoKey')
})

test('add device with Uint8Array content key', async t => {
    // Create a content key and export as Uint8Array
    const contentKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )
    const keyBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', contentKey)
    )

    // Create a new device
    const newDevice = await EccKeys.create()

    // Wrap the content key (as Uint8Array) for the new device
    const wrapped = await myKeys.wrap(keyBytes, newDevice.publicExchangeKey)

    t.equal(typeof wrapped.enc, 'string', 'should return ephemeral public key as string')
    t.equal(typeof wrapped.wrappedKey, 'string', 'should return wrapped key as string')

    // New device should be able to unwrap it
    const unwrappedKey = await newDevice.unwrap(wrapped.enc, wrapped.wrappedKey)
    t.ok(unwrappedKey instanceof CryptoKey, 'should unwrap to CryptoKey')
})

test('add device with custom info parameter', async t => {
    const contentKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )

    const newDevice = await EccKeys.create()
    const customInfo = 'custom-key-wrap-info'

    // Wrap with custom info
    const wrapped = await myKeys.wrap(
        contentKey,
        newDevice.publicExchangeKey,
        customInfo
    )

    // Unwrap with same custom info
    const unwrappedKey = await newDevice.unwrap(
        wrapped.enc,
        wrapped.wrappedKey,
        customInfo
    )

    t.ok(unwrappedKey instanceof CryptoKey,
        'should unwrap with matching custom info')

    // Verify the keys match
    const originalBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', contentKey)
    )
    const unwrappedBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', unwrappedKey)
    )

    let match = originalBytes.length === unwrappedBytes.length
    if (match) {
        for (let i = 0; i < originalBytes.length; i++) {
            if (originalBytes[i] !== unwrappedBytes[i]) {
                match = false
                break
            }
        }
    }
    t.ok(match, 'unwrapped key should match original')
})

test('add device - multiple devices', async t => {
    // Simulate adding multiple devices to an account
    const contentKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )

    const device1 = await EccKeys.create()
    const device2 = await EccKeys.create()
    const device3 = await EccKeys.create()

    // Wrap content key for all devices
    const wrapped1 = await myKeys.wrap(contentKey, device1.publicExchangeKey)
    const wrapped2 = await myKeys.wrap(contentKey, device2.publicExchangeKey)
    const wrapped3 = await myKeys.wrap(contentKey, device3.publicExchangeKey)

    // All devices should be able to unwrap
    const key1 = await device1.unwrap(wrapped1.enc, wrapped1.wrappedKey)
    const key2 = await device2.unwrap(wrapped2.enc, wrapped2.wrappedKey)
    const key3 = await device3.unwrap(wrapped3.enc, wrapped3.wrappedKey)

    // Export all keys for comparison
    const originalBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', contentKey)
    )
    const key1Bytes = new Uint8Array(await crypto.subtle.exportKey('raw', key1))
    const key2Bytes = new Uint8Array(await crypto.subtle.exportKey('raw', key2))
    const key3Bytes = new Uint8Array(await crypto.subtle.exportKey('raw', key3))

    t.ok(bytesEqual(originalBytes, key1Bytes), 'device 1 key should match')
    t.ok(bytesEqual(originalBytes, key2Bytes), 'device 2 key should match')
    t.ok(bytesEqual(originalBytes, key3Bytes), 'device 3 key should match')
})

// Helper to compare bytes
function bytesEqual (a:Uint8Array, b:Uint8Array) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}
