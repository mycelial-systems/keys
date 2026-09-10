import { fromString, type SupportedEncodings, toString } from 'uint8arrays'
import { get, set, delMany } from 'idb-keyval'
import type {
    CharSize,
    Msg,
    SymmKeyLength,
    DID,
    SymmKey,
} from './types.js'
import { AES } from './aes/index.js'
import {
    toBase64,
    joinBufs,
    sha256,
} from './util.js'
import {
    rsaOperations,
    publicKeyToDid,
    getPublicKeyAsArrayBuffer,
} from './crypto.js'
import { KeysDeletedError } from './errors.js'

export { publicKeyToDid, getPublicKeyAsArrayBuffer }
export { KeysDeletedError }
export * from './constants.js'
export type { DID }
export { getPublicKeyAsUint8Array } from './crypto.js'
export type SerializedKeys = {
    DID:DID;
    pulicExchangeKey:string;
}

export interface RsaEncryptor {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array>
}

export interface EccEncryptor {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        info?:string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array>
}

export interface RsaEncryptorAsString {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<string>
}

export interface EccEncryptorAsString {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        info?:string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<string>
}

// Type helpers to constrain implementations
export type RsaKeysType = AbstractKeys & {
    encrypt: RsaEncryptor;
    encryptAsString: RsaEncryptorAsString;
}

export type EccKeysType = AbstractKeys & {
    encrypt: EccEncryptor;
    encryptAsString: EccEncryptorAsString;
}

/**
 * Args to constructor.
 */
export type KeyArgs = {
    keys:{ exchange:CryptoKeyPair, write:CryptoKeyPair };
    did:DID;
    hasPersisted:boolean;
    isSessionOnly?:boolean;  // in memory only?
    exchangeKeyName?:string;
    writeKeyName?:string;
}

/**
 * The class that extends AbstractKeys
 */
interface ChildKeys<T extends AbstractKeys = AbstractKeys> {
    new (opts:KeyArgs):T;
    _instance:T;
    TYPE:'ecc'|'rsa';
    INFO:string;
    _createExchangeKeys(extractable?:boolean):Promise<CryptoKeyPair>
    _createWriteKeys(extractable?:boolean):Promise<CryptoKeyPair>
}

/**
 * The parent key. Doesn't implement the encrypt/sign functions.
 */
export abstract class AbstractKeys {
    DID:DID
    hasPersisted:boolean
    isSessionOnly:boolean
    /**
     * Have these keys been deleted? A deleted keypair is terminal -- the key
     * material is gone, and any use of it throws.
     */
    destroyed:boolean
    /**
     * The `indexedDB` names this keypair was loaded from, and the names
     * `persist` and `delete` will use.
     */
    readonly exchangeKeyName:string
    readonly writeKeyName:string
    static EXCHANGE_KEY_NAME:string  // needs to be defined by child class
    static WRITE_KEY_NAME:string
    static _instance  // a cache for indexedDB

    // the key material -- read it via the `exchangeKey`/`writeKey` getters,
    // which throw if this instance was deleted
    protected _exchangeKey:CryptoKeyPair|null
    protected _writeKey:CryptoKeyPair|null

    constructor (opts:KeyArgs) {
        const { keys } = opts
        const ctor = this.constructor as typeof AbstractKeys
        this.DID = opts.did
        this._exchangeKey = keys.exchange
        this._writeKey = keys.write
        this.hasPersisted = opts.hasPersisted
        this.isSessionOnly = !!opts.isSessionOnly
        this.destroyed = false
        this.exchangeKeyName = opts.exchangeKeyName || ctor.EXCHANGE_KEY_NAME
        this.writeKeyName = opts.writeKeyName || ctor.WRITE_KEY_NAME
    }

    get exchangeKey ():CryptoKeyPair {
        if (this.destroyed || !this._exchangeKey) throw new KeysDeletedError()
        return this._exchangeKey
    }

    get writeKey ():CryptoKeyPair {
        if (this.destroyed || !this._writeKey) throw new KeysDeletedError()
        return this._writeKey
    }

    /**
     * By default, encrypt the given data to yourself, as a "note to self".
     */
    abstract encrypt (
        content:string|Uint8Array,
        recipient?:CryptoKey|string|null,
        aesKeyOrInfo?:SymmKey|Uint8Array|string|null,
        keysizeOrAesKey?:SymmKeyLength|SymmKey|Uint8Array|string|null,
        keysize?:SymmKeyLength|null
    ):Promise<Uint8Array>

    abstract encryptAsString (
        content:string|Uint8Array,
        recipient?:CryptoKey|string|null,
        aesKeyOrInfo?:SymmKey|Uint8Array|string|null,
        keysizeOrAesKey?:SymmKeyLength|SymmKey|Uint8Array|string|null,
        keysize?:SymmKeyLength|null
    ):Promise<string>

    abstract decrypt(
        msg:string|Uint8Array|ArrayBuffer,
        publicKeyOrKeysize?:CryptoKey|string|SymmKeyLength|null,
        aesAlgorithm?:string|null,
    ):Promise<ArrayBuffer|Uint8Array>

    abstract decryptAsString(
        msg:string|Uint8Array|ArrayBuffer,
        publicKeyOrKeysize?:CryptoKey|string|SymmKeyLength|null,
        aesAlgorithm?:string|null,
    ):Promise<string>

    abstract sign(msg:Msg, charsize?:CharSize):Promise<Uint8Array>
    abstract signAsString(msg:string, charsize?:CharSize):Promise<string>

    publicExchangeKeyAsString (format?:SupportedEncodings):Promise<string> {
        return this.publicExchangeKey.asString(format)
    }

    publicWriteKeyAsString (format?:SupportedEncodings):Promise<string> {
        return this.publicWriteKey.asString(format)
    }

    get publicWriteKey () {
        const publicKey = this.writeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?:SupportedEncodings):Promise<string> => {
                const arrayBuffer = await getPublicKeyAsArrayBuffer(this.writeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(uint8Array)
            }
        })
    }

    get publicExchangeKey () {
        const publicKey = this.exchangeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?: SupportedEncodings): Promise<string> => {
                const arrayBuffer = await getPublicKeyAsArrayBuffer(this.exchangeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(uint8Array)
            }
        })
    }

    get privateWriteKey ():CryptoKey {
        return this.writeKey.privateKey
    }

    get privateExchangeKey ():CryptoKey {
        return this.exchangeKey.privateKey
    }

    /**
     * The machine-readable name for this keypair.
     */
    get deviceName ():Promise<string> {
        return AbstractKeys.deviceName(this.DID)
    }

    /**
     * Return a 32-character, DNS-friendly hash of the given DID.
     *
     * @param {DID} did A DID format string
     * @returns {string} 32 character, base32 hash of the DID
     */
    static deviceName (did:DID):Promise<string> {
        return getDeviceName(did)
    }

    /**
     * Get the relevant AES key.
     *   - if this is an ECC keypair, then use DHKE with the given public key
     *   - if this is RSA, use your private key to decrypt the given AES key
     */
    abstract getAesKey (
        publicKey?:CryptoKey|string|null,
        info?:string|null
    ):Promise<CryptoKey>

    /**
     * Save this keys instance to `indexedDB`.
     */
    async persist ():Promise<void> {
        if (this.destroyed) throw new KeysDeletedError()
        if (this.isSessionOnly) return

        await Promise.all([
            set(this.exchangeKeyName, this.exchangeKey),
            set(this.writeKeyName, this.writeKey)
        ])

        this.hasPersisted = true
    }

    /**
     * Delete this keypair. This deletes the keys from indexedDB, drops the
     * in-memory key material, and clears the instance cache, so `load` will
     * not hand out these keys again.
     *
     * After this, the instance is `destroyed` -- using it throws
     * a `KeysDeletedError`.
     */
    async delete ():Promise<void> {
        const exchangeName = this.exchangeKeyName
        const writeName = this.writeKeyName
        await delMany([exchangeName, writeName])
        const ctor = this.constructor as typeof AbstractKeys
        ctor._invalidate(exchangeName, writeName)
        this._destroy()
    }

    /**
     * Drop the in-memory key material. Internal -- call `delete` instead.
     */
    _destroy ():void {
        this.destroyed = true
        this.hasPersisted = false
        this._exchangeKey = null
        this._writeKey = null
    }

    /**
     * If the cached instance was loaded from the given names, then its keys
     * are gone too. Destroy it, and clear the cache. Internal.
     */
    static _invalidate (exchangeName:string, writeName:string):void {
        const cached:AbstractKeys|null = this._instance
        if (!cached) return
        if (cached.exchangeKeyName !== exchangeName) return
        if (cached.writeKeyName !== writeName) return
        cached._destroy()
        this._instance = null
    }

    /**
     * Delete a stored keypair without loading it first. Deletes the keys from
     * indexedDB, and destroys the cached instance, if there is one for
     * these names.
     *
     * @param {{ encryptionKeyName, writeKeyName }} [opts] The indexedDB names
     *   to delete. Defaults to this class's names.
     */
    static async delete (opts:{
        encryptionKeyName?:string,
        writeKeyName?:string
    } = {}):Promise<void> {
        const exchangeName = opts.encryptionKeyName || this.EXCHANGE_KEY_NAME
        const writeName = opts.writeKeyName || this.WRITE_KEY_NAME
        await delMany([exchangeName, writeName])
        this._invalidate(exchangeName, writeName)
    }

    abstract toJson (format?:SupportedEncodings):Promise<{
        DID:DID;
        publicExchangeKey:string;
    }>

    /**
     * Return a 32-character, DNS friendly hash of the public signing key.
     *
     * @returns {Promise<string>}
     */
    async getDeviceName ():Promise<string> {
        return AbstractKeys.deviceName(this.DID)
    }

    static _createExchangeKeys (_extractable?:boolean):Promise<CryptoKeyPair> {
        throw new Error('The child should implement this')
    }

    static _createWriteKeys (_extractable?:boolean):Promise<CryptoKeyPair> {
        throw new Error('The child should implement this')
    }

    static async create<T extends AbstractKeys> (
        this:ChildKeys,
        session?:boolean,
        extractable?:boolean,
        keys?:{
            exchangeKeys?:CryptoKeyPair|null,
            writeKeys?:CryptoKeyPair|null,
            dbKey?:string,
        }
    ):Promise<T> {
        // encryption
        const exchange = keys?.exchangeKeys || await this._createExchangeKeys(
            extractable
        )
        // signatures
        const write = keys?.writeKeys || await this._createWriteKeys(extractable)

        const publicSigningKey = await getPublicKeyAsArrayBuffer(write)
        const did = await publicKeyToDid(
            new Uint8Array(publicSigningKey),
            this.TYPE === 'ecc' ? 'ed25519' : 'rsa'
        )

        const keysInstance = new this({
            keys: { exchange, write },
            did,
            hasPersisted: false,
            isSessionOnly: !!session
        })

        this._instance = keysInstance

        return keysInstance as T
    }

    static async exist (opts:{
        encryptionKeyName?:string,
        writeKeyName?:string
    } = {}):Promise<boolean> {
        const keys = await get(opts.writeKeyName || this.WRITE_KEY_NAME)
        const excahngeKeys = await get(opts.encryptionKeyName || this.EXCHANGE_KEY_NAME)
        if (!keys || !excahngeKeys) return false
        return true
    }

    /**
     * Restore some keys from indexedDB, or create a new keypair if it doesn't
     * exist yet.
     *
     * By default this saves the keys to `indexedDB` before returning, so the
     * keypair you get back survives a page reload. Pass `{ persist: false }`
     * to skip that and call `.persist()` yourself. Session keys are never
     * written to `indexedDB`, so `{ session: true }` wins over `persist`.
     *
     * @param {{ encryptionKeyName, signingKeyName, session, persist }} opts
     *   Strings to use as keys in indexedDB, a session boolean -- is this in
     *   memory only? Or can it be persisted -- and a persist boolean.
     * @returns {Promise<AbstractKeys>}
     */
    static async load<T extends AbstractKeys = AbstractKeys> (
        this:ChildKeys & typeof AbstractKeys,
        opts:Partial<{
            encryptionKeyName:string,
            writeKeyName:string,
            session:boolean,
            extractable:boolean,
            persist:boolean,
        }> = {
            session: false,
        }
    ):Promise<T> {
        const shouldPersist = opts.persist !== false
        const exchangeKeyName = opts.encryptionKeyName || this.EXCHANGE_KEY_NAME
        const writeKeyName = opts.writeKeyName || this.WRITE_KEY_NAME

        // cache -- only if it is for the same indexedDB entries
        const cached:AbstractKeys|null = this._instance
        if (
            cached &&
            !cached.destroyed &&
            cached.exchangeKeyName === exchangeKeyName &&
            cached.writeKeyName === writeKeyName
        ) {
            if (shouldPersist && !cached.hasPersisted) await cached.persist()
            return cached as T
        }

        let hasPersisted = true
        let exchangeKeys:CryptoKeyPair|undefined = await get(exchangeKeyName)
        let writeKeys:CryptoKeyPair|undefined = await get(writeKeyName)

        if (!exchangeKeys) {
            hasPersisted = false
            exchangeKeys = await this._createExchangeKeys(opts.extractable)
        }
        if (!writeKeys) {
            hasPersisted = false
            writeKeys = await this._createWriteKeys(opts.extractable)
        }

        const publicSigningKey = await getPublicKeyAsArrayBuffer(writeKeys)
        const did = await publicKeyToDid(
            new Uint8Array(publicSigningKey),
            this.TYPE === 'ecc' ? 'ed25519' : 'rsa'
        )

        const keys = new this({
            keys: { exchange: exchangeKeys, write: writeKeys },
            did,
            hasPersisted,
            isSessionOnly: !!opts.session,
            exchangeKeyName,
            writeKeyName
        }) as T

        this._instance = keys
        if (shouldPersist && !hasPersisted) await keys.persist()
        return keys
    }
}

/**
 * Encrypt the given message to the given public key. If an AES key is not
 * provided, one will be created. Use an AES key to encrypt the given
 * content, then we encrypt the AES key to the given public key.
 *
 * @param {{ content, publicKey }} opts The content to encrypt and
 *   public key to encrypt to
 * @param {SymmKey|Uint8Array|string} [aesKey] An optional AES key to encrypt
 *   to the given public key
 * @returns {Promise<ArrayBuffer>} The encrypted AES key, concattenated with
 *   the encrypted content.
 */
export async function encryptTo (
    opts:{ content:string|Uint8Array; publicKey:CryptoKey|string; },
    aesKey?:SymmKey|Uint8Array|string,
):Promise<ArrayBuffer> {
    const { content, publicKey } = opts
    const key = aesKey || await AES.create()
    const encryptedContent = await AES.encrypt(
        typeof content === 'string' ? fromString(content) : content,
        typeof key === 'string' ? await AES.import(key) : key,
    )
    const encryptedKey = await encryptKeyTo({ key, publicKey })

    return joinBufs(encryptedKey, encryptedContent)
}

/**
 * Encrypt the given AES key to the given public key. Return the encrypted AES
 * key concattenated with the cipher text.
 *
 * @param { content, publicKey } opts The content to encrypt and key to
 *   encrypt to.
 * @param {SymmKey|Uint8Array|string} [aesKey] Optional -- the AES key. One will
 *   be created if not passed in.
 * @returns {Promise<string>} The encrypted AES key concattenated with the
 *   cipher text.
 */
encryptTo.asString = async function (
    opts:{ content:string|Uint8Array; publicKey:CryptoKey|string },
    aesKey?:SymmKey|Uint8Array|string
):Promise<string> {
    const joined = await encryptTo(opts, aesKey)
    return toString(new Uint8Array(joined), 'base64pad')
}

export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format:'arraybuffer'):Promise<ArrayBuffer>

export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format:'uint8array'):Promise<Uint8Array>

export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format?:undefined):Promise<Uint8Array>

/**
 * Encrypt the given content to the given public key. This is RSA encryption,
 * and should be used only to encrypt AES keys.
 *
 * @param {{ content, publicKey }} params The content to encrypt, and public key
 * to encrypt it to.
 * @returns {Promise<Uint8Array>}
 */
export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format?:'uint8array'|'arraybuffer'):Promise<Uint8Array|ArrayBuffer> {
    let _key:Uint8Array|string
    if (key instanceof CryptoKey) {
        _key = await AES.export(key)
    } else {
        _key = key
    }

    const buf = await rsaOperations.encrypt(_key, publicKey)
    if (format && format === 'arraybuffer') return buf
    return new Uint8Array(buf)
}

encryptKeyTo.asString = async function ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|string|Uint8Array;
}, format?:SupportedEncodings):Promise<string> {
    const asArr = await encryptKeyTo({ key, publicKey })
    return format ? toString(asArr, format) : toBase64(asArr)
}

// /**
//  * Decrypt the given message with the given key. We expect the `iv` to be
//  * prefixed to the encrypted message.
//  * @param msg The message to decrypt
//  * @param key The key to decrypt with
//  * @param opts Optional args for algorithm and stuff
//  * @returns {Promise<ArrayBuffer>}
//  */
// async function decryptBytes (
//     msg:Msg,
//     key:CryptoKey|string,
//     opts?:Partial<{
//         alg:SymmAlgorithm;
//         length: SymmKeyLength;
//         iv: ArrayBuffer;
//     }>
// ):Promise<ArrayBuffer> {
//     const cipherText = normalizeBase64ToBuf(msg)
//     const importedKey = typeof key === 'string' ?
//         await importKey(key, opts) :
//         key
//     // `iv` is prefixed to the cypher text
//     const iv = cipherText.slice(0, IV_LENGTH)
//     const cipherBytes = cipherText.slice(IV_LENGTH)
//     const msgBuff = await webcrypto.subtle.decrypt({
//         name: DEFAULT_SYMM_ALGORITHM,
//         iv
//     }, importedKey, cipherBytes)

//     return msgBuff
// }

export async function getDeviceName (did:DID|string) {
    const hashedUsername = await sha256(
        new TextEncoder().encode(did.normalize('NFD'))
    )

    return toString(hashedUsername, 'base32').slice(0, 32)
}
