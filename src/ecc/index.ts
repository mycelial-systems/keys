import { type SupportedEncodings, toString, fromString } from 'uint8arrays'
import {
    DEFAULT_ECC_EXCHANGE,
    DEFAULT_ECC_WRITE,
    DEFAULT_SYMM_ALGORITHM,
    SALT_LENGTH,
    IV_LENGTH,
    DEFAULT_SYMM_LENGTH,
    ECC_WRITE_ALGORITHM,
    ECC_EXCHANGE_ALGORITHM,
    X25519_PUBLIC_KEY_LENGTH
} from '../constants.js'
import {
    EccCurve,
    KeyUse,
    type PublicKey,
    type SymmKeyLength,
    type SymmKey,
    type Msg,
    type CharSize,
    type DID,
    type WrappedKey,
} from '../types.js'
import {
    base64ToArrBuf,
    normalizeToBuf,
    toBase64,
    didToPublicKey
} from '../util.js'
import { checkValidKeyUse } from '../errors.js'
import { AbstractKeys } from '../_base.js'

const webcrypto = globalThis.crypto

// Helper function to ensure proper ArrayBuffer type
function toArrayBuffer (data:Uint8Array):ArrayBuffer {
    return new Uint8Array(data).buffer
}

/**
 * Class for ECC keys
 */
export class EccKeys extends AbstractKeys {
    static TYPE:'ecc'|'rsa' = 'ecc' as const
    static EXCHANGE_KEY_NAME:string = DEFAULT_ECC_EXCHANGE
    static WRITE_KEY_NAME:string = DEFAULT_ECC_WRITE
    static INFO = 'keys'

    /**
     * Factory function.
     * @param {boolean} [session] Session only? i.e., not saved in indexedDB.
     *   Default `false`.
     * @param {boolean} [extractable] Can we extract the private keys? Default
     *   `false`.
     * @param {{ exchangeKeys, writeKeys }} [keys] A set of keys to use here.
     * @returns {Promise<EccKeys>} A new class instance.
     */
    static async create<T extends AbstractKeys = EccKeys> (
        session?:boolean,
        extractable?:boolean,
        keys?:{
            exchangeKeys?:CryptoKeyPair|null,
            writeKeys?:CryptoKeyPair|null,
        }
    ):Promise<T> {
        return await super.create<T>(session, extractable, keys)
    }

    get publicExchangeKey () {
        const publicKey = this.exchangeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?: SupportedEncodings): Promise<string> => {
                const arrayBuffer = await exportPublicKey(this.exchangeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(arrayBuffer)
            }
        })
    }

    get publicWriteKey () {
        const publicKey = this.writeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?: SupportedEncodings): Promise<string> => {
                const arrayBuffer = await exportPublicKey(this.writeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(arrayBuffer)
            }
        })
    }

    static async _createExchangeKeys (
        extractable:boolean = false
    ):Promise<CryptoKeyPair> {
        /**
         * don't use `{ name: ECDH, namedCurve: 'X25519' }`, use
         * `{ name: 'X25519' }`.
         *
         * X25519/Ed25519 don't use `namedCurve`.
         */
        return await webcrypto.subtle.generateKey(
            {
                name: ECC_EXCHANGE_ALGORITHM
                // namedCurve: EccCurve.X25519
            },
            extractable,
            ['deriveKey', 'deriveBits']
        ) as CryptoKeyPair
    }

    static async _createWriteKeys (extractable:boolean = false):Promise<CryptoKeyPair> {
        return await webcrypto.subtle.generateKey(
            {
                name: ECC_WRITE_ALGORITHM
            },
            extractable,
            ['sign', 'verify']
        )
    }

    /**
     * Restore some keys from indexedDB, or create a new keypair if it doesn't
     * exist yet. Overrides base class to use ECC-specific key names.
     */
    static async load<T extends AbstractKeys = EccKeys> (
        this:typeof EccKeys,
        opts:Partial<{
            encryptionKeyName:string,
            writeKeyName:string,
            session:boolean,
            extractable:boolean,
        }> = {
            session: false,
        }
    ):Promise<T> {
        return super.load(opts) as Promise<T>
    }

    /**
     * Serialize this keys instance. Will return an object of
     * { DID, publicExchangeKey }, where DID is the public write key,
     * and `publicExchangeKey` is the encryption key, `base64` encoded.
     * @returns {Promise<{ DID:DID, publicExchangeKey:string }>}
     */
    async toJson (
        format?:SupportedEncodings
    ):Promise<{ DID:DID; publicExchangeKey:string; }> {
        const did = this.DID

        const rawKey = await exportPublicKey(this.exchangeKey)

        const keyString = (format ?
            toString(new Uint8Array(rawKey), format) :
            toBase64(rawKey))

        return {
            publicExchangeKey: keyString,
            DID: did
        }
    }

    /**
     * "Add a device," meaning, take an existing AES key and add the ability
     * for a new keypair to decrypt/use the AES key.
     *
     * This implements HPKE-style key wrapping:
     *   1. Generate ephemeral X25519 keypair
     *   2. Do ECDH with recipient's public key -> shared secret
     *   3. Use HKDF to derive a KEK (key encryption key)
     *   4. AES-GCM encrypt the content
     *   5. Return the ephemeral public key (encapsulation) + wrapped key
     *
     * @param {SymmKey|Uint8Array|string} contentKey The existing AES key used
     *   to encrypt the content. Can be a base64 encoded string.
     * @param {CryptoKey} newPublicKey The new device's public X25519 key.
     * @param {string} [info] Optional info parameter for HKDF.
     *   Defaults to 'key-wrap'.
     * @returns {Promise<WrappedKey>} The ephemeral public key (base64) and
     *          the wrapped AES key (base64).
     */
    async wrap (
        contentKey:SymmKey|Uint8Array|string,
        newPublicKey:CryptoKey,  // the new device's public key
        info?:string
    ):Promise<WrappedKey> {
        // 1. Generate ephemeral X25519 keypair
        const ephemeralKeypair = await EccKeys._createExchangeKeys(true)

        // 2. Generate random salt for HKDF
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))

        // 3. Derive KEK using ECDH + HKDF with ephemeral private key and
        // recipient's public key
        const kek = await deriveKey(
            ephemeralKeypair.privateKey,
            newPublicKey,
            salt,
            info || 'key-wrap'
        )

        // 4. Prepare the content key for encryption
        let contentKeyBytes:Uint8Array
        if (contentKey instanceof CryptoKey) {
            // Export the AES key to raw format
            const exported = await crypto.subtle.exportKey('raw', contentKey)
            contentKeyBytes = new Uint8Array(exported)
        } else if (typeof contentKey === 'string') {
            contentKeyBytes = fromString(contentKey, 'base64pad')
        } else {
            contentKeyBytes = contentKey
        }

        // 5. Generate IV for AES-GCM encryption
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))

        // 6. Encrypt the content key with the KEK
        const wrappedKeyBuffer = await crypto.subtle.encrypt(
            { name: DEFAULT_SYMM_ALGORITHM, iv },
            kek,
            toArrayBuffer(contentKeyBytes)
        )

        // 7. Export ephemeral public key
        const ephemeralPubKeyBuffer = await exportPublicKey(ephemeralKeypair)

        // 8. Combine salt + iv + wrapped key for the final wrapped key blob
        const saltBuf = new Uint8Array(salt)
        const ivBuf = new Uint8Array(iv)
        const wrappedBuf = new Uint8Array(wrappedKeyBuffer)
        const combinedSize = saltBuf.length + ivBuf.length + wrappedBuf.length
        const combined = new Uint8Array(combinedSize)
        combined.set(saltBuf, 0)
        combined.set(ivBuf, saltBuf.length)
        combined.set(wrappedBuf, saltBuf.length + ivBuf.length)

        // 9. Return base64-encoded results
        return {
            enc: toBase64(new Uint8Array(ephemeralPubKeyBuffer)),
            wrappedKey: toBase64(combined)
        }
    }

    /**
     * Unwrap a content key that was wrapped for this device using the `add` method.
     *
     * The recipient device uses its private key + the ephemeral public key
     * to rederive the KEK and decrypt the wrapped content key.
     *
     * @param enc The ephemeral public key (base64) from the sender.
     * @param wrappedKey The wrapped content key (base64) - contains salt + iv + ciphertext.
     * @param info Optional info parameter for HKDF. Must match what was used in `add`. Defaults to 'key-wrap'.
     * @returns {Promise<CryptoKey>} The unwrapped AES content key.
     */
    async unwrap (
        enc:string,
        wrappedKey:string,
        info?:string
    ):Promise<CryptoKey> {
        // 1. Import the ephemeral public key
        const ephemeralPubKey = await importPublicKey(
            enc,
            EccCurve.X25519,
            KeyUse.Exchange
        )

        // 2. Decode the wrapped key blob and extract salt, iv, and ciphertext
        const wrappedBuf = new Uint8Array(base64ToArrBuf(wrappedKey))
        const salt = wrappedBuf.slice(0, SALT_LENGTH)
        const iv = wrappedBuf.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
        const ciphertext = wrappedBuf.slice(SALT_LENGTH + IV_LENGTH)

        // 3. Derive the same KEK using our private key and the ephemeral public key
        const kek = await deriveKey(
            this.exchangeKey.privateKey,
            ephemeralPubKey,
            salt,
            info || 'key-wrap'
        )

        // 4. Decrypt the wrapped key
        const contentKeyBytes = await crypto.subtle.decrypt(
            { name: DEFAULT_SYMM_ALGORITHM, iv },
            kek,
            toArrayBuffer(ciphertext)
        )

        // 5. Import the content key back as a CryptoKey
        const contentKey = await crypto.subtle.importKey(
            'raw',
            contentKeyBytes,
            { name: DEFAULT_SYMM_ALGORITHM },
            true,
            ['encrypt', 'decrypt']
        )

        return contentKey
    }

    /**
     * Encrypt the given content to the given public key, or encrypt to
     * our own public key if a key is not passed in.
     *
     * This does ECIES style encryption -- a new ephemeral keypair is generated
     * and used to encrypt the message with ephemeral private + recipient public.
     * The public key from the ephemeral keypair is prefixed to the cipher text.
     *
     * @param {string|Uint8Array} content Content to encrypt
     * @param {CryptoKey|string} [recipient] Their public key. Optional b/c we
     *        will use our own public key if not passed in. Can be a CryptoKey
     *        or a base64 encoded string.
     * @param {string} [info] info tag for HKDF. Default is the class property.
     * @param {SymmKey|Uint8Array|string} [aesKey] This is not relevant for most
     *        use cases.
     * @param {SymmKeyLength} [keysize] Default is 256
     * @returns {Promise<ArrayBuffer>} Buffer of ephemeral-public-key + salt +
     *          iv + cipher text
     */
    async encrypt (
        content:string|Uint8Array,
        recipient?:CryptoKey|string|null,  // their public key
        info?:string|null,
        aesKey?:SymmKey|Uint8Array|string|null,
        keysize?:SymmKeyLength|null
    ):Promise<Uint8Array> {
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))

        // publicKey is either passed in or we use our own for note to self
        const _publicKey = (recipient || this.exchangeKey.publicKey)
        let publicKey:CryptoKey
        if (typeof _publicKey === 'string') {
            publicKey = await importPublicKey(
                _publicKey,
                EccCurve.X25519,
                KeyUse.Exchange
            )
        } else {
            publicKey = _publicKey
        }

        // ECIES: Generate ephemeral keypair for this encryption
        const ephemeralKeypair = await EccKeys._createExchangeKeys(true)

        // key is passed in or derived using ephemeral private key
        let key = aesKey || (await deriveKey(
            ephemeralKeypair.privateKey,  // use ephemeral private key
            publicKey,
            salt,
            info || EccKeys.INFO,
            keysize
        ))

        // if a key was passed in, but it is not a CryptoKey instance
        if (!(key instanceof CryptoKey)) {
            key = await deriveKey(
                ephemeralKeypair.privateKey,  // use ephemeral private key
                publicKey,
                salt,
                info || EccKeys.INFO
            )
        }

        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
        const plaintext:Uint8Array = (typeof content === 'string' ?
            new TextEncoder().encode(content) :
            content)

        const ciphertext = await crypto.subtle.encrypt(
            { name: DEFAULT_SYMM_ALGORITHM, iv },
            key,
            toArrayBuffer(plaintext)
        )

        // Export ephemeral public key to prepend to ciphertext
        const ephemeralPubKeyBuf = new Uint8Array(
            await exportPublicKey(ephemeralKeypair)
        )

        // Prepend ephemeral public key, salt and IV to the ciphertext
        const saltBuffer = new Uint8Array(salt)
        const ivBuffer = new Uint8Array(iv)
        const cipherBuf = new Uint8Array(ciphertext)
        const size = ephemeralPubKeyBuf.length + saltBuffer.length +
            ivBuffer.length + cipherBuf.length
        const result = new Uint8Array(size)
        result.set(ephemeralPubKeyBuf, 0)
        result.set(saltBuffer, ephemeralPubKeyBuf.length)
        result.set(ivBuffer, ephemeralPubKeyBuf.length + saltBuffer.length)
        result.set(cipherBuf, ephemeralPubKeyBuf.length + saltBuffer.length +
            ivBuffer.length)

        return result
    }

    /**
     * Encrypt and return as base64 string.
     */
    async encryptAsString (
        content:string|Uint8Array,
        recipient?:CryptoKey|string|null,  // their public key
        info?:string|null,
        aesKey?:SymmKey|Uint8Array|string|null,
        keysize?:SymmKeyLength|null,
    ):Promise<string> {
        const encrypted = await this.encrypt(
            content,
            recipient,
            info || EccKeys.INFO,
            aesKey,
            keysize
        )

        return toString(new Uint8Array(encrypted), 'base64pad')
    }

    /**
     * Decrypt the given message. The encrypted message should be
     * ephemeral public key + salt + iv + cipher text.
     *
     * The ephemeral public key is extracted from the beginning of the message
     * and used with our private key to derive the AES decryption key.
     *
     * @param msg The encrypted content
     * @param {string} aesAlgorithm The algorithm. Default is AES-GCM.
     * @param {string} info Custom "info" parameter
     * @returns {Promise<ArrayBuffer>} The decrypted content.
     */
    async decrypt (
        msg:string|Uint8Array|ArrayBuffer,
        aesAlgorithm?:string|null,
        info?:string|null,
    ):Promise<ArrayBuffer|Uint8Array> {
        // ECIES: Extract ephemeral public key from the beginning of the message
        const encrypted = normalizeToBuf(msg, base64ToArrBuf)
        const ephemeralPubKeyBuf = encrypted.slice(0, X25519_PUBLIC_KEY_LENGTH)

        // ephemeral public key should be prepended to the data
        const ephemeralPublicKey = await webcrypto.subtle.importKey(
            'raw',
            ephemeralPubKeyBuf,
            { name: ECC_EXCHANGE_ALGORITHM },
            true,
            []
        )

        // Extract salt, iv, and ciphertext after the ephemeral public key
        const salt = encrypted.slice(
            X25519_PUBLIC_KEY_LENGTH,
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH
        )
        const iv = encrypted.slice(
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH,
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH + IV_LENGTH
        )
        const ciphertext = encrypted.slice(
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH + IV_LENGTH
        )

        // Derive an AES key with our private key + ephemeral-public-key
        const { privateKey } = this.exchangeKey
        const key = await deriveKey(
            privateKey,
            ephemeralPublicKey,
            salt,
            info || EccKeys.INFO
        )

        // we have the key, now decrypt the message
        const decrypted = await crypto.subtle.decrypt(
            {
                name: aesAlgorithm || DEFAULT_SYMM_ALGORITHM,
                iv,
            },
            key,
            ciphertext
        )

        return decrypted
    }

    /**
     * Decrypt and return as string using ECIES. The encrypted message should be
     * ephemeral public key + salt + iv + cipher text.
     *
     * The ephemeral public key is extracted from the beginning of the message
     * and used with our private key to derive the AES decryption key.
     *
     * @param msg The encrypted content
     * @param {string} aesAlgorithm The algorithm. Default is AES-GCM.
     * @param {string} info Custom "info" parameter
     * @returns {Promise<string>} The decrypted content as a string.
     */
    async decryptAsString (
        msg:string|Uint8Array|ArrayBuffer,
        aesAlgorithm?:string|null,
        info?:string|null,
    ):Promise<string> {
        const dec = await this.decrypt(msg, aesAlgorithm, info)
        return toString(new Uint8Array(dec))
    }

    /**
     * Do DHKE, create a new AES-GCM key.
     *
     * @param {CryptoKey|string|null} [publicKey] Public key to use in DHKE.
     *        Will use our public key if it is not passed in.
     * @param {string} info The info parameter for DHKE. Will use the class
     *        property `INFO` if it is not passed in.
     * @returns {CryptoKey} New AES key
     */
    async getAesKey (
        publicKey?:CryptoKey|string|null,
        info?:string|null,
    ):Promise<CryptoKey> {
        if (!publicKey) {
            publicKey = this.publicExchangeKey
        }

        let pub:CryptoKey
        if (typeof publicKey === 'string') {
            pub = await importPublicKey(
                publicKey,
                EccCurve.X25519,
                KeyUse.Exchange
            )
        } else {
            pub = publicKey
        }

        // Generate a random salt for HKDF
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))

        // Derive AES key using ECDH + HKDF
        const aesKey = await deriveKey(
            this.exchangeKey.privateKey,
            pub,
            salt,
            info || EccKeys.INFO
        )

        return aesKey
    }

    /**
     * Sign the given content using our private write key.
     */
    async sign (msg:Msg, _charsize?:CharSize):Promise<Uint8Array> {
        const encoder = new TextEncoder()
        let data:Uint8Array

        if (typeof msg === 'string') {
            data = encoder.encode(msg)
        } else if (msg instanceof ArrayBuffer) {
            data = new Uint8Array(msg)
        } else {
            data = msg
        }

        const signature = await webcrypto.subtle.sign(
            { name: ECC_WRITE_ALGORITHM },
            this.writeKey.privateKey,
            toArrayBuffer(data)
        )

        return new Uint8Array(signature)
    }

    /**
     * Sign the given content and return as base64 string.
     */
    async signAsString (msg:string, _charsize?:CharSize):Promise<string> {
        const signature = await this.sign(msg, _charsize)
        return toString(signature, 'base64pad')
    }
}

// Attach asString to the prototype method for backward compatibility
Object.assign(EccKeys.prototype.sign, {
    asString: async function (
        this:EccKeys,
        msg:string,
        _charsize?:CharSize
    ):Promise<string> {
        const signature = await this.sign(msg, _charsize)
        return toString(signature, 'base64pad')
    }
})

/**
 * Get the public key from a given keypair.
 *
 * @param {CryptoKeyPair} keypair The keypair to get the public side from.
 * @returns {Promise<ArrayBuffer>} ArrayBuffer of public key material
 */
export async function exportPublicKey(
    keypair:CryptoKeyPair,
    format:'jwk'
):Promise<JsonWebKey>

export async function exportPublicKey(
    keypair:CryptoKeyPair,
    format?:'raw'|'spki'|'pkcs8'
):Promise<ArrayBuffer>

export async function exportPublicKey (
    keypair:CryptoKeyPair,
    format:KeyFormat = 'raw'
):Promise<JsonWebKey|ArrayBuffer> {
    return await crypto.subtle.exportKey(format, keypair.publicKey)
}

export async function importPublicKey (
    base64Key:string,
    curve:EccCurve,
    use:KeyUse
):Promise<PublicKey> {
    checkValidKeyUse(use)
    const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALGORITHM : ECC_WRITE_ALGORITHM
    const uses:KeyUsage[] = use === KeyUse.Exchange ? [] : ['verify']
    const buf = base64ToArrBuf(base64Key)

    // X25519 doesn't use namedCurve in the algorithm parameter
    const algorithm = (curve === EccCurve.X25519) ?
        { name: alg } :
        { name: alg, namedCurve: curve }

    return webcrypto.subtle.importKey(
        'raw',
        buf,
        algorithm,
        true,
        uses
    )
}

export default {
    EccKeys,
    importPublicKey
}

// Add backward compatibility by attaching asString methods to prototypes
Object.assign(EccKeys.prototype.encrypt, {
    asString: async function (
        this: EccKeys,
        content: string | Uint8Array,
        recipient?: CryptoKey | string,
        info?: string,
        aesKey?: SymmKey | Uint8Array | string,
        keysize?: SymmKeyLength
    ): Promise<string> {
        return this.encryptAsString(content, recipient, info, aesKey, keysize)
    }
})

Object.assign(EccKeys.prototype.decrypt, {
    asString: async function (
        this: EccKeys,
        msg: string | Uint8Array | ArrayBuffer,
        aesAlgorithm?: string
    ): Promise<string> {
        return this.decryptAsString(msg, aesAlgorithm)
    }
})

Object.assign(EccKeys.prototype.sign, {
    asString: async function (
        this: EccKeys,
        msg: string,
        _charsize?: CharSize
    ): Promise<string> {
        return this.signAsString(msg, _charsize)
    }
})

/**
 * Check that the given signature is valid with the given message.
 * This uses Ed25519 verification.
 */
export async function verify (
    msg:string|Uint8Array,
    sig:string|Uint8Array,
    signingDid:DID
):Promise<boolean> {
    try {
        const _key = didToPublicKey(signingDid)

        // Verify it's an Ed25519 key
        if (_key.type !== 'ed25519') {
            throw new Error(`Expected Ed25519 key for ECC verification, got ${_key.type}`)
        }

        // Extract raw Ed25519 key from DER encoding
        // DER format has 12-byte header, then 32-byte raw key
        const rawKeyBytes = _key.publicKey.slice(-32)

        // Import the public key for verification
        const publicKey = await webcrypto.subtle.importKey(
            'raw',
            rawKeyBytes,
            { name: ECC_WRITE_ALGORITHM },
            true,
            ['verify']
        )

        // Prepare the message using the same encoding as the sign function
        const encoder = new TextEncoder()
        let data:Uint8Array

        if (typeof msg === 'string') {
            data = encoder.encode(msg)
        } else if (msg instanceof ArrayBuffer) {
            data = new Uint8Array(msg)
        } else {
            data = msg
        }

        // Prepare the signature - handle both string and Uint8Array
        let signature:Uint8Array
        if (typeof sig === 'string') {
            signature = new Uint8Array(base64ToArrBuf(sig))
        } else {
            signature = sig
        }

        // Verify the signature
        const isValid = await webcrypto.subtle.verify(
            { name: ECC_WRITE_ALGORITHM },
            publicKey,
            toArrayBuffer(signature),
            toArrayBuffer(data)
        )

        return isValid
    } catch (_err) {
        return false
    }
}

/**
 * Derive an AES key from X25519 keypair via ECDH + HKDF
 */
async function deriveKey (
    privateKey:CryptoKey,
    publicKey:CryptoKey,
    salt:Uint8Array|ArrayBuffer,
    info:string,
    keysize?:number|null
):Promise<CryptoKey> {
    const encoder = new TextEncoder()
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'X25519', public: publicKey },
        privateKey,
        256
    )

    const hkdfBaseKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        'HKDF',
        false,
        ['deriveKey']
    )

    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt instanceof Uint8Array ? toArrayBuffer(salt) : salt,
            info: encoder.encode(info)
        },
        hkdfBaseKey,
        { name: 'AES-GCM', length: keysize || DEFAULT_SYMM_LENGTH },
        false,
        ['encrypt', 'decrypt']
    )
}
