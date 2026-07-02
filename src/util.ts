import { fromString, toString as uToString } from 'uint8arrays'
import type {
    DID,
    Msg,
    HashAlg,
    SymmKeyOpts,
    SymmKey,
    RsaSize
} from './types.js'
import {
    KeyUse,
    CharSize,
} from './types.js'
import {
    BASE58_DID_PREFIX,
    KEY_USE,
    RSA_SIGN_ALGORITHM,
    RSA_ALGORITHM,
    RSA_DID_PREFIX,
    KEY_TYPE,
    EDWARDS_DID_PREFIX,
    BLS_DID_PREFIX,
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LENGTH,
} from './constants.js'

const webcrypto = globalThis.crypto

export const InvalidKeyUse = new Error('Invalid key use. Please use ' +
    "'encryption' or 'signing")
export const InvalidMaxValue = new Error('Max must be less than 256 and ' +
    'greater than 0')

// Helper function to ensure proper ArrayBuffer type
export function toArrayBuffer (data:Uint8Array):ArrayBuffer {
    return new Uint8Array(data).buffer
}

/**
 * Create a 32 character, DNS-friendly hash of the given DID.
 *
 * @param {DID} did String representation of the DID for the device
 * @returns {string} The 32 character, DNS friendly hash
 */
export async function createDeviceName (did:DID):Promise<string> {
    const normalizedDid = did.normalize('NFD')
    const hashedUsername = await sha256(
        new TextEncoder().encode(normalizedDid)
    )
    return uToString(hashedUsername, 'base32').slice(0, 32)
}

export async function sha256 (bytes:Uint8Array):Promise<Uint8Array> {
    return new Uint8Array(
        await webcrypto.subtle.digest('sha-256', bytes.buffer as ArrayBuffer)
    )
}

export function base64ToArrBuf (string:string):ArrayBuffer {
    const uint8 = fromString(string, 'base64pad')
    return toArrayBuffer(uint8)
}

export const normalizeToBuf = (
    msg:Msg,
    strConv:(str:string)=>ArrayBuffer
):ArrayBuffer => {
    if (typeof msg === 'string') {
        return strConv(msg)
    } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
        // this is the best runtime check I could find for ArrayBuffer/Uint8Array
        const temp = new Uint8Array(msg)
        return temp.buffer
    } else {
        throw new Error('Improper value. Must be a string, ArrayBuffer, Uint8Array')
    }
}

export function normalizeBase64ToBuf (msg:Msg):ArrayBuffer {
    return normalizeToBuf(msg, base64ToArrBuf)
}

export const normalizeUtf8ToBuf = (msg:Msg):ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8))
}

export function strToArrBuf (str:string, charSize:CharSize):ArrayBuffer {
    const view = charSize === 8 ?
        new Uint8Array(str.length) :
        new Uint16Array(str.length)

    for (let i = 0, strLen = str.length; i < strLen; i++) {
        view[i] = str.charCodeAt(i)
    }

    return view.buffer
}

export const normalizeUtf16ToBuf = (msg:Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16))
}

export function normalizeUnicodeToBuf (msg:Msg, charSize:CharSize) {
    switch (charSize) {
        case 8: return normalizeUtf8ToBuf(msg)
        default: return normalizeUtf16ToBuf(msg)
    }
}

export function didToPublicKey (did:string):({
    publicKey:Uint8Array<ArrayBuffer>,
    type:'rsa'|'ed25519'|'bls12-381'
}) {
    if (!did.startsWith(BASE58_DID_PREFIX)) {
        throw new Error(
            'Please use a base58-encoded DID formatted `did:key:z...`')
    }

    const didWithoutPrefix = ('' + did.substring(BASE58_DID_PREFIX.length))
    const magicalBuf = fromString(didWithoutPrefix, 'base58btc')
    const { keyBuffer, type } = parseMagicBytes(toArrayBuffer(magicalBuf))

    return {
        publicKey: new Uint8Array(keyBuffer),
        type
    }
}

/**
 * Parse magic bytes on prefixed key-buffer
 * to determine cryptosystem & the unprefixed key-buffer.
 */
function parseMagicBytes (prefixedKey:ArrayBuffer) {
    // RSA
    if (hasPrefix(prefixedKey, toArrayBuffer(RSA_DID_PREFIX))) {
        return {
            keyBuffer: prefixedKey.slice(RSA_DID_PREFIX.byteLength),
            type: KEY_TYPE.RSA
        }
    // EDWARDS
    } else if (hasPrefix(prefixedKey, toArrayBuffer(EDWARDS_DID_PREFIX))) {
        return {
            keyBuffer: prefixedKey.slice(EDWARDS_DID_PREFIX.byteLength),
            type: KEY_TYPE.Edwards
        }
    // BLS
    } else if (hasPrefix(prefixedKey, toArrayBuffer(BLS_DID_PREFIX))) {
        return {
            keyBuffer: prefixedKey.slice(BLS_DID_PREFIX.byteLength),
            type: KEY_TYPE.BLS
        }
    }

    throw new Error('Unsupported key algorithm. Try using RSA.')
}

const arrBufs = {
    equal: (aBuf:ArrayBuffer, bBuf:ArrayBuffer) => {
        const a = new Uint8Array(aBuf)
        const b = new Uint8Array(bBuf)
        if (a.length !== b.length) return false
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false
        }
        return true
    }
}

export function hasPrefix (prefixedKey:ArrayBuffer, prefix:ArrayBuffer) {
    return arrBufs.equal(prefix, prefixedKey.slice(0, prefix.byteLength))
}

export function toBase64 (arr:Uint8Array|ArrayBuffer) {
    return uToString(
        arr instanceof ArrayBuffer ?
            new Uint8Array(arr) :
            arr,
        'base64pad'
    )
}

export function fromBase64 (str:string) {
    return fromString(str, 'base64pad')
}

export async function importKey (
    key:string|Uint8Array,
    opts?:Partial<SymmKeyOpts>
):Promise<SymmKey> {
    const buf = typeof key === 'string' ? base64ToArrBuf(key) : toArrayBuffer(key)

    return webcrypto.subtle.importKey(
        'raw',
        buf,
        {
            name: opts?.alg || DEFAULT_SYMM_ALGORITHM,
            length: opts?.length || DEFAULT_SYMM_LENGTH,
        },
        true,
        ['encrypt', 'decrypt']
    )
}

export function randomBuf (
    length:number,
    { max }:{ max:number } = { max: 255 }
):ArrayBuffer {
    if (max < 1 || max > 255) {
        throw InvalidMaxValue
    }

    const arr = new Uint8Array(length)

    if (max === 255) {
        webcrypto.getRandomValues(arr)
        return arr.buffer
    }

    let index = 0
    const interval = max + 1
    const divisibleMax = Math.floor(256 / interval) * interval
    const tmp = new Uint8Array(1)

    while (index < arr.length) {
        webcrypto.getRandomValues(tmp)
        if (tmp[0] < divisibleMax) {
            arr[index] = tmp[0] % interval
            index++
        }
    }

    return arr.buffer
}

export function joinBufs (
    fst:ArrayBuffer|Uint8Array,
    snd:ArrayBuffer|Uint8Array
):ArrayBuffer {
    const view1 = fst instanceof ArrayBuffer ?
        new Uint8Array(fst) :
        new Uint8Array(toArrayBuffer(fst))

    const view2 = snd instanceof ArrayBuffer ?
        new Uint8Array(snd) :
        new Uint8Array(toArrayBuffer(snd))

    const joined = new Uint8Array(view1.length + view2.length)
    joined.set(view1)
    joined.set(view2, view1.length)
    return joined.buffer
}

export async function makeEccKeypair (
    curve:'X25519'|'ECDSA',
    uses:'encyrpt'|'sign',
    extractable:boolean = false
):Promise<CryptoKeyPair> {
    const keys = await webcrypto.subtle.generateKey(
        { name: curve },  // X25519 or ECDSA
        extractable,
        KEY_USE[uses]
    ) as CryptoKeyPair

    return keys
}

export async function makeRSAKeypair (
    size:RsaSize,
    hashAlg:HashAlg,
    use:KeyUse,
    extractable:boolean = false
):Promise<CryptoKeyPair> {
    const isExtractable = extractable
    if (!(Object.values(KeyUse).includes(use))) {
        throw new Error('invalid key use')
    }
    const alg = use === KeyUse.Exchange ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM
    const uses:KeyUsage[] = (use === KeyUse.Exchange ?
        ['encrypt', 'decrypt'] :
        ['sign', 'verify'])

    return webcrypto.subtle.generateKey({
        name: alg,
        modulusLength: size,
        publicExponent: publicExponent(),
        hash: { name: hashAlg }
    } as RsaHashedKeyGenParams, isExtractable, uses)
}

function publicExponent ():Uint8Array {
    return new Uint8Array([0x01, 0x00, 0x01])
}

/**
 * Create a 32 character, DNS-friendly hash of the given DID.
 *
 * @param {DID} did String representation of the DID for the device
 * @returns {string} The 32 character, DNS friendly hash
 */
export async function getDeviceName (did:DID|string):Promise<string> {
    const hashedUsername = await sha256(
        new TextEncoder().encode(did.normalize('NFD'))
    )

    return uToString(hashedUsername, 'base32').slice(0, 32)
}
