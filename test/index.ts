import { test } from '@substrate-system/tapzero'
import { verify as ed25519Verify, EccKeys } from '../src/ecc/index.js'
import { verify as rsaVerify, RsaKeys } from '../src/rsa/index.js'
import { verify, keyTypeFromDid, publicKeyToDid } from '../src/crypto.js'
import { type DID } from '../src/types.js'
import './aes.js'
import './rsa.js'
import './ecc.js'
import './delete.js'
import './persist.js'

let rsaKeys:RsaKeys

test('Verify all signature types', async t => {
    const ecc = await EccKeys.create(true)
    const rsa = rsaKeys = await RsaKeys.create(true)
    const message = 'message to sign as string'

    const signature = await ecc.signAsString(message)
    t.equal(typeof signature, 'string', 'Can sign with Ed25519')

    const rsaSig = await rsa.signAsString(message)
    t.equal(typeof rsaSig, 'string', 'Can sign with RSA')

    t.ok(await rsaVerify(
        message,
        rsaSig,
        rsa.DID,
    ), 'rsa signature is ok')

    t.ok(await ed25519Verify(
        message,
        signature,
        ecc.DID,
    ), 'ecc is ok')

    console.log('**ECC DID**', ecc.DID)
    console.log('**RSA DID**', rsa.DID)

    // this should work with either type of signature
    t.ok(await verify({ message, did: ecc.DID, signature }),
        'Generic verify with ECC keys')
    t.ok(await verify({ message, did: rsa.DID, signature: rsaSig }),
        'Can verify RSA with generic function')

    t.ok(!(await verify({
        message,
        did: ecc.DID,
        signature: 'A' + signature.slice(1)
    })), 'Should not verify an invalid Ed25519 signature')

    t.ok(!(await verify({
        message,
        did: rsa.DID,
        signature: 'A' + rsaSig.slice(1)
    })), 'Should not verify an invalid RSA signature')
})

let did:DID
test('public key to DID', async t => {
    const keys = await EccKeys.create()
    const authorDid = await publicKeyToDid(keys.writeKey.publicKey, 'ed25519')
    did = authorDid
    t.ok(did, 'create did')
})

test('key type from DID', async t => {
    const type = keyTypeFromDid(did)
    t.equal(type, 'ed25519', 'should return the key type given a DID')
    const rsaType = keyTypeFromDid(rsaKeys.DID)
    t.equal(rsaType, 'rsa', 'should return RSA type for RSA key')
})

test('Get a DID without passing in the key type', async t => {
    const keys = await EccKeys.create()
    const did = await publicKeyToDid(keys.writeKey.publicKey)
    t.ok(did.includes('did:key'), 'should create a DID string')

    const typeFromDid = keyTypeFromDid(did)
    t.equal(typeFromDid, 'ed25519', 'should return the correct key type')
})

test('all done', () => {
    if (window) {
        // @ts-expect-error tests
        window.testsFinished = true
    }
})
