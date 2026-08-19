import { test } from '@substrate-system/tapzero'
import { get, set, del } from 'idb-keyval'
import { EccKeys } from '../src/ecc/index.js'
import { RsaKeys } from '../src/rsa/index.js'

const CUSTOM = {
    encryptionKeyName: 'test-custom-exchange',
    writeKeyName: 'test-custom-write'
}

/**
 * Start from a known state -- no cached instance, and nothing in
 * indexedDB under the names this file uses.
 */
async function reset ():Promise<void> {
    EccKeys._instance = null
    RsaKeys._instance = null
    await Promise.all([
        del(EccKeys.EXCHANGE_KEY_NAME),
        del(EccKeys.WRITE_KEY_NAME),
        del(RsaKeys.EXCHANGE_KEY_NAME),
        del(RsaKeys.WRITE_KEY_NAME),
        del(CUSTOM.encryptionKeyName),
        del(CUSTOM.writeKeyName)
    ])
}

async function throws (fn:()=>unknown):Promise<Error|null> {
    try {
        await fn()
        return null
    } catch (err) {
        return err as Error
    }
}

test('__________________ delete _______________', async t => {
    await reset()
    t.ok(EccKeys, 'should start with a clean slate')
})

test('delete invalidates the cached instance', async t => {
    await reset()
    const a = await EccKeys.load()
    await a.persist()
    await a.delete()

    const b = await EccKeys.load()
    t.ok(a.DID !== b.DID,
        'should return a new identity, not the deleted one')
})

test('deleted keys cannot be re-persisted', async t => {
    await reset()
    const keys = await EccKeys.load()
    await keys.persist()
    await keys.delete()

    const err = await throws(() => keys.persist())
    t.ok(err, 'persist should reject after delete')
    t.equal(await EccKeys.exist(), false,
        'should not have keys in indexedDB')
})

test('the hasPersisted guard cannot resurrect deleted keys', async t => {
    await reset()
    const keys = await EccKeys.load()
    await keys.persist()
    const did = keys.DID
    await keys.delete()

    const nextKeys = await EccKeys.load()
    if (!nextKeys.hasPersisted) await nextKeys.persist()

    t.ok(nextKeys.DID !== did,
        'should not write the deleted keypair back to indexedDB')
})

test('a deleted instance throws on key access', async t => {
    await reset()
    const keys = await EccKeys.load(CUSTOM)
    await keys.delete()

    t.equal(keys.destroyed, true, 'should have a `destroyed` flag')

    t.ok(await throws(() => keys.publicExchangeKey),
        'publicExchangeKey should throw')
    t.ok(await throws(() => keys.publicWriteKey),
        'publicWriteKey should throw')
    t.ok(await throws(() => keys.privateExchangeKey),
        'privateExchangeKey should throw')
    t.ok(await throws(() => keys.privateWriteKey),
        'privateWriteKey should throw')
    t.ok(await throws(() => keys.exchangeKey),
        'exchangeKey should throw')
    t.ok(await throws(() => keys.writeKey),
        'writeKey should throw')
})

test('a deleted instance cannot sign or encrypt', async t => {
    await reset()
    const keys = await EccKeys.load(CUSTOM)
    await keys.delete()

    t.ok(await throws(() => keys.sign('hello')),
        'sign should reject')
    t.ok(await throws(() => keys.encrypt('hello')),
        'encrypt should reject')
    t.ok(await throws(() => keys.toJson()),
        'toJson should reject')
})

test('delete removes the entries it was loaded from', async t => {
    await reset()

    // a sentinel under the default names, to be sure they survive
    await set(EccKeys.EXCHANGE_KEY_NAME, 'sentinel')

    const keys = await EccKeys.load(CUSTOM)
    await keys.persist()

    t.ok(await get(CUSTOM.encryptionKeyName),
        'should persist under the given exchange key name')
    t.ok(await get(CUSTOM.writeKeyName),
        'should persist under the given write key name')

    await keys.delete()

    t.equal(await get(CUSTOM.encryptionKeyName), undefined,
        'should delete the custom exchange key')
    t.equal(await get(CUSTOM.writeKeyName), undefined,
        'should delete the custom write key')
    t.equal(await get(EccKeys.EXCHANGE_KEY_NAME), 'sentinel',
        'should not touch the default key names')

    await del(EccKeys.EXCHANGE_KEY_NAME)
})

test('load does not overwrite the static key names', async t => {
    await reset()
    await EccKeys.load(CUSTOM)

    t.equal(EccKeys.EXCHANGE_KEY_NAME, 'ecc-exchange',
        'should leave the static exchange name alone')
    t.equal(EccKeys.WRITE_KEY_NAME, 'ecc-write',
        'should leave the static write name alone')
})

test('the instance cache is keyed on the key names', async t => {
    await reset()
    const a = await EccKeys.load({
        encryptionKeyName: 'test-a-exchange',
        writeKeyName: 'test-a-write'
    })
    const b = await EccKeys.load({
        encryptionKeyName: 'test-b-exchange',
        writeKeyName: 'test-b-write'
    })

    t.ok(a.DID !== b.DID,
        'should not return the cached instance for different key names')

    const c = await EccKeys.load({
        encryptionKeyName: 'test-b-exchange',
        writeKeyName: 'test-b-write'
    })
    t.equal(c, b, 'should return the cached instance for the same key names')
})

test('static delete', async t => {
    await reset()
    const keys = await EccKeys.load(CUSTOM)
    await keys.persist()

    await EccKeys.delete(CUSTOM)

    t.equal(await get(CUSTOM.encryptionKeyName), undefined,
        'should delete the exchange key from indexedDB')
    t.equal(await get(CUSTOM.writeKeyName), undefined,
        'should delete the write key from indexedDB')
    t.equal(EccKeys._instance, null, 'should clear the instance cache')
    t.equal(keys.destroyed, true,
        'should destroy the instance that was loaded from those names')
})

test('static delete with no keys in indexedDB', async t => {
    await reset()
    const err = await throws(() => EccKeys.delete(CUSTOM))
    t.equal(err, null, 'should not throw when there is nothing to delete')
})

test('RSA keys delete the same way', async t => {
    await reset()
    const keys = await RsaKeys.load()
    await keys.persist()
    await keys.delete()

    t.equal(keys.destroyed, true, 'should be destroyed')
    t.ok(await throws(() => keys.persist()), 'persist should reject')
    t.equal(await RsaKeys.exist(), false, 'should not exist in indexedDB')

    const next = await RsaKeys.load()
    t.ok(next.DID !== keys.DID, 'should load a new identity')
})

test('clean up after delete tests', async t => {
    await reset()
    await Promise.all([
        del('test-a-exchange'),
        del('test-a-write'),
        del('test-b-exchange'),
        del('test-b-write')
    ])
    t.ok(true, 'cleaned up')
})
