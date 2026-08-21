import { test } from '@substrate-system/tapzero'
import { get, del } from 'idb-keyval'
import { EccKeys } from '../src/ecc/index.js'
import { RsaKeys } from '../src/rsa/index.js'

const CUSTOM = {
    encryptionKeyName: 'test-persist-exchange',
    writeKeyName: 'test-persist-write'
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

test('_________________ persist on load ________________', async t => {
    await reset()
    t.ok(EccKeys, 'should start with a clean slate')
})

test('load saves new keys to indexedDB by default', async t => {
    await reset()
    const keys = await EccKeys.load()

    t.equal(keys.hasPersisted, true,
        'should have the hasPersisted flag')
    t.ok(await get(EccKeys.EXCHANGE_KEY_NAME),
        'should write the exchange key to indexedDB')
    t.ok(await get(EccKeys.WRITE_KEY_NAME),
        'should write the write key to indexedDB')
})

test('the persisted keys survive a reload', async t => {
    await reset()
    const keys = await EccKeys.load()
    const did = keys.DID

    // a fresh page would have no cached instance
    EccKeys._instance = null
    const next = await EccKeys.load()

    t.equal(next.DID, did, 'should return the same identity')
})

test('load with custom names saves under those names', async t => {
    await reset()
    const keys = await EccKeys.load(CUSTOM)

    t.equal(keys.hasPersisted, true, 'should have the hasPersisted flag')
    t.ok(await get(CUSTOM.encryptionKeyName),
        'should write the exchange key under the custom name')
    t.ok(await get(CUSTOM.writeKeyName),
        'should write the write key under the custom name')
    t.equal(await get(EccKeys.EXCHANGE_KEY_NAME), undefined,
        'should not write anything under the default names')
})

test('`persist: false` opts out', async t => {
    await reset()
    const keys = await EccKeys.load({ persist: false })

    t.equal(keys.hasPersisted, false, 'should not have the hasPersisted flag')
    t.equal(await get(EccKeys.EXCHANGE_KEY_NAME), undefined,
        'should not write the exchange key to indexedDB')
    t.equal(await get(EccKeys.WRITE_KEY_NAME), undefined,
        'should not write the write key to indexedDB')
})

test('`persist: false` keys can still be persisted later', async t => {
    await reset()
    const keys = await EccKeys.load({ persist: false })
    await keys.persist()

    t.equal(keys.hasPersisted, true, 'should have the hasPersisted flag')
    t.ok(await get(EccKeys.EXCHANGE_KEY_NAME),
        'should write the exchange key to indexedDB')
})

test('session keys are not written, even though persist defaults to true',
    async t => {
        await reset()
        const keys = await EccKeys.load({ session: true })

        t.equal(keys.isSessionOnly, true, 'should be session only')
        t.equal(keys.hasPersisted, false,
            'should not have the hasPersisted flag')
        t.equal(await get(EccKeys.EXCHANGE_KEY_NAME), undefined,
            'should not write anything to indexedDB')
    }
)

test('load persists a cached instance that was never saved', async t => {
    await reset()
    const created = await EccKeys.create()
    t.equal(created.hasPersisted, false, 'create should not persist')

    const loaded = await EccKeys.load()
    t.equal(loaded, created, 'should return the cached instance')
    t.equal(created.hasPersisted, true, 'load should persist it')
    t.ok(await get(EccKeys.EXCHANGE_KEY_NAME),
        'should write the exchange key to indexedDB')
})

test('RSA keys persist on load too', async t => {
    await reset()
    const keys = await RsaKeys.load()

    t.equal(keys.hasPersisted, true, 'should have the hasPersisted flag')
    t.ok(await get(RsaKeys.EXCHANGE_KEY_NAME),
        'should write the exchange key to indexedDB')
    t.ok(await get(RsaKeys.WRITE_KEY_NAME),
        'should write the write key to indexedDB')
})

test('clean up the persist tests', async t => {
    await reset()
    t.ok(true, 'should clean up')
})
