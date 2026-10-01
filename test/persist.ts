import { test } from '@substrate-system/tapzero'
import { get, del } from 'idb-keyval'
import { EccKeys } from '../src/ecc/index.js'
import { RsaKeys } from '../src/rsa/index.js'

const CUSTOM = {
    encryptionKeyName: 'test-persist-exchange',
    writeKeyName: 'test-persist-write'
}

const DB_KEY = 'test-create-db-key'

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

test('create with dbKey persists both ECC keypairs', async t => {
    await reset()
    const keys = await EccKeys.create(false, false, { dbKey: DB_KEY })
    await keys.persist()

    t.equal(keys.exchangeKeyName, `${DB_KEY}.ecc-exchange`,
        'should prefix the ECC exchange key name')
    t.equal(keys.writeKeyName, `${DB_KEY}.ecc-write`,
        'should prefix the ECC signing key name')
    t.ok(await get(`${DB_KEY}.ecc-exchange`),
        'should persist the ECC exchange key under the prefixed name')
    t.ok(await get(`${DB_KEY}.ecc-write`),
        'should persist the ECC signing key under the prefixed name')

    await keys.delete()
})

test('create with dbKey persists both RSA keypairs', async t => {
    await reset()
    const keys = await RsaKeys.create(false, false, { dbKey: DB_KEY })
    await keys.persist()

    t.equal(keys.exchangeKeyName, `${DB_KEY}.rsa-exchange-key`,
        'should prefix the RSA exchange key name')
    t.equal(keys.writeKeyName, `${DB_KEY}.rsa-write-key`,
        'should prefix the RSA signing key name')
    t.ok(await get(`${DB_KEY}.rsa-exchange-key`),
        'should persist the RSA exchange key under the prefixed name')
    t.ok(await get(`${DB_KEY}.rsa-write-key`),
        'should persist the RSA signing key under the prefixed name')

    await keys.delete()
})

test('create with dbKey does not change the class default names',
    async t => {
        await reset()
        const prefixed = await EccKeys.create(false, false, { dbKey: DB_KEY })

        t.equal(EccKeys.EXCHANGE_KEY_NAME, 'ecc-exchange',
            'should leave the static exchange key name alone')
        t.equal(EccKeys.WRITE_KEY_NAME, 'ecc-write',
            'should leave the static write key name alone')

        const plain = await EccKeys.create()
        t.equal(plain.exchangeKeyName, 'ecc-exchange',
            'a later create without dbKey should use the default name')
        t.equal(plain.writeKeyName, 'ecc-write',
            'a later create without dbKey should use the default name')
        t.equal(prefixed.exchangeKeyName, `${DB_KEY}.ecc-exchange`,
            'the prefixed instance should keep its own name')
    }
)

test('concurrent creates with different dbKeys keep their own names',
    async t => {
        await reset()
        const [alice, bob] = await Promise.all([
            EccKeys.create(false, false, { dbKey: 'alice' }),
            EccKeys.create(false, false, { dbKey: 'bob' })
        ])

        t.equal(alice.exchangeKeyName, 'alice.ecc-exchange',
            'alice should get the alice prefix')
        t.equal(alice.writeKeyName, 'alice.ecc-write',
            'alice should get the alice prefix')
        t.equal(bob.exchangeKeyName, 'bob.ecc-exchange',
            'bob should get the bob prefix')
        t.equal(bob.writeKeyName, 'bob.ecc-write',
            'bob should get the bob prefix')
    }
)

test('load with dbKey does not change the class default names', async t => {
    await reset()
    const prefixed = await EccKeys.load({ dbKey: DB_KEY })

    t.equal(prefixed.exchangeKeyName, `${DB_KEY}.ecc-exchange`,
        'should use the prefixed name on the instance')
    t.equal(EccKeys.EXCHANGE_KEY_NAME, 'ecc-exchange',
        'should leave the static exchange key name alone')
    t.equal(EccKeys.WRITE_KEY_NAME, 'ecc-write',
        'should leave the static write key name alone')

    EccKeys._instance = null
    const plain = await EccKeys.load()
    t.equal(plain.exchangeKeyName, 'ecc-exchange',
        'a later load without dbKey should use the default name')

    await prefixed.delete()
})

test('load with dbKey restores both ECC keypairs', async t => {
    await reset()
    EccKeys.EXCHANGE_KEY_NAME = 'ecc-exchange'
    EccKeys.WRITE_KEY_NAME = 'ecc-write'

    const source = await EccKeys.create(false, false, { dbKey: DB_KEY })
    await source.persist()
    const did = source.DID

    EccKeys._instance = null
    EccKeys.EXCHANGE_KEY_NAME = 'ecc-exchange'
    EccKeys.WRITE_KEY_NAME = 'ecc-write'
    const keys = await EccKeys.load({ dbKey: DB_KEY })

    t.equal(keys.DID, did, 'should restore the ECC identity')
    t.equal(keys.exchangeKeyName, `${DB_KEY}.ecc-exchange`,
        'should use the prefixed ECC exchange key name')
    t.equal(keys.writeKeyName, `${DB_KEY}.ecc-write`,
        'should use the prefixed ECC signing key name')

    await del(`${DB_KEY}.ecc-exchange`)
    await del(`${DB_KEY}.ecc-write`)
})

test('load with dbKey restores both RSA keypairs', async t => {
    await reset()
    RsaKeys.EXCHANGE_KEY_NAME = 'rsa-exchange-key'
    RsaKeys.WRITE_KEY_NAME = 'rsa-write-key'

    const source = await RsaKeys.create(false, false, { dbKey: DB_KEY })
    await source.persist()
    const did = source.DID

    RsaKeys._instance = null
    RsaKeys.EXCHANGE_KEY_NAME = 'rsa-exchange-key'
    RsaKeys.WRITE_KEY_NAME = 'rsa-write-key'
    const keys = await RsaKeys.load({ dbKey: DB_KEY })

    t.equal(keys.DID, did, 'should restore the RSA identity')
    t.equal(keys.exchangeKeyName, `${DB_KEY}.rsa-exchange-key`,
        'should use the prefixed RSA exchange key name')
    t.equal(keys.writeKeyName, `${DB_KEY}.rsa-write-key`,
        'should use the prefixed RSA signing key name')

    await del(`${DB_KEY}.rsa-exchange-key`)
    await del(`${DB_KEY}.rsa-write-key`)
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
