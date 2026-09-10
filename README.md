# keys
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/keys/nodejs.yml?style=flat-square)](https://github.com/substrate-system/keys/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/keys?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/keys?cache-control=no-cache)](https://packagephobia.com/result?p=@substrate-system/keys)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Create and store keypairs in the browser with the
[web crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

Use [`indexedDB`](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)
to store
[non-extractable keypairs](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey#extractable)
in the browser. "Non-extractable" means that the browser prevents you from ever
reading the private key, but the keys can still be persisted and
re-used indefinitely.

>
> [!TIP]
> Use the [persist method](https://developer.mozilla.org/en-US/docs/Web/API/StorageManager/persist)
> to request that the browser not delete from `indexedDB`.
>

Each instance of `Keys` has two keypairs &mdash; one for signing, and another
for encrypting. 

See also,
[the API docs generated from typescript](https://substrate-system.github.io/keys/).

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Exports](#exports)
  * [ESM](#esm)
  * [Common JS](#common-js)
  * [pre-bundled JS](#pre-bundled-js)
    + [copy](#copy)
    + [HTML](#html)
  * [`@substrate-system/keys`](#substrate-systemkeys)
  * [`ecc`](#ecc)
  * [`rsa`](#rsa)
  * [import `aes`](#import-aes)
  * [`crypto`](#crypto)
    + [`crypto.verify`](#cryptoverify)
    + [`crypto.keyTypeFromDid`](#cryptokeytypefromdid)
- [Get started](#get-started)
  * [Verify a signature](#verify-a-signature)
  * [ECC keys](#ecc-keys)
    + [Create a keypair](#create-a-keypair)
    + [Encrypt a Message](#encrypt-a-message)
    + [Multiple devices](#multiple-devices)
  * [some notes about the `keys` instance](#some-notes-about-the-keys-instance)
    + [`keys.DID`](#keysdid)
    + [`keys.getDeviceName` / `keys.deviceName`](#keysgetdevicename--keysdevicename)
    + [`keys.hasPersisted`](#keyshaspersisted)
    + [`keys.destroyed`](#keysdestroyed)
    + [`keys.publicExchangeKey`](#keyspublicexchangekey)
    + [`keys.publicExchangeKeyAsString()`](#keyspublicexchangekeyasstring)
    + [`keys.publicWriteKey`](#keyspublicwritekey)
    + [`keys.publicWriteKeyAsString()`](#keyspublicwritekeyasstring)
  * [Delete a keypair](#delete-a-keypair)
    + [`Keys.delete()`](#keysdelete)
  * [Sign and Verify Something](#sign-and-verify-something)
  * [encrypt something](#encrypt-something)
    + [`keys.encrypt` methods](#keysencrypt-methods)
    + [`keys.encryptAsString` methods](#keysencryptasstring-methods)
  * [decrypt something](#decrypt-something)
- [Examples](#examples)
  * [Create a new `Keys` instance](#create-a-new-keys-instance)
    + [Parameters](#parameters)
    + [`.create()` example](#create-example)
  * [Get a hash of the DID](#get-a-hash-of-the-did)
    + [Static `deviceName` method](#static-devicename-method)
    + [Instance `getdeviceName` method](#instance-getdevicename-method)
  * [Persist the keys](#persist-the-keys)
    + [`.persist`](#persist)
    + [`.persist` example](#persist-example)
  * [Restore from indexedDB](#restore-from-indexeddb)
    + [`static .load`](#static-load)
    + [Parameters](#parameters-1)
    + [example](#example)
  * [Sign something](#sign-something)
    + [example](#example-1)
  * [Get a signature as a string](#get-a-signature-as-a-string)
    + [`keys.signAsString(msg)`](#keyssignasstringmsg)
    + [Backward compatibility: `keys.sign.asString(msg)`](#backward-compatibility-keyssignasstringmsg)
  * [Verify a signature](#verify-a-signature-1)
  * [Encrypt a key](#encrypt-a-key)
    + [example](#example-2)
    + [encrypt a key, return a string](#encrypt-a-key-return-a-string)
    + [format](#format)
  * [Asymmetrically encrypt some arbitrary data](#asymmetrically-encrypt-some-arbitrary-data)
    + [example](#example-3)
  * [Asymmetrically encrypt a string, return a new string](#asymmetrically-encrypt-a-string-return-a-new-string)
    + [`keys.decryptAsString`](#keysdecryptasstring)
  * [Decrypt a message](#decrypt-a-message)
  * [In memory only](#in-memory-only)
- [AES](#aes)
  * [`create`](#create)
  * [`export`](#export)
    + [`aes.export` example](#aesexport-example)
  * [`export.asString`](#exportasstring)
    + [`export.asString` example](#exportasstring-example)
  * [`AES.encrypt`](#aesencrypt)
  * [`AES.decrypt`](#aesdecrypt)
- [See also](#see-also)

<!-- tocstop -->

</details>


## Install

```sh
npm i -S @substrate-system/keys
```

## Exports

This exposes ESM and common JS via
[package.json `exports` field](https://nodejs.org/api/packages.html#exports).


### ESM

```js
import { EccKeys, verify } from '@substrate-system/keys/ecc'
import { RsaKeys, verify } from '@substrate-system/keys/rsa'
import { AES } from '@substrate-system/keys/aes'
```

### Common JS

```js
const { EccKeys, verify } = require('@substrate-system/keys/ecc')
const { RsaKeys, verify } = require('@substrate-system/keys/rsa')
const { AES } = require('@substrate-system/keys/aes')
```

### pre-bundled JS

This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@substrate-system/keys/dist/index.min.js ./public/keys.min.js
```

#### HTML
```html
<script type="module" src="./keys.min.js"></script>
```


### `@substrate-system/keys`

Import everything.

```js
import * as keys from '@substrate-system/keys'
```

### `ecc`

Import functions for Ed25519 signatures and X25519 encryption.

```js
import {
  EccKeys,
  exportPublicKey,
  importPublicKey,
  verify
} from '@substrate-system/keys/ecc' 
```

### `rsa`

Import RSA functions.

```js
import {
  RsaKeys,
  encryptKeyTo,
  encryptTo,
  verify,
  publicKeyToDid,
  getPublicKeyAsUint8Array
} from '@substrate-system/keys/rsa' 
```

### [import `aes`](#aes)

Import AES (symmetric) encryption only.

```js
import {
  AES,
  importAesKey
} from '@substrate-system/keys/aes'
```

### `crypto`

Some miscellaneous functions.

```js
import {
  verify,
  keyTypeFromDid,
  publicKeyToDid
} from '@substrate-system/keys/crypto'
```

#### `crypto.verify`

The `verify` function exposed here will work with either RSA or Ed25519
signatures.

```js
const eccOk = await verify({ message, did: ecc.DID, signature: eccSig })
const rsaOk = await verify({ message, did: rsa.DID, signature: rsaSig })
```

#### `crypto.keyTypeFromDid`

Return a string either 'rsa' or 'ed25519' given a DID.

```js
const type = keyTypeFromDid(eccKeys.DID)
// 'ed25519'

const rsaType = keyTypeFromDid(rsaKeys.DID)
// 'rsa'
```


------------------------------------------------------


## Get started

### Verify a signature

This is exposed as a separate import so that you do not need to bundle all of
`keys` just to verify a signature.

```js
import { verify } from '@substrate-system/keys/crypto'

// ed25519
const isOk = await verify({ message, publicKey: ecc.DID, signature })

// RSA
const isOk = await verify({ message, publicKey: rsa.DID, signature })
```

### ECC keys

#### Create a keypair

Create a new keypair, then save it in `indexedDB`.

ECC is now supported in all major browsers.

```js
import { EccKeys, verify } from '@substrate-system/keys/ecc'

// create a keypair, and save it to indexedDB
const keys = await EccKeys.load()

// ... sometime in the future ...
// get the same keys back from indexedDB
const keysAgain = await EccKeys.load()

console.assert(keys.DID === keysAgain.DID)  // true
```

#### Encrypt a Message

ECC encryption uses the ECIES (Elliptic Curve Integrated Encryption Scheme)
pattern. For each encrypted message:

1. A new ephemeral X25519 keypair is generated
2. A new AES key is generated with the ephemeral private key and recipient's
   public key.
3. The message is encrypted with the AES key.
4. The ephemeral public key is prepended to the ciphertext

To decrypt:

1. The recipient extracts the ephemeral public key, salt, and IV from
   the ciphertext
2. The recipient's private key is combined with the ephemeral public key via
   ECDH to get a shared secret
3. Recipient uses HKDF with the shared secret and salt to derive the same AES key
4. Use the AES key and IV to decrypt the message

Note that this does **not** provide forward secrecy &mdash; if the recipient's
long-term private key is compromised, an attacker can decrypt past messages by
extracting the ephemeral public key from the ciphertext and deriving the
shared secret for each message.

The good news is that this *would provide* forward secrecy for the sender's
keys. If the sender's long-term private key is compormised, then past
messages remain illegible because they were each created with a new keypair,
the secret side of which has been discarded.

For true forward secrecy, you would want both parties to use ephemeral keys,
like with
[Signal's double ratchet protocol](https://signal.org/docs/specifications/doubleratchet/).


**Ciphertext format:**

```
[32-byte ephemeral public key][16-byte salt][12-byte IV][ciphertext]
```


```ts
import { EccKeys } from '@substrate-system/keys/ecc'

const alice = await EccKeys.create()
const bob = await EccKeys.create()

// Alice encrypts a message to Bob's public key
const message = 'Hello Bob!'
const encrypted = await alice.encrypt(message, bob.publicExchangeKey)

// Bob decrypts using his private key + the ephemeral public key from the ciphertext
const decrypted = await bob.decryptAsString(encrypted)
console.log(decrypted)  // 'Hello Bob!'

// Encrypt to self (note to self)
const selfEncrypted = await alice.encrypt('Secret note')
const selfDecrypted = await alice.decryptAsString(selfEncrypted)
```

#### Multiple devices

Multiple devices need to read the same data. Generate a random AES key for the
data encryption, then encrypt that AES key to each device's public key with
`wrap` and `unwrap` methods.

See [asymmetric docs](./docs-asymmetric/README.md) for more about how
this works.

* Use `wrap()` to encrypt an AES key for a new device's public key
* Use `unwrap()` on the new device to recover the AES key
* Add devices without re-encrypting the entire dataset


```ts
import { EccKeys } from '@substrate-system/keys/ecc'
import { AES } from '@substrate-system/keys/aes'

// Device 1 has a symmetric key for encrypting data
const device1 = await EccKeys.create()
const contentKey = await AES.create({ length: 256 })

// Encrypt some data.
// (AES.encrypt automatically prepends iv to ciphertext).
const message = 'secret data for all devices'
const encrypted = await AES.encrypt(
    new TextEncoder().encode(message),
    contentKey
)

// ... device 1 needs to obtain device 2's public exchange key ...

// wrap the content key for device 2
const wrapped = await device1.wrap(contentKey, device2.publicExchangeKey)

console.log(wrapped)
// {
//   enc: 'base64-encoded-ephemeral-public-key...',
//   wrappedKey: 'base64-encoded-wrapped-content-key...'
// }

// Store encrypted data + wrapped key entries for each device


// -----------------------------------------
// device 2
// -----------------------------------------

// ... device 2 needs to obtain the wrapped key ...

const device2 = await EccKeys.create()

// Device 2 unwraps the content key
const device2ContentKey = await device2.unwrap(wrapped.enc, wrapped.wrappedKey)

// Device 2 decrypts the data with the unwrapped key
// (AES.decrypt automatically extracts iv from the encrypted data)
const decrypted = await AES.decrypt(encrypted, device2ContentKey)


console.log(new TextDecoder().decode(decrypted))
// => 'secret data for all devices'
```

### some notes about the `keys` instance

#### `keys.DID`

```js
'did:key:z13V3Sog2YaUKhdGCmgx9UZuW...'
```

This is the [DID string](https://www.w3.org/TR/did-1.0/) for the signing key for
this instance. The DID looks like this:

##### Ed25519 DID

```
did:key:zStERvoWtx7FQS432smzbGENZHjsN55X8pUZ3np8DXGhZFf3TCorijCPeJoLytwb
```

##### RSA DID

```
did:key:z13V3Sog2YaUKhdGCmgx9UZuW1o1ShFJYc6DvGYe7NTt689NoL2HdpC46K4PjfsUVAopaqmnySjJV8T6K9dMB2FUXhqfKYLUz9o9fA7xkgiNr25sUQq4vJPuPfP1kbSqtYXe5V2CZTUMucF2jfNMrWjHHRUZpEzPwGeZd5prsu9pxnVhPKnVxxKTJAVqQCp3CDRASeYKQmqVRmyPSrdQaYz4AoQxaBd52mNC7dEC4xXKbVw45dhQc52j5chR8YKCeaNANWh8DEZ7U8Dtb89PL5qP8817oxswQhz4e97p8EGtJDVrGbCXN4EucnpYaacRane4YPcmevs1pMYV8iqzJd8UZLWtDcUBNrCkeVTdnzXnM4Rq9sWiFwF3nYk6fxqfUZDfYyfPtxacSoGaSjo38ye
```

#### `keys.getDeviceName` / `keys.deviceName`

Return a 32 character, DNS friendly hash of the signing public key.

```js
const name = await keys.getDeviceName()

// a promise is exposed as property `deviceName`
const name = await keys.deviceName
```

#### `keys.hasPersisted`

A flag indicating whether these keys are saved in `indexedDB`. It is `true`
after `.persist`, and after any `.load` that did not opt out with
`{ persist: false }`.

#### `keys.destroyed`

A flag indicating whether [`.delete`](#delete-a-keypair) has been called. A
destroyed keypair is terminal -- the key material is gone, and any use of it
throws a `KeysDeletedError`.

#### `keys.publicExchangeKey`

The public encryption `CryptoKey`. For ECC keys, this is the X25519 exchange key.
For RSA keys, this is the RSA encryption key.

#### `keys.publicExchangeKeyAsString()`

Get the public encryption key as a `base64` string. For other formats,
[see below](#format-options).

```ts
{
  async publicExchangeKeyAsString (format?:SupportedEncodings):Promise<string>
}
```

#### `keys.publicWriteKey`

The public signing `CryptoKey`. This is the Ed25519 or RSA signing key.

#### `keys.publicWriteKeyAsString()`

Get the public signing key as a string.

```ts
{
  async publicWriteKeyAsString (format?:SupportedEncodings):Promise<string>
}
```

### Delete a keypair

Delete the keypair. This deletes the keys from `indexedDB`, drops the
in-memory key material, and clears the instance cache, so `load` will not
hand these keys out again.

```js
await keys.delete()
```

`delete` is terminal. Afterwards the instance is `destroyed`, and using it
throws a `KeysDeletedError`. That includes `persist`, so the common
"make sure my keys are saved" guard cannot write a deleted keypair back
into `indexedDB`.

```js
await keys.delete()

keys.destroyed  // => true

// all of these throw
keys.publicExchangeKey
await keys.sign('hello')
await keys.encrypt('hello')
if (!keys.hasPersisted) await keys.persist()
```

The names deleted are the ones the instance was loaded with, so keys
loaded under custom names delete the custom entries.

```js
const keys = await EccKeys.load({
    encryptionKeyName: 'my-exchange-key',
    writeKeyName: 'my-write-key'
})

// deletes 'my-exchange-key' and 'my-write-key'
await keys.delete()
```

#### `Keys.delete()`

Delete a stored keypair without loading it first. This is the companion to
the static `exist` method. It deletes the given entries from `indexedDB`,
and destroys the cached instance if there is one for those names.

```ts
{
  static async delete (opts?:{
      encryptionKeyName?:string,
      writeKeyName?:string
  }):Promise<void>
}
```

```js
import { EccKeys } from '@substrate-system/keys/ecc'

await EccKeys.delete()

// or, if you used custom names
await EccKeys.delete({
    encryptionKeyName: 'my-exchange-key',
    writeKeyName: 'my-write-key'
})
```

--------------------------------------------------------------------------


### Sign and Verify Something

`.verify` takes the content, the signature, and the DID for the public key
used to sign. The DID is exposed as the property `.DID` on a `Keys` instance.

>
> [!NOTE]  
> `verify` is exposed as a separate function, so you don't
> have to include all of `Keys` just to verify a signature.
>

```js
import { RsaKeys, verify } from '@substrate-system/keys/rsa'
// or: import { EccKeys, verify } from '@substrate-system/keys/ecc'

const keys = await RsaKeys.create()
// or: const keys = await EccKeys.create()

// sign something
const sig = await keys.signAsString('hello string')
// or string format: const sig = await keys.sign.asString('hello string')

// verify the signature
const isOk = await verify('hello string', sig, keys.DID)
```

### encrypt something
Take the public key we are encrypting to, return encrypted content.

#### `keys.encrypt` methods

Encrypt something, return a Uint8Array.

**ECC:**

>
> [!NOTE]  
> `recipient` is optional. If it is omitted, then this will encrypt to
> its own public key, a "note to self."
>

```ts
async encrypt (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,  // their public key
  info?:string,
  aesKey?:SymmKey|Uint8Array|string,
  keysize?:SymmKeyLength
):Promise<Uint8Array>
```

**RSA:**
```ts
async encrypt (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,
  aesKey?:SymmKey|Uint8Array|string,  // For RSA, can pass in AES key
  keysize?:SymmKeyLength,
):Promise<Uint8Array>
```

#### `keys.encryptAsString` methods

Encrypt something, return a string.

**ECC:**
```ts
async encryptAsString (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,
  info?:string,
  aesKey?:SymmKey|Uint8Array|string,
  keysize?:SymmKeyLength,
):Promise<string>
```

**RSA:**
```ts
async encryptAsString (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,
  aesKey?:SymmKey|Uint8Array|string,
  keysize?:SymmKeyLength,
):Promise<string>
```

```js
import { encryptTo } from '@substrate-system/keys/rsa'  // RSA version

// need to know the public key we are encrypting for
const publicKey = await keys.publicExchangeKeyAsString()  // Both ECC and RSA

const encrypted = await encryptTo({
  content: 'hello public key',
  publicKey
})  // => ArrayBuffer

const encrypted = await encryptTo.asString({
  content: 'hello public key',
  publicKey
})  // => <encrypted text>
```

### decrypt something
A `Keys` instance has a method `decrypt`. The `encryptedMessage` argument is
an `ArrayBuffer`, as returned from `encryptTo`, above.

```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

const keys = await EccKeys.create()
// or: const keys = await RsaKeys.create()

// This will decrypt the message using our own public key
const decrypted = await keys.decrypt(encryptedMsg)
```

----------------------------------------------------------------------

## Examples

### Create a new `Keys` instance

Use the factory function `EccKeys.create` or `RsaKeys.create`. The optional parameters,
`encryptionKeyName` and `writeKeyName`, are added as properties to the
`keys` instance. These are used as indexes for saving the keys in `indexedDB`.

**ECC:**
```ts
class EccKeys {
  static EXCHANGE_KEY_NAME:string = 'ecc-exchange'
  static WRITE_KEY_NAME:string = 'ecc-write'

  static async create (
    session?:boolean,  // default false
    extractable?:boolean,
    keys?:{
        exchangeKeys?:CryptoKeyPair|null,
        writeKeys?:CryptoKeyPair|null,
    }
):Promise<EccKeys>
```

**RSA:**
```ts
class RsaKeys {
  static EXCHANGE_KEY_NAME:string = 'rsa-exchange'
  static WRITE_KEY_NAME:string = 'rsa-write'

  static async create (
    session?:boolean,  // defaut false
    extractable?:boolean,
    keys?:{
        exchangeKeys?:CryptoKeyPair|null,
        writeKeys?:CryptoKeyPair|null,
    }
  ):Promise<RsaKeys> {
}
```

#### Parameters

- `session` (optional, boolean): If `true`, keys are created in memory only and won't be saved to `indexedDB` even if `persist()` is called.
- `extractable` (optional, boolean): If `true`, creates extractable keys that can be exported/read. Defaults to `false` for security.

>
> [!WARNING]  
> Set `extractable: true` only when you need to export private keys.
> Non-extractable keys (default) are better for security.
>


#### `.create()` example

Use the factory function b/c async.

```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

// Create non-extractable keys (recommended)
const keys = await EccKeys.create()

// Create extractable keys (only when export is needed)
const extractableKeys = await EccKeys.create(false, true)

// Create session-only, extractable keys
const sessionKeys = await EccKeys.create(true, true)

// Session-only keys are not persisted.
```

### Get a hash of the DID
Get a 32-character, DNS-friendly string of the hash of the given `DID`.
Available as static or instance method. If called as an instance method,
this will use the `DID` assigned to the given `Keys` instance.

The static method requires a `DID` string to be passed in.

#### Static `deviceName` method

```ts
class EccKeys {  // or RsaKeys
  static async deviceName (did:DID):Promise<string>
}
```

#### Instance `getdeviceName` method

If used as an instance method, this will use the `DID` assigned to the instance.

```ts
class EccKeys {  // or RsaKeys
  async getDeviceName ():Promise<string>
}
```

### Persist the keys
Save the keys to `indexedDB`. This depends on the values of the static class
properties `EXCHANGE_KEY_NAME` and `WRITE_KEY_NAME`.
Set them if you want to change the indexes under which the keys are
saved to `indexedDB`.

Defaults for indexedDB:

- **ECC**: `'ecc-exchange'` and `'ecc-write'`
- **RSA**: `'rsa-exchange-key'` and `'rsa-write-key'`

#### `.persist`

```ts
class EccKeys {  // or RsaKeys
  async persist ():Promise<void>
}
```

You only need this for keys made with [`.create`](#create-a-new-keys-instance), or
for a [`.load`](#static-load) that opted out with `{ persist: false }`.
Otherwise `.load` has already saved them.

#### `.persist` example
```js
import { EccKeys } from '@substrate-system/keys/ecc'

const keys = await EccKeys.create()
EccKeys.EXCHANGE_KEY_NAME = 'encryption-key-custom-name'
EccKeys.WRITE_KEY_NAME = 'signing-key-custom-name'
await keys.persist()
```

### Restore from indexedDB
Create a `Keys` instance from data saved to `indexedDB`. Pass in different
`indexedDB` key names for the keys if you need to.

If there is nothing saved yet, `.load` creates a new keypair *and saves it*,
so the keys you get back are durable -- reload the page, call `.load` again,
and you get the same identity. There is no separate `.persist` step to
remember. Pass `{ persist: false }` if you want the old two-step behavior.

#### `static .load`
```ts
class EccKeys {  // or RsaKeys
    static async load (opts?:{
      encryptionKeyName?:string,
      writeKeyName?:string,
      session?:boolean,
      extractable?:boolean,
      persist?:boolean,
    }):Promise<EccKeys>
}
```

#### Parameters

- `encryptionKeyName` (optional, string): Custom name for the encryption key in `indexedDB`
- `writeKeyName` (optional, string): Custom name for the signing key in `indexedDB`
- `session` (optional, boolean): If `true`, creates session-only keys if no keys exist in `indexedDB`
- `extractable` (optional, boolean): If `true` and keys don't exist in `indexedDB`, new keys will be created as extractable. Defaults to `false`.
- `persist` (optional, boolean): Save the keys to `indexedDB` before returning. Defaults to `true`. Session keys are never written, so `session: true` wins over this.

#### example

```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

// Load existing keys from indexedDB, or create and save new
// non-extractable ones
const newKeys = await EccKeys.load()
console.log(newKeys.hasPersisted)  // true

// Load with custom options
const customKeys = await EccKeys.load({
  encryptionKeyName: 'my-custom-encryption-key',
  writeKeyName: 'my-custom-signing-key',
  extractable: true  // If keys don't exist, create them as extractable
})

// Opt out of saving -- you are responsible for calling `.persist`
const unsaved = await EccKeys.load({ persist: false })
console.log(unsaved.hasPersisted)  // false
await unsaved.persist()
```


### Sign something
Create a new signature for the given input.

**ECC:**
```ts
async sign (msg:Msg, _charsize?:CharSize):Promise<Uint8Array>
```

**RSA:**
```ts
async sign (
  msg:Msg,
  charsize:CharSize = DEFAULT_CHAR_SIZE
):Promise<Uint8Array>
```

#### example
```js
const sig = await keys.sign('hello signatures')
```

### Get a signature as a string

#### `keys.signAsString(msg)`

Sign a message and return the signature as a base64 encoded string.

```ts
{
  async signAsString (msg:string, charsize?:CharSize):Promise<string>
}
```

```js
const sig = await keys.signAsString('hello string')
// => ubW9PIjb360v...
```

#### Backward compatibility: `keys.sign.asString(msg)`

For backward compatibility, the `.asString` method is still available:

```js
const sig = await keys.sign.asString('hello string')
// => ubW9PIjb360v...
```

### Verify a signature
Check if a given signature is valid. This is exposed as a stateless function so
that it can be used independently from any keypairs. You need to pass in the
data that was signed, the signature, and the `DID` string of the public key used
to create the signature.

This works the same for either RSA or ECC keys.

```ts
async function verify (
    msg:string|Uint8Array,
    sig:string|Uint8Array,
    signingDid:DID
):Promise<boolean>
```

**RSA verification uses RSA-PSS with SHA-256:**

```js
import { verify } from '@substrate-system/keys/rsa'

const isOk = await verify('hello string', sig, keys.DID)
```

**ECC verification uses Ed25519:**

```js
import { verify } from '@substrate-system/keys/ecc'

const isOk = await verify('hello string', sig, keys.DID)
```

### Encrypt a key

Use asymmetric (RSA) encryption to encrypt an AES key to the given public key.

```ts
async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format?:'uint8array'|'arraybuffer'):Promise<Uint8Array|ArrayBuffer>
```

#### example
```js
import { encryptKeyTo } from '@substrate-system/keys/rsa'

// pass in a CryptoKey
const encrypted = await encryptKeyTo({
    key: myAesKey,
    publicKey: keys.publicExchangeKey
})

// pass in a base64 string
const encryptedTwo = await encryptKeyTo({
  key: aesKey,
  publicKey: await keys.publicExchangeKeyAsString()
})  // => Uint8Array
```

#### encrypt a key, return a string

Encrypt the given key to the public key, and return the result as a
base64 string.

> !NOTE
> This is only relevant for RSA keys

```ts
import { encryptKeyTo } from '@substrate-system/keys/rsa'

encryptKeyTo.asString = async function ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|string|Uint8Array;
}, format?:SupportedEncodings):Promise<string> {
```

#### format
`encryptKeyTo.asString` takes an optional second argument for
[the format](https://github.com/achingbrain/uint8arrays/blob/26684d4fa1a78f3e5c16e74bf13192e881db4fcf/src/util/bases.ts#L46)
of the returned string.
Format is anything supported by [uint8arrays](https://github.com/achingbrain/uint8arrays).
By default, if omitted, it is `base64`.


### Asymmetrically encrypt some arbitrary data

Encrypt the given message to the given public key. If an AES key is not
provided, one will be created. Use the AES key to encrypt the given
content, then encrypt the AES key to the given public key.

> !NOTE
> This is only relevant for RSA keys.
> If using ECC keys, a symmetric key is automatically generated
> via diffie-hellman.

The return value is an ArrayBuffer containing the encrypted AES key +
the `iv` + the encrypted content if using RSA. It is `salt` + `iv` + cipher text
if using ECC.

To decrypt, pass the returned value to `keys.decrypt`, where `keys` is an
instance with the corresponding private key.

```ts
async function encryptTo (
    opts:{
        content:string|Uint8Array;
        publicKey:CryptoKey|string;
    },
    aesKey?:SymmKey|Uint8Array|string,
):Promise<ArrayBuffer>
```

#### example
```js
import { encryptTo } from '@substrate-system/keys/rsa'

const encrypted = await encryptTo({
    content: 'hello encryption',
    publicKey: keys.publicExchangeKey
})

// => ArrayBuffer
```

### Asymmetrically encrypt a string, return a new string

Encrypt the given string, and return a new string that is the (encrypted) AES
key concatenated with the `iv` and cipher text. The
corresponding method `keys.decryptAsString` will know how to parse and
decrypt the resulting text.

Use the functions `encryptTo.asString` and `keys.decryptAsString`.

#### `keys.decryptAsString`

**ECC:**
```ts
async decryptAsString (
  msg:string|Uint8Array|ArrayBuffer,
  publicKey?:CryptoKey|string,
  aesAlgorithm?:string,
  info?:string,
):Promise<string>
```

**RSA:**
```ts
async decryptAsString (
  msg:string|Uint8Array|ArrayBuffer,
  keysize?:CryptoKey|string|SymmKeyLength,
  _aesAlgorithm?:string,
):Promise<string>
```

##### example

```js
import { RsaKeys, encryptTo } from '@substrate-system/keys/rsa'  // RSA example
// or: import { EccKeys } from '@substrate-system/keys/ecc'

const keys = await RsaKeys.create()
// or: const keys = await EccKeys.create()
const pubKey = await keys.publicExchangeKeyAsString()  // Both ECC and RSA
const msg = { type: 'test', content: 'hello' }
const cipherText = await encryptTo.asString({
    content: JSON.stringify(msg),
    // pass in a string public key or crypto key or Uint8Array
    publicKey: pubKey
})  // => string

const text = await keys.decryptAsString(cipherText)
const data = JSON.parse(text)
// => { type: 'test', content: 'hello' }
```

### Decrypt a message

**ECC:**
```ts
async decrypt (
  msg:string|Uint8Array|ArrayBuffer,
  publicKey?:CryptoKey|string,
  aesAlgorithm?:string,
  info?:string,
):Promise<ArrayBuffer>
```

> !NOTE
> ECC keys will use our own public key if it is not passed in.

**RSA:**
```ts
async decrypt (
  msg:string|Uint8Array|ArrayBuffer,
  keysize?:CryptoKey|string|SymmKeyLength,
  _aesAlgorithm?:string,
):Promise<Uint8Array>
```

```js
const decrypted = await keys.decrypt(encrypted)
// => ArrayBuffer (ECC) or Uint8Array (RSA)
```

### In memory only

Create a keypair, but do not save it in `indexedDB`, even if you call `persist`.
Pass `true` as the session parameter to `.create` or
pass `{ session: true }` to `.load`. Session keys are never written to
`indexedDB`, so `session: true` beats the `persist` default in `.load`.

```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

const keys = await EccKeys.create(true)
// or: const keys = await RsaKeys.create(true)

// or pass it to `.load`
const keysTwo = await EccKeys.load({ session: true })
// or: const keysTwo = await RsaKeys.load({ session: true })
```

## AES

Expose several AES functions, use nice defaults.

* algorithm: `AES-GCM`
* key size: `256`
* `iv` size: [`12` bytes (96 bits)](https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes)


```js
import { AES } from '@substrate-system/keys/aes'

const key = await AES.create(/* ... optional arguments ... */)
```

### `create`
Create a new AES key. By default uses 256 bits & GCM algorithm.

```ts
import {
  DEFAULT_SYMM_ALGORITHM,
  DEFAULT_SYMM_LENGTH
} from '@substrate-system/keys/constants'

function create (opts:{ alg:string, length:number } = {
    alg: DEFAULT_SYMM_ALGORITHM,  // AES-GCM
    length: DEFAULT_SYMM_LENGTH  // 256
}):Promise<CryptoKey>
```

```ts
import { AES } from '@substrate-system/keys/aes'
const aesKey = await AES.create()
```

### `export`

Get the AES key as a `Uint8Array`.

```ts
export const AES = {
  async export (key:CryptoKey):Promise<Uint8Array>
}
```

#### `aes.export` example

```js
import { AES } from '@substrate-system/keys/aes'

const exported = await AES.export(myAesKey)
```

### `export.asString`

Get the key as a string, `base64` encoded by default.

```ts
async function asString (
  key:CryptoKey,
  format?:SupportedEncoding
):Promise<string>
```

#### `export.asString` example

```js
import { AES } from '@substrate-system/keys/aes'

const exported = await AES.export.asString(myAesKey)
// => QlfjZKzzgtNMVC4fPY7S537r/PFstifTyYqcsbsCjHQ=

const base32 = await AES.export.asString(myAesKey, 'base32')
// => ijl6gzfm6obngtcufypt3dws457ox7hrns3cpu6jrkoldoycrr2a
```

### `AES.encrypt`

Take a `Uint8Array`, return an encrypted `Uint8Array`.

```ts
async function encrypt (
  data:Uint8Array,
  cryptoKey:CryptoKey|Uint8Array,
  iv?:Uint8Array
):Promise<Uint8Array>
```

```js
import { AES } from '@substrate-system/keys/aes'
import { fromString } from 'uint8arrays'

const encryptedText = await AES.encrypt(fromString('hello AES'), aesKey)
```

### `AES.decrypt`

```ts
async function decrypt (
  encryptedData:Uint8Array|string,
  cryptoKey:CryptoKey|Uint8Array|ArrayBuffer,
  iv?:Uint8Array
):Promise<Uint8Array>
```

```js
import { toString } from 'uint8arrays'
import { AES } from '@substrate-system/keys/aes'

const decryped = await AES.decrypt(encryptedText, aesKey)
const decryptedText = toString(decrypted)
// => 'hello AES'
```

## See also

* [KEM Trails – Understanding Key Encapsulation Mechanisms](https://soatok.blog/2024/02/26/kem-trails-understanding-key-encapsulation-mechanisms/)
  > the primary motivation for KEMs comes from post-quantum cryptography, not RSA.
* [Understanding HKDF](https://soatok.blog/2021/11/17/understanding-hkdf/)
