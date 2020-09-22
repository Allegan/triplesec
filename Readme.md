# Triple Sec
A simple, easy to use, JavaScript [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) wrapper.

![logo](logo.svg)

# Example

## v1 Encrypt & Decrypt
```js
const password = "hunter2"
const plainText = "Hello, World!"

// encode password and plainText
const ePassword = TripleSec.convert.strToBytes(password)
const ePlainText = TripleSec.convert.strToBytes(plainText)

// import the password
const kPassword = await TripleSec.import.password(ePassword)

// derive a secure key from the password using PBKDF2
const derived = await TripleSec.derive.fromPassword(kPassword)

// encrypt using the key
const cipher = await TripleSec.encrypt(ePlainText, derived.key)

// log the hex encoded cipher-text
console.log(TripleSec.convert.bytesToHex(cipher.buff))

// decrypt and convert back
const uncipher = await TripleSec.decrypt(cipher.buff, derived.key, cipher.iv)
const uncipherText = TripleSec.convert.bytesToStr(uncipher.buff)

// check equality
console.log(plainText === uncipherText)
```

## ECDH exchange
```js
// generate key-pairs
let kpa = await TripleSec.ecdh.generateKeyPair()
let kpb = await TripleSec.ecdh.generateKeyPair()

// exchange and derive AES keys
let pka = await TripleSec.ecdh.deriveSecretKey(kpa.privateKey, kpb.publicKey)
let pkb = await TripleSec.ecdh.deriveSecretKey(kpb.privateKey, kpa.publicKey)

// export the keys
let exa = await TripleSec.export.key(pka)
let exb = await TripleSec.export.key(pkb)

// show the keys in hex
console.log(TripleSec.convert.bytesToHex(exa))
console.log(TripleSec.convert.bytesToHex(exb))

// import the keys
let ima = await TripleSec.import.key(exa)
let imb = await TripleSec.import.key(exb)
```

## v2 Encrypt & Decrypt
```js
const salt = Salt.generate(16)
const key = new KeyProvider()

// generate key from password
await key.fromPassword("hunter2", salt)

// encrypt a plaintext
const encryptor = new Encryptor(key)
const plainText = "Hello"
const encoded = Encoder.strToBytes(plainText)
const cipherText = await encryptor.encrypt(encoded)

// log ciphertext
console.log(Encoder.bytesToHex(cipherText.buff))

// decrypt
const uncipherText = await encryptor.decrypt(cipherText.buff, cipherText.iv)

// log plaintext
console.log(Encoder.bytesToStr(uncipherText.buff))
```