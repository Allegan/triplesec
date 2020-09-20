# Triple Sec
A simple, easy to use, JavaScript [Web Crypto API]() wrapper.

![logo](logo.svg)

# Example

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