/**
 * Copyright (c) 2020 Allegan Brigham
 *
 * triplesec.js
 *
 * Triple Sec is a simple, easy to use, JavaScript wrapper around the Web Crypto
 * API. It provides methods that can be used to encrypt and decrypt, sign,
 * digest, derive keys, and derive shared secrets. While Triple Sec makes every
 * effort to be both secure and simple there is no garauntee that it is either.
 *
 * Please do not use this in any production environments or in applications
 * security is a requirement. For all intents and purposes this is unreviewed,
 * untested, unvalidated, and a toy project.
 *
 * @summary easy-to-use Web Crypto API wrapper
 * @author Allegan Brigham <alleganbrigham@gmail.com>
 * @gpg email <fingerprint: A73322DF88539324>
 * @gpg github <fingerprint: 938D1714A84A021E>
 *
 * @license GNU GPL v3
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

const TripleSec = (() => {
    if (!window.crypto || !window.crypto.subtle)
        return { error: "The Web Crypto API is required for Triple Sec." }

    // window.crypto.subtle alias
    const subtle = window.crypto.subtle

    /**
     * Randomness
     *
     * Provides utility functions that allow for the retrieval of 8, 64, 128,
     * 256, and 512-bits of cryptographically secure random numbers
     *
     * @method get8 - gets 8 bits of randomness
     * @method get64 - gets 64 bits of randomness
     * @method get96 - gets 96 bits of randomness
     * @method get128 - gets 128 bits of randomness
     * @method get256 - gets 256 bits of randomness
     * @method get512 - gets 512 bits of randomness
     *
     * @return <Uint8Array> - secured bits in byte blocks
     */
    const Randomness = (() => {
        const mod = {
            get8: () => window.crypto.getRandomValues(new Uint8Array(1)),
            get64: () => window.crypto.getRandomValues(new Uint8Array(8)),
            get96: () => window.crypto.getRandomValues(new Uint8Array(12)),
            get128: () => window.crypto.getRandomValues(new Uint8Array(16)),
            get256: () => window.crypto.getRandomValues(new Uint8Array(32)),
            get512: () => window.crypto.getRandomValues(new Uint8Array(64))
        }

        // export module
        return Object.freeze(mod)
    })()

    /**
     * Convert
     *
     * Provides utility functions for the encoding and decoding of UTF-16
     * strings to and from Uint8Arrays including the ability to encode and
     * decode to ASCII hex values
     *
     * @method strToBytes - UTF-16 string to Uint8Array
     * @method bytesToStr - Uint8Array to UTF-16 string
     * @method hexToBytes - Hex encoded UTF-16 string to Uint8Array
     * @method bytesToHex - Uint8Array to hex encoded UTF-16 string
     */
    const Convert = (() => {
        /**
         * strToBytes
         *
         * Takes a UTF-16 encoded string and converts it to a Uint8Array
         *
         * @param <String> str - string to encode
         *
         * @return <Uint8Array>
         */
        const strToBytes = (str) => {
            return (new TextEncoder()).encode(str)
        }

        /**
         * bytesToStr
         *
         * Takes a Uint8Array and converts it to a UTF-16 encoded string
         *
         * @param <Uint8Array> buff - buffer to decode
         *
         * @return <String>
         */
        const bytesToStr = (buff) => {
            return (new TextDecoder()).decode(buff)
        }

        /**
         * hexToBytes
         *
         * Takes a hex encoded UTF-16 string and converts it to a Uint8Array
         *
         * @param <String> str - hex encoded string to decode
         */
        const hexToBytes = (str) => {
            return new Uint8Array(str
                .split(/(.{2})/)
                .filter(char => char !== "")
                .map(char => parseInt(char, 16)))
        }

        /**
         * bytesToHex
         *
         * Takes a Uint8Array and convers it to a hex encoded UTF-16 string
         *
         * @param <Uint8Array> buff - buffer to encode
         *
         * @return <String>
         */
        const bytesToHex = (buff) => {
            return Array
                .from(buff)
                .map(char =>
                    char.toString(16)
                        .padStart(2, '0')
                        .toUpperCase())
                .join('')
        }

        // export module
        return Object.freeze({
            strToBytes: strToBytes,
            bytesToStr: bytesToStr,
            hexToBytes: hexToBytes,
            bytesToHex: bytesToHex
        })
    })()

    /**
     * Import
     *
     * Provides a set of utility functions that make importing wrapped and
     * unwrapped key material, in addition to password material, easier.
     *
     * @method password - import password material as a key
     */
    const Import = (() => {
        /**
         * password
         *
         * @async
         *
         * Enables the importing of password material as a key in order to
         * later enable a secure key to be derived from it. If you are taking
         * in passwords for encryption you should be using this function.
         *
         * @param <Uint8Array> pass - encoded password material
         *
         * @return <CryptoKey>
         */
        const password = async (pass) => {
            return subtle.importKey(
                "raw",
                pass,
                "PBKDF2",
                false,
                ["deriveKey"]
            )
        }

        // export module functions
        return Object.freeze({
            password: password
        })
    })()

    /**
     * DeriveKey
     *
     * @async
     *
     * Provides a set of utilities that are used to securely derive key material
     * from different types of input data
     *
     * @warning never use a digest in order to derive key material
     *
     * @method fromPassword - take a password and derive a secure key from it
     */
    const DeriveKey = (() => {

        /**
         * fromPassword
         *
         * @async
         *
         * Provides a way to take an imported password and use it to derive a
         * strong, secure, AES-GCM key. This is the only function that you
         * should be using if you plan to encrypt something using a password.
         *
         * @param <CryptoKey> password - imported password to derive a key from
         * @param <Number> rounds - number of rounds to derive (default 100000)
         *
         * @return <CryptoKey>
         */
        const fromPassword = async (password, rounds = 100000) => {
            const salt = Randomness.get128()
            const key = await subtle.deriveKey(
                {
                    name: "PBKDF2",
                    hash: "SHA-256",
                    salt: salt,
                    iterations: rounds,
                    length: 256
                },
                password,
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                [
                    "encrypt",
                    "decrypt"
                ]
            )

            // return the key and the salt
            return Object.freeze({
                key: key,
                salt: salt
            })
        }

        // export module
        return Object.freeze({
            fromPassword: fromPassword
        })
    })()

    /**
     * encrypt
     *
     * @async
     *
     * Perform encryption of a given buffer using a given key, iv (optional),
     * associated data (optional), and tag length (optional).
     *
     * @param <Uint8Array> buff - buffer to encrypt
     * @param <CryptoKey> key - key to encrypt with
     * @param <Uint8Array> iv - pre-selected iv (optional)
     * @param <Uint8Array> data - additional data (optional)
     * @param <Number> tagLength - size of auth tag (optional: 128 default)
     *
     * @return <Object>: {
     *     <Uint8Array> buff - cipher-text
     *     <Uint8Array> iv - iv either provided or generated
     *     <Uint8Array> tagLength - the tagLength used
     * }
     */
    const encrypt = async (buff, key, iv = undefined, data = undefined, tagLength = 128) => {
        const uiv = (typeof iv !== 'undefined') ? iv : Randomness.get128()
        let aesParams = {
            name: "AES-GCM",
            iv: uiv,
            tagLength: tagLength
        }

        // include additionalData
        if (typeof data !== 'undefined')
            aesParams.additionalData = data

        // encrypt 
        const res = await subtle.encrypt(
            aesParams,
            key,
            buff
        )

        return Object.freeze({
            buff: new Uint8Array(res),
            iv: uiv,
            tagLength: tagLength
        })
    }

    /**
     * decrypt
     *
     * @async
     *
     * Perform decryption of a given buffer using a given key, iv (optional),
     * associated data (optional), and tag length (optional).
     *
     * @param <Uint8Array> buff - buffer to decrypt
     * @param <CryptoKey> key - key to decrypt with
     * @param <Uint8Array> iv - pre-selected iv (optional)
     * @param <Uint8Array> data - additional data (optional)
     * @param <Number> tagLength - size of auth tag (optional: 128 default)
     *
     * @return <Object>: {
     *     <Uint8Array> buff - plain-text
     * }
     */
    const decrypt = async (buff, key, iv = undefined, data = undefined, tagLength = 128) => {
        let aesParams = {
            name: "AES-GCM",
            iv: iv,
            tagLength: tagLength
        }

        // include additionalData
        if (typeof data !== 'undefined')
            aesParams.additionalData = data

        // decrypt
        const res = await subtle.decrypt(
            aesParams,
            key,
            buff
        )

        return {
            buff: new Uint8Array(res)
        }
    }

    // export module
    return Object.freeze({
        rand: Randomness,
        convert: Convert,
        import: Import,
        derive: DeriveKey,
        encrypt: encrypt,
        decrypt: decrypt
    })
})()
