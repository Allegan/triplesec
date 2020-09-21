class Encoder {
    /**
     * strToBytes
     * Encode a UTF-16 string to a Uint8Array
     * @static
     * @param {string} str - string to encode to a Uint8Array
     * @returns {Uint8Array}
     */
    static strToBytes (str) {
        return (new TextEncoder()).encode(str)
    }

    /**
     * bytesToStr
     * Encode a Uint8Array to a UTF-16 string
     * @static
     * @param {Uint8Array} buff - buffer to encode as a string
     * @returns {string}
     */
    static bytesToStr (buff) {
        return (new TextDecoder()).decode(buff)
    }
}

class Salt {
    /**
     * generate
     * Generate a salt of a defined size
     * @static
     * @param {number} bytes - number of bytes for the salt
     * @returns {Uint8Array}
     */
    static generate (size) {
        return window.crypto.getRandomValues(new Uint8Array(size))
    }
}

class KeyProvider {
    #crypto
    #keySize
    #key

    /**
     * @constructor
     * @param {number} bits - key length (can be 128, 192, or 256)
     */
    constructor (bits = 256) {
        // validate key size
        const validSizes = [ 128, 192, 256 ]

        if (!validSizes.includes(bits))
            throw new RangeError("Provided size must be: 128, 196, or 256")

        this.#keySize = bits
        this.#key = undefined
        this.#crypto = window.crypto.subtle
    }

    /**
     * #pbkdf2ImportParams
     * Generate the params needed to import a key for PBKDF2
     * @private
     * @param {Uint8Array} keyMaterial - key material to import
     * @returns {array}
     */
    #pbkdf2ImportParams (keyMaterial) {
        return [
            "raw",           // import material format
            keyMaterial,     // material to import
            "PBKDF2",        // intended key algorithm
            false,           // can be exported?
            [
                "deriveKey"  // can be used to derive another key
            ]
        ]
    }

    /**
     * #aesImportParams
     * Generate the params needed to import a key for AES-GCM
     * @private
     * @param {Uint8Array} keyMaterial - key material to import
     * @returns {array}
     */
    #aesImportParams (keyMaterial) {
        return [
            "raw",           // import material format
            keyMaterial,     // material to import
            "AES-GCM",       // intended key algorithm
            true,            // can be exported?
            [
                "encrypt",   // can be used to encrypt
                "decrypt"    // can be used to decrypt
            ]
        ]
    }

    /**
     * #importKey
     * @async
     * @private
     * @param {Uint8Array} keyMaterial - key material to import
     * @param {boolean} password - keyMaterial is a password
     * @returns {CryptoKey}
     */
    async #importKey (keyMaterial, password = false) {
        const params = (password) 
            ? this.#pbkdf2ImportParams(keyMaterial)
            : this.#aesImportParams(keyMaterial)

        return this.#crypto.importKey(...params)
    }

    /**
     * fromPassword
     * Derive a secure AES key from a password
     * @async
     * @param {string} password - password from which to derive a key
     * @param {ArrayBuffer} salt - optional salt to add to key derivision
     * @param {number} iterations - optional times to run the derivision algorithm
     */
    async fromPassword (password, salt, iterations = 100000) {
        if (this.#key !== undefined)
            throw new Error("A key has already been generated")

        const encoded = Encoder.strToBytes(password)
        const keyMaterial = await this.#importKey(encoded, true)
        const pbkdf2Params = {
            name: "PBKDF2",
            hash: "SHA-256",
            iterations: iterations,
            length: this.#keySize,
            salt: salt
        }

        // salt?
        if (salt) 
            pbkdf2Params.salt = salt
        
        this.#key = await this.#crypto.deriveKey(
            pbkdf2Params,
            keyMaterial,
            {
                name: "AES-GCM",
                length: this.#keySize
            },
            true,
            [
                "encrypt",
                "decrypt"
            ]
        )
    }

    /**
     * generateKey
     * Generate a new AES key
     */
    async generateKey () {
        if (this.#key !== undefined)
            throw new Error("A key has already been generated")

        this.#key = await this.#crypto.generateKey(
            {
                name: "AES-GCM",
                length: this.#keySize
            },
            true,
            [
                "encrypt",
                "decrypt"
            ]
        )
    }

    /**
     * _getKey
     * Gets the instance of CryptoKey
     * @private
     * @warning do not use this to export the key
     * @returns {CryptoKey}
     */
    _getKey () {
        if (this.#key === undefined)
            throw new Error("Key has not yet been generated")

        return this.#key
    }
}