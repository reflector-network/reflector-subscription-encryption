const {subtle} = crypto
const publicExponent = new Uint8Array([1, 0, 1])
const textEncoder = new TextEncoder()

/**
 * Generate random 32-byte encryption key
 * @return {Uint8Array}
 */
function generateRandomEncryptionKey() {
    return crypto.getRandomValues(new Uint8Array(32))
}

/**
 * Import binary RSA key as CryptoKey for encryption/decryption
 * @param {ArrayBuffer|Uint8Array|string} key - Raw RSA key in binary format
 * @return {Promise<CryptoKey>}
 */
export function importRSAKey(key) {
    key = normalizeData(key)
    let format = 'pkcs8'
    let usage = 'decrypt'
    if (key.length < 500) {//private keys are longer than public
        format = 'spki'
        usage = 'encrypt'
    }
    return subtle.importKey(
        format,
        key,
        {name: 'RSA-OAEP', hash: 'SHA-256'},
        true,
        [usage]
    )
}

/**
 * Import binary AES key as CryptoKey for encryption/decryption
 * @param {ArrayBuffer|Uint8Array|string} key - Raw AES key in binary format
 * @return {Promise<CryptoKey>}
 */
function importAESKey(key) {
    return subtle.importKey(
        'raw',
        normalizeData(key),
        {name: 'AES-GCM'},
        true,
        ['encrypt', 'decrypt']
    )
}

/**
 * Generate pair of keys for RSA-OAEP encryption
 * @return {Promise<{privateKey: ArrayBuffer, publicKey: ArrayBuffer}>}
 */
export async function generateRSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent,
            hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
    )

    const [privateKey, publicKey] = await Promise.all([
        crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
        crypto.subtle.exportKey('spki', keyPair.publicKey)
    ])

    return {privateKey, publicKey}
}

/**
 * Get SHA256 hash of the data
 * @param {ArrayBuffer|Uint8Array|string} data - Data to hash
 * @returns {Promise<ArrayBuffer>}
 */
export function sha256(data) {
    return crypto.subtle.digest('SHA-256', normalizeData(data))
}

/**
 * Encrypt the data with a public RSA key
 * @param {CryptoKey} rsaPublicKey - Public key for RSA encryption
 * @param {ArrayBuffer|Uint8Array|string} data - Data to encrypt
 * @return {Uint8Array}
 */
export async function encrypt(rsaPublicKey, data) {
    //every time a new encryption key is generated
    const aesKey = generateRandomEncryptionKey()
    //encrypt data with AES
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const encryptedData = await subtle.encrypt({name: 'AES-GCM', iv}, await importAESKey(aesKey), normalizeData(data))
    //encrypt the key itself + IV with RSA
    const aesKeyIV = new Uint8Array(44)
    aesKeyIV.set(aesKey, 0)
    aesKeyIV.set(iv, 32)
    const encryptedAesKeyIv = await subtle.encrypt({name: 'RSA-OAEP'}, rsaPublicKey, aesKeyIV)
    //concatenate both key and data
    const res = new Uint8Array(256 + encryptedData.byteLength)
    res.set(new Uint8Array(encryptedAesKeyIv), 0)
    res.set(new Uint8Array(encryptedData), 256)
    return res
}

/**
 * Decrypt the data with a private RSA key
 * @param {CryptoKey} rsaPrivateKey - Private key for RSA encryption
 * @param {ArrayBuffer|Uint8Array|string} encryptedData - Data to decrypt
 * @return {Promise<Uint8Array|null>}
 */
export async function decrypt(rsaPrivateKey, encryptedData) {
    try {
        //parse and validate input
        encryptedData = normalizeData(encryptedData)
        if (!encryptedData || encryptedData.length < 256)
            return null
        if (!rsaPrivateKey.algorithm) { //try to import
            rsaPrivateKey = await importRSAKey(rsaPrivateKey)
        }
        //decode AES KEY
        const aesKeyIV = new Uint8Array(await subtle.decrypt({name: 'RSA-OAEP'}, rsaPrivateKey, encryptedData.subarray(0, 256)))
        //the rest of the input is the encrypted data itself
        encryptedData = encryptedData.subarray(256)
        const aesKey = await importAESKey(aesKeyIV.subarray(0, 32))
        const res = await subtle.decrypt({name: 'AES-GCM', iv: aesKeyIV.subarray(32)}, aesKey, encryptedData)
        return new Uint8Array(res)
    } catch (e) {
        console.error(e)
        return null
    }
}

/**
 * Normalize binary input data
 * @param {ArrayBuffer|Uint8Array|string} data - Binary data
 * @return {Uint8Array}
 * @internal
 */
function normalizeData(data) {
    if (typeof data === 'string')
        return textEncoder.encode(data)
    if (data instanceof ArrayBuffer)
        return new Uint8Array(data)
    return data
}
const encryption = {encrypt, decrypt, sha256, generateRSAKeyPair, importRSAKey}

export default encryption