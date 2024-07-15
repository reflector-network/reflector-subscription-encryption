if (!globalThis.crypto) {
    globalThis.crypto = require('node:crypto').webcrypto
}
const {decrypt, encrypt, generateRSAKeyPair, importRSAKey} = require('../src/encryption')

describe('Encryption', () => {
    test('encryption + decryption works', async () => {
        const rsaKeypair = await generateRSAKeyPair()
        const plainText = 'Some random message to encrypt!!!'
        const encrypted = await encrypt(await importRSAKey(rsaKeypair.publicKey), plainText)
        const decrypted = await decrypt(await importRSAKey(rsaKeypair.privateKey), encrypted)
        expect(new TextDecoder().decode(decrypted.buffer)).toEqual(plainText)
    })

    test('new iv vector generated every time', async () => {
        const rsaKeypair = await generateRSAKeyPair()
        const plainText = 'Some random message to encrypt!!!'
        const pk = await importRSAKey(rsaKeypair.publicKey)
        const encrypted1 = await encrypt(pk, plainText)
        const encrypted2 = await encrypt(pk, plainText)
        expect(encrypted1).not.toEqual(encrypted2)
    })
})