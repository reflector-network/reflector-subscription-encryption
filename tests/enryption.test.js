//use node --experimental-vm-modules to run tests
import {decrypt, encrypt, generateRSAKeyPair, importRSAKey} from '../src/encryption.js'
import nativeCrypto from 'node:crypto'

if (!globalThis.crypto) {
    globalThis.crypto = nativeCrypto.webcrypto
}

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