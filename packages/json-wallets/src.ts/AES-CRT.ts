export class AES_CRT_128 {
    constructor(private subtle: SubtleCrypto) {}
    async encrypt(key: Uint8Array, counter: Uint8Array, data: Uint8Array) {
        const cryptoKey = await this.subtle.importKey("raw", key, "AES-CTR", false, ["encrypt"]);
        return new Uint8Array(await this.subtle.encrypt({ name: "AES-CTR", counter, length: 128 }, cryptoKey, data));
    }
    decrypt(key: Uint8Array, counter: Uint8Array, data: Uint8Array) {
        // Decryption is symetric 解密是对称的
        return this.encrypt(key, counter, data);
    }
}
