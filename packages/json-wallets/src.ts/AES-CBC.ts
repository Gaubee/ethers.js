export class AES_CBC_128 {
    constructor(private subtle: SubtleCrypto) {}

    async encrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array) {
        return new Uint8Array(
            await this.subtle.encrypt(
                {
                    name: "AES-CBC",
                    iv,
                },
                await this.subtle.importKey("raw", key, "AES-CBC", false, ["encrypt"]),
                data,
            ),
        );
    }
    async decrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array) {
        return new Uint8Array(
            await this.subtle.decrypt(
                {
                    name: "AES-CBC",
                    iv,
                },
                await this.subtle.importKey("raw", key, "AES-CBC", false, ["decrypt"]),
                data,
            ),
        );
    }
}
