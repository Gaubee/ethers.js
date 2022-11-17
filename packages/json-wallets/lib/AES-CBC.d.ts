export declare class AES_CBC_128 {
    private subtle;
    constructor(subtle: SubtleCrypto);
    encrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
    decrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
}
//# sourceMappingURL=AES-CBC.d.ts.map