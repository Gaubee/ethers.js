export declare class AES_CRT_128 {
    private subtle;
    constructor(subtle: SubtleCrypto);
    encrypt(key: Uint8Array, counter: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
    decrypt(key: Uint8Array, counter: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
}
//# sourceMappingURL=AES-CRT.d.ts.map