export declare type ProgressCallback = (percent: number) => void;
export declare type ScryptFunc<T> = (pw: Uint8Array, salt: Uint8Array, n: number, r: number, p: number, dkLen: number, callback?: ProgressCallback) => T;
export declare const scryptFunc: ScryptFunc<Promise<Uint8Array>>;
//# sourceMappingURL=browser-scrypt.d.ts.map