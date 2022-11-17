import { scrypt } from "hash-wasm";

export type ProgressCallback = (percent: number) => void;
export type ScryptFunc<T> = (
    pw: Uint8Array,
    salt: Uint8Array,
    n: number,
    r: number,
    p: number,
    dkLen: number,
    callback?: ProgressCallback,
) => T;

export const scryptFunc: ScryptFunc<Promise<Uint8Array>> = async (pw, salt, n, r, p, dkLen, callback) => {
    callback?.(0);
    const key = await scrypt({
        password: pw,
        salt,
        costFactor: n,
        blockSize: r,
        parallelism: p,
        hashLength: dkLen,
        outputType: "binary",
    });
    callback?.(1);
    return key;
};
