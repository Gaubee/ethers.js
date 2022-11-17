import { scrypt } from "node:crypto";
import type { ScryptFunc, ProgressCallback } from "./browser-scrypt";
export type { ScryptFunc, ProgressCallback };

export const scryptFunc: ScryptFunc<Promise<Uint8Array>> = async (pw, salt, n, r, p, dkLen, callback) => {
    callback?.(0);
    const key = await new Promise<Uint8Array>((resolve, reject) => {
        scrypt(pw, salt, dkLen, {}, (err, derivedKey) => {
            if (err) {
                return reject(err);
            }
            resolve(derivedKey);
        });
    });
    callback?.(1);
    return key;
};
