import { AES_CRT_128 } from "./AES-CRT";
import { webcrypto } from "node:crypto";
export const crt128 = new AES_CRT_128(webcrypto.subtle);
