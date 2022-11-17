import { AES_CBC_128 } from "./AES-CBC";
import { webcrypto } from "node:crypto";
export const cbc128 = new AES_CBC_128(webcrypto.subtle);
