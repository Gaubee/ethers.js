import { AES_CBC_128 } from "./AES-CBC";
export const cbc128 = new AES_CBC_128(crypto.subtle);
