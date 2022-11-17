"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.crt128 = void 0;
var AES_CRT_1 = require("./AES-CRT");
var node_crypto_1 = require("node:crypto");
exports.crt128 = new AES_CRT_1.AES_CRT_128(node_crypto_1.webcrypto.subtle);
//# sourceMappingURL=ctr.js.map