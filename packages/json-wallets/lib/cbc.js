"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cbc128 = void 0;
var AES_CBC_1 = require("./AES-CBC");
var node_crypto_1 = require("node:crypto");
exports.cbc128 = new AES_CBC_1.AES_CBC_128(node_crypto_1.webcrypto.subtle);
//# sourceMappingURL=cbc.js.map