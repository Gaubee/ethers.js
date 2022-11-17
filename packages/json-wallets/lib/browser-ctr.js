"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.crt128 = void 0;
var AES_CRT_1 = require("./AES-CRT");
exports.crt128 = new AES_CRT_1.AES_CRT_128(crypto.subtle);
//# sourceMappingURL=browser-ctr.js.map