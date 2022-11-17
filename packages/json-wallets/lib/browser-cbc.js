"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cbc128 = void 0;
var AES_CBC_1 = require("./AES-CBC");
exports.cbc128 = new AES_CBC_1.AES_CBC_128(crypto.subtle);
//# sourceMappingURL=browser-cbc.js.map