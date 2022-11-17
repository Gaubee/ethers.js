"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encrypt = exports.decrypt = exports.KeystoreAccount = void 0;
var ctr_1 = require("./ctr");
var scrypt_1 = require("./scrypt");
var address_1 = require("@ethersproject/address");
var bytes_1 = require("@ethersproject/bytes");
var hdnode_1 = require("@ethersproject/hdnode");
var keccak256_1 = require("@ethersproject/keccak256");
var pbkdf2_1 = require("@ethersproject/pbkdf2");
var properties_1 = require("@ethersproject/properties");
var random_1 = require("@ethersproject/random");
var transactions_1 = require("@ethersproject/transactions");
var utils_1 = require("./utils");
var logger_1 = require("@ethersproject/logger");
var _version_1 = require("./_version");
var logger = new logger_1.Logger(_version_1.version);
function hasMnemonic(value) {
    return value != null && value.mnemonic && value.mnemonic.phrase;
}
var KeystoreAccount = /** @class */ (function (_super) {
    __extends(KeystoreAccount, _super);
    function KeystoreAccount() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    KeystoreAccount.prototype.isKeystoreAccount = function (value) {
        return !!(value && value._isKeystoreAccount);
    };
    return KeystoreAccount;
}(properties_1.Description));
exports.KeystoreAccount = KeystoreAccount;
function _decrypt(data, key, ciphertext) {
    return __awaiter(this, void 0, void 0, function () {
        var cipher, iv;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cipher = (0, utils_1.searchPath)(data, "crypto/cipher");
                    if (!(cipher === "aes-128-ctr")) return [3 /*break*/, 2];
                    iv = (0, utils_1.looseArrayify)((0, utils_1.searchPath)(data, "crypto/cipherparams/iv"));
                    return [4 /*yield*/, ctr_1.crt128.decrypt(key, iv, ciphertext)];
                case 1: return [2 /*return*/, _a.sent()];
                case 2: return [2 /*return*/, null];
            }
        });
    });
}
function _getAccount(data, key) {
    return __awaiter(this, void 0, void 0, function () {
        var ciphertext, computedMAC, privateKey, mnemonicKey, address, check, account, mnemonicCiphertext, mnemonicIv, path, locale, entropy, mnemonic, node;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    ciphertext = (0, utils_1.looseArrayify)((0, utils_1.searchPath)(data, "crypto/ciphertext"));
                    computedMAC = (0, bytes_1.hexlify)((0, keccak256_1.keccak256)((0, bytes_1.concat)([key.slice(16, 32), ciphertext]))).substring(2);
                    if (computedMAC !== (0, utils_1.searchPath)(data, "crypto/mac").toLowerCase()) {
                        throw new Error("invalid password");
                    }
                    return [4 /*yield*/, _decrypt(data, key.slice(0, 16), ciphertext)];
                case 1:
                    privateKey = _a.sent();
                    if (!privateKey) {
                        logger.throwError("unsupported cipher", logger_1.Logger.errors.UNSUPPORTED_OPERATION, {
                            operation: "decrypt",
                        });
                    }
                    mnemonicKey = key.slice(32, 64);
                    address = (0, transactions_1.computeAddress)(privateKey);
                    if (data.address) {
                        check = data.address.toLowerCase();
                        if (check.substring(0, 2) !== "0x") {
                            check = "0x" + check;
                        }
                        if ((0, address_1.getAddress)(check) !== address) {
                            throw new Error("address mismatch");
                        }
                    }
                    account = {
                        _isKeystoreAccount: true,
                        address: address,
                        privateKey: (0, bytes_1.hexlify)(privateKey),
                    };
                    if (!((0, utils_1.searchPath)(data, "x-ethers/version") === "0.1")) return [3 /*break*/, 3];
                    mnemonicCiphertext = (0, utils_1.looseArrayify)((0, utils_1.searchPath)(data, "x-ethers/mnemonicCiphertext"));
                    mnemonicIv = (0, utils_1.looseArrayify)((0, utils_1.searchPath)(data, "x-ethers/mnemonicCounter"));
                    path = (0, utils_1.searchPath)(data, "x-ethers/path") || hdnode_1.defaultPath;
                    locale = (0, utils_1.searchPath)(data, "x-ethers/locale") || "en";
                    return [4 /*yield*/, ctr_1.crt128.decrypt(mnemonicKey, mnemonicIv, mnemonicCiphertext)];
                case 2:
                    entropy = _a.sent();
                    try {
                        mnemonic = (0, hdnode_1.entropyToMnemonic)(entropy, locale);
                        node = hdnode_1.HDNode.fromMnemonic(mnemonic, null, locale).derivePath(path);
                        if (node.privateKey != account.privateKey) {
                            throw new Error("mnemonic mismatch");
                        }
                        account.mnemonic = node.mnemonic;
                    }
                    catch (error) {
                        // If we don't have the locale wordlist installed to
                        // read this mnemonic, just bail and don't set the
                        // mnemonic
                        if (error.code !== logger_1.Logger.errors.INVALID_ARGUMENT || error.argument !== "wordlist") {
                            throw error;
                        }
                    }
                    _a.label = 3;
                case 3: return [2 /*return*/, new KeystoreAccount(account)];
            }
        });
    });
}
function pbkdf2Sync(passwordBytes, salt, count, dkLen, prfFunc) {
    return (0, bytes_1.arrayify)((0, pbkdf2_1.pbkdf2)(passwordBytes, salt, count, dkLen, prfFunc));
}
function pbkdf2(passwordBytes, salt, count, dkLen, prfFunc) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/, pbkdf2Sync(passwordBytes, salt, count, dkLen, prfFunc)];
        });
    });
}
function _computeKdfKey(data, password, pbkdf2Func, scryptFunc, progressCallback) {
    var passwordBytes = (0, utils_1.getPassword)(password);
    var kdf = (0, utils_1.searchPath)(data, "crypto/kdf");
    if (kdf && typeof kdf === "string") {
        var throwError = function (name, value) {
            return logger.throwArgumentError("invalid key-derivation function parameters", name, value);
        };
        if (kdf.toLowerCase() === "scrypt") {
            var salt = (0, utils_1.looseArrayify)((0, utils_1.searchPath)(data, "crypto/kdfparams/salt"));
            var N = parseInt((0, utils_1.searchPath)(data, "crypto/kdfparams/n"));
            var r = parseInt((0, utils_1.searchPath)(data, "crypto/kdfparams/r"));
            var p = parseInt((0, utils_1.searchPath)(data, "crypto/kdfparams/p"));
            // Check for all required parameters
            if (!N || !r || !p) {
                throwError("kdf", kdf);
            }
            // Make sure N is a power of 2
            if ((N & (N - 1)) !== 0) {
                throwError("N", N);
            }
            var dkLen = parseInt((0, utils_1.searchPath)(data, "crypto/kdfparams/dklen"));
            if (dkLen !== 32) {
                throwError("dklen", dkLen);
            }
            return scryptFunc(passwordBytes, salt, N, r, p, 64, progressCallback);
        }
        else if (kdf.toLowerCase() === "pbkdf2") {
            var salt = (0, utils_1.looseArrayify)((0, utils_1.searchPath)(data, "crypto/kdfparams/salt"));
            var prfFunc = null;
            var prf = (0, utils_1.searchPath)(data, "crypto/kdfparams/prf");
            if (prf === "hmac-sha256") {
                prfFunc = "sha256";
            }
            else if (prf === "hmac-sha512") {
                prfFunc = "sha512";
            }
            else {
                throwError("prf", prf);
            }
            var count = parseInt((0, utils_1.searchPath)(data, "crypto/kdfparams/c"));
            var dkLen = parseInt((0, utils_1.searchPath)(data, "crypto/kdfparams/dklen"));
            if (dkLen !== 32) {
                throwError("dklen", dkLen);
            }
            return pbkdf2Func(passwordBytes, salt, count, dkLen, prfFunc);
        }
    }
    return logger.throwArgumentError("unsupported key-derivation function", "kdf", kdf);
}
function decrypt(json, password, progressCallback) {
    return __awaiter(this, void 0, void 0, function () {
        var data, key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    data = JSON.parse(json);
                    return [4 /*yield*/, _computeKdfKey(data, password, pbkdf2, scrypt_1.scryptFunc, progressCallback)];
                case 1:
                    key = _a.sent();
                    return [2 /*return*/, _getAccount(data, key)];
            }
        });
    });
}
exports.decrypt = decrypt;
function encrypt(account, password, options, progressCallback) {
    if (options === void 0) { options = {}; }
    return __awaiter(this, void 0, void 0, function () {
        var mnemonic, node, privateKey, passwordBytes, entropy, path, locale, srcMnemonic, client, salt, iv, uuidRandom, N, r, p, key, derivedKey, macPrefix, mnemonicKey, ciphertext, mac, data, mnemonicIv, mnemonicCiphertext, now, timestamp;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    // Check the address matches the private key
                    if ((0, address_1.getAddress)(account.address) !== (0, transactions_1.computeAddress)(account.privateKey)) {
                        throw new Error("address/privateKey mismatch");
                    }
                    // Check the mnemonic (if any) matches the private key
                    if (hasMnemonic(account)) {
                        mnemonic = account.mnemonic;
                        node = hdnode_1.HDNode.fromMnemonic(mnemonic.phrase, null, mnemonic.locale).derivePath(mnemonic.path || hdnode_1.defaultPath);
                        if (node.privateKey != account.privateKey) {
                            throw new Error("mnemonic mismatch");
                        }
                    }
                    privateKey = (0, bytes_1.arrayify)(account.privateKey);
                    passwordBytes = (0, utils_1.getPassword)(password);
                    entropy = null;
                    path = null;
                    locale = null;
                    if (hasMnemonic(account)) {
                        srcMnemonic = account.mnemonic;
                        entropy = (0, bytes_1.arrayify)((0, hdnode_1.mnemonicToEntropy)(srcMnemonic.phrase, srcMnemonic.locale || "en"));
                        path = srcMnemonic.path || hdnode_1.defaultPath;
                        locale = srcMnemonic.locale || "en";
                    }
                    client = options.client;
                    if (!client) {
                        client = "ethers.js";
                    }
                    salt = null;
                    if (options.salt) {
                        salt = (0, bytes_1.arrayify)(options.salt);
                    }
                    else {
                        salt = (0, random_1.randomBytes)(32);
                    }
                    iv = null;
                    if (options.iv) {
                        iv = (0, bytes_1.arrayify)(options.iv);
                        if (iv.length !== 16) {
                            throw new Error("invalid iv");
                        }
                    }
                    else {
                        iv = (0, random_1.randomBytes)(16);
                    }
                    uuidRandom = null;
                    if (options.uuid) {
                        uuidRandom = (0, bytes_1.arrayify)(options.uuid);
                        if (uuidRandom.length !== 16) {
                            throw new Error("invalid uuid");
                        }
                    }
                    else {
                        uuidRandom = (0, random_1.randomBytes)(16);
                    }
                    N = 1 << 17, r = 8, p = 1;
                    if (options.scrypt) {
                        if (options.scrypt.N) {
                            N = options.scrypt.N;
                        }
                        if (options.scrypt.r) {
                            r = options.scrypt.r;
                        }
                        if (options.scrypt.p) {
                            p = options.scrypt.p;
                        }
                    }
                    return [4 /*yield*/, (0, scrypt_1.scryptFunc)(passwordBytes, salt, N, r, p, 64, progressCallback)];
                case 1:
                    key = _a.sent();
                    derivedKey = key.slice(0, 16);
                    macPrefix = key.slice(16, 32);
                    mnemonicKey = key.slice(32, 64);
                    return [4 /*yield*/, ctr_1.crt128.encrypt(derivedKey, iv, privateKey)];
                case 2:
                    ciphertext = _a.sent();
                    mac = (0, keccak256_1.keccak256)((0, bytes_1.concat)([macPrefix, ciphertext]));
                    data = {
                        address: account.address.substring(2).toLowerCase(),
                        id: (0, utils_1.uuidV4)(uuidRandom),
                        version: 3,
                        crypto: {
                            cipher: "aes-128-ctr",
                            cipherparams: {
                                iv: (0, bytes_1.hexlify)(iv).substring(2),
                            },
                            ciphertext: (0, bytes_1.hexlify)(ciphertext).substring(2),
                            kdf: "scrypt",
                            kdfparams: {
                                salt: (0, bytes_1.hexlify)(salt).substring(2),
                                n: N,
                                dklen: 32,
                                p: p,
                                r: r,
                            },
                            mac: mac.substring(2),
                        },
                    };
                    if (!entropy) return [3 /*break*/, 4];
                    mnemonicIv = (0, random_1.randomBytes)(16);
                    return [4 /*yield*/, ctr_1.crt128.encrypt(mnemonicKey, mnemonicIv, entropy)];
                case 3:
                    mnemonicCiphertext = _a.sent();
                    now = new Date();
                    timestamp = now.getUTCFullYear() +
                        "-" +
                        (0, utils_1.zpad)(now.getUTCMonth() + 1, 2) +
                        "-" +
                        (0, utils_1.zpad)(now.getUTCDate(), 2) +
                        "T" +
                        (0, utils_1.zpad)(now.getUTCHours(), 2) +
                        "-" +
                        (0, utils_1.zpad)(now.getUTCMinutes(), 2) +
                        "-" +
                        (0, utils_1.zpad)(now.getUTCSeconds(), 2) +
                        ".0Z";
                    data["x-ethers"] = {
                        client: client,
                        gethFilename: "UTC--" + timestamp + "--" + data.address,
                        mnemonicCounter: (0, bytes_1.hexlify)(mnemonicIv).substring(2),
                        mnemonicCiphertext: (0, bytes_1.hexlify)(mnemonicCiphertext).substring(2),
                        path: path,
                        locale: locale,
                        version: "0.1",
                    };
                    _a.label = 4;
                case 4: return [2 /*return*/, JSON.stringify(data)];
            }
        });
    });
}
exports.encrypt = encrypt;
//# sourceMappingURL=keystore.js.map