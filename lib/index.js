'use strict';

var elliptic = require('elliptic');
var BN2 = require('bn.js');
var CryptoJS = require('crypto-js');
var jsSha256 = require('js-sha256');

function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

var elliptic__default = /*#__PURE__*/_interopDefault(elliptic);
var BN2__default = /*#__PURE__*/_interopDefault(BN2);
var CryptoJS__default = /*#__PURE__*/_interopDefault(CryptoJS);

var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __publicField = (obj, key, value) => {
  __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
  return value;
};
function default_curve() {
  var config = new Config();
  config.set_curve_by_default();
  return config.curve();
}
var secp256k1, Config, Curve;
var init_Config = __esm({
  "src/Config.ts"() {
    secp256k1 = new elliptic__default.default.ec("secp256k1");
    Config = class {
      constructor() {
        this.set_curve = /* @__PURE__ */ __name(() => {
          this._curve = this._default_curve;
        }, "set_curve");
        this.set_curve_by_default = /* @__PURE__ */ __name(() => {
          this.set_curve();
        }, "set_curve_by_default");
        this.curve = /* @__PURE__ */ __name(() => {
          return this._curve;
        }, "curve");
        this._default_curve = new Curve();
        this._curve = this._default_curve;
      }
    };
    __name(Config, "Config");
    __name(default_curve, "default_curve");
    Curve = class {
      constructor() {
        this._order = secp256k1.curve.n;
        this._generator = secp256k1.curve.g;
        this._order_size = secp256k1.curve.n.byteLength();
        this.name = /* @__PURE__ */ __name(() => {
          return this._name;
        }, "name");
        this.order = /* @__PURE__ */ __name(() => {
          return this._order;
        }, "order");
        this.generator = /* @__PURE__ */ __name(() => {
          return this._generator;
        }, "generator");
        this.order_size = /* @__PURE__ */ __name(() => {
          return this._order_size;
        }, "order_size");
        this._curve = secp256k1;
        this._name = "secp256k1";
        this._order = secp256k1.curve.n;
        this._generator = secp256k1.curve.g;
        this._order_size = secp256k1.curve.n.byteLength();
      }
    };
    __name(Curve, "Curve");
  }
});
var _Scalar, Scalar;
var init_Math = __esm({
  "src/Math.ts"() {
    init_Config();
    _Scalar = class {
      constructor(bigInt) {
        this.curve = /* @__PURE__ */ __name(() => {
          return this._curve;
        }, "curve");
        /**
         * valueOf
         */
        this.valueOf = /* @__PURE__ */ __name(() => {
          return this._scalar;
        }, "valueOf");
        /**
         * \brief Getting BIGNUM bytes from existing BigInteger
         * @return vector of bytes
         */
        this.to_bytes = /* @__PURE__ */ __name(() => {
          var bytes = this._scalar.toArray();
          if (bytes.length == 33) {
            return bytes.slice(1, 33);
          }
          return bytes;
        }, "to_bytes");
        this.add = /* @__PURE__ */ __name((sc) => {
          return new _Scalar(this.valueOf().add(sc.valueOf()));
        }, "add");
        this.sub = /* @__PURE__ */ __name((sc) => {
          return new _Scalar(this.valueOf().sub(sc.valueOf()));
        }, "sub");
        this.mul = /* @__PURE__ */ __name((sc) => {
          return new _Scalar(this.valueOf().mul(sc.valueOf()).mod(this.curve().order()));
        }, "mul");
        this.eq = /* @__PURE__ */ __name((sc) => {
          return this.valueOf().eq(sc.valueOf());
        }, "eq");
        this.invm = /* @__PURE__ */ __name(() => {
          return new _Scalar(this.valueOf().invm(this.curve().order()));
        }, "invm");
        this._scalar = bigInt;
        this._curve = default_curve();
      }
    };
    Scalar = _Scalar;
    __name(Scalar, "Scalar");
    /**
    * \brief Generate random BigInteger.
    * @return
    */
    Scalar.generate_random = /* @__PURE__ */ __name(function(curve) {
      if (typeof curve == "undefined") {
        curve = default_curve();
      }
      return new _Scalar(curve._curve.genKeyPair().getPrivate());
    }, "generate_random");
    /**
     * \brief Get BigInteger from big endian ordered bytes
     * @param buffer
     * @return
     */
    Scalar.from_bytes = /* @__PURE__ */ __name(function(buffer) {
      if (buffer.length != _Scalar.expected_byte_length() && buffer.length != 2 * this.expected_byte_length()) {
        throw new Error("Invalid length of data.");
      }
      return new _Scalar(new BN2__default.default(buffer));
    }, "from_bytes");
    /**
     *  get length of BN
     */
    Scalar.expected_byte_length = /* @__PURE__ */ __name(() => {
      return default_curve().order_size();
    }, "expected_byte_length");
  }
});
var require_src = __commonJS({
  "src/index.js"(exports, module) {
    init_Config();
    init_Math();
    var GroupElement = class {
      constructor(point, curve) {
        __publicField(this, "to_bytes", /* @__PURE__ */ __name(() => {
          var x = this._ec_point.getX().toArray();
          var y = this._ec_point.getY().toArray();
          return [4].concat(x, y);
        }, "to_bytes"));
        __publicField(this, "valueOf", /* @__PURE__ */ __name(() => {
          return this._ec_point;
        }, "valueOf"));
        __publicField(this, "add", /* @__PURE__ */ __name((ge) => {
          return new GroupElement(this.valueOf().add(ge.valueOf()));
        }, "add"));
        __publicField(this, "mul", /* @__PURE__ */ __name((sc) => {
          return new GroupElement(this.valueOf().mul(sc.valueOf()));
        }, "mul"));
        __publicField(this, "eq", /* @__PURE__ */ __name((ge) => {
          return this.valueOf().eq(ge.valueOf());
        }, "eq"));
        this._ec_point = point;
        this._curve = curve;
      }
    };
    __name(GroupElement, "GroupElement");
    GroupElement.generate_random = function(curve) {
      if (typeof curve == "undefined") {
        curve = default_curve();
      }
      return new GroupElement(curve.generator().mul(Scalar.generate_random().valueOf()));
    };
    GroupElement.from_bytes = function(buffer) {
      var ge_size = GroupElement.expected_byte_length();
      if (buffer.length != ge_size) {
        throw new Error("Invalid length of data.");
      }
      var sc_size = Scalar.expected_byte_length();
      var x = buffer.slice(1, sc_size + 1);
      var y = buffer.slice(sc_size + 1, ge_size);
      return new GroupElement(default_curve()._curve.curve.point(x, y));
    };
    GroupElement.expected_byte_length = function(curve, is_compressed) {
      if (typeof curve == "undefined") {
        curve = default_curve();
      }
      if (is_compressed) {
        return 1 + curve.order_size();
      } else {
        return 1 + 2 * curve.order_size();
      }
    };
    function to_hex(byteArray) {
      return Array.from(byteArray, function(byte) {
        return ("0" + (byte & 255).toString(16)).slice(-2);
      }).join("");
    }
    __name(to_hex, "to_hex");
    function from_hex(hexString) {
      var result = [];
      while (hexString.length >= 2) {
        result.push(parseInt(hexString.substring(0, 2), 16));
        hexString = hexString.substring(2, hexString.length);
      }
      return result;
    }
    __name(from_hex, "from_hex");
    function SHA256(obj) {
      var hash = jsSha256.sha256.update(to_hex(obj.to_bytes())).digest();
      return new Scalar(new BN2__default.default(hash));
    }
    __name(SHA256, "SHA256");
    function hash_to_scalar(points) {
      var hash = jsSha256.sha256.create();
      for (var i = 0; i < points.length; i++) {
        hash.update(to_hex(points[i].to_bytes()));
      }
      var points_hash = hash.digest();
      var b1 = new BN2__default.default(points_hash);
      var b2 = new BN2__default.default(1);
      return new Scalar(b1.add(b2));
    }
    __name(hash_to_scalar, "hash_to_scalar");
    var PrivateKey = class {
      constructor(prvKey, pubKey) {
        /**
         * \brief Getting the big integer which is representing this Private Key.
         */
        __publicField(this, "valueOf", /* @__PURE__ */ __name(function() {
          return this._scalar;
        }, "valueOf"));
        /**
         * \brief Getting generated PublicKey
         * @return PublicKey
         */
        __publicField(this, "get_public_key", /* @__PURE__ */ __name(function() {
          var curve = new Curve();
          return new PublicKey(new GroupElement(curve.generator().mul(this.valueOf().valueOf())));
        }, "get_public_key"));
        /**
         * \brief Getting BIGNUM bytes from existing BigInteger
         * @return vector of bytes
         */
        __publicField(this, "to_bytes", /* @__PURE__ */ __name(function() {
          return this.valueOf().to_bytes();
        }, "to_bytes"));
        this._scalar = prvKey;
        if (typeof pubKey == "undefined") {
          var curve = new Curve();
          pubKey = new PublicKey(new GroupElement(curve.generator().mul(prvKey.valueOf())));
        }
        this._public_key = pubKey;
      }
    };
    __name(PrivateKey, "PrivateKey");
    PrivateKey.from_bytes = function(buffer) {
      return new PrivateKey(Scalar.from_bytes(buffer));
    };
    PrivateKey.generate = function(seed, curve, options2) {
      if (typeof curve == "undefined") {
        curve = default_curve();
      }
      if (typeof seed !== "undefined") {
        seed = seed.toString("hex");
      }
      let entropy = "";
      if (seed) {
        entropy = new Uint8Array(192);
        seed.split("").map((item) => item.charCodeAt(0)).map((i, index) => {
          entropy.fill(i, index, index + 1);
        });
        entropy.fill(0, seed.split("").length, 191);
        seed = void 0;
      }
      var kp = curve._curve.genKeyPair(seed, {
        entropy
      });
      return new PrivateKey(new Scalar(kp.getPrivate()), new PublicKey(new GroupElement(kp.getPublic())));
    };
    var PublicKey = class {
      constructor(pubKey) {
        /**
         * Getting point from this public key
         * @return
         */
        __publicField(this, "valueOf", /* @__PURE__ */ __name(function() {
          return this.pubKey;
        }, "valueOf"));
        __publicField(this, "to_bytes", /* @__PURE__ */ __name(function() {
          return this.valueOf().to_bytes();
        }, "to_bytes"));
        this.pubKey = pubKey;
      }
    };
    __name(PublicKey, "PublicKey");
    PublicKey.from_bytes = function(buffer) {
      return new PublicKey(GroupElement.from_bytes(buffer));
    };
    var ReEncryptionKey = class {
      constructor(re_key, internal_public_key) {
        /**
         * \brief Getting RK number
         * @return
         */
        __publicField(this, "get_re_key", /* @__PURE__ */ __name(function() {
          return this._re_key;
        }, "get_re_key"));
        /**
         * Getting RK point
         * @return
         */
        __publicField(this, "get_internal_public_key", /* @__PURE__ */ __name(function() {
          return this._internal_public_key;
        }, "get_internal_public_key"));
        __publicField(this, "to_bytes", /* @__PURE__ */ __name(function() {
          var rk = this.get_re_key().to_bytes();
          var ipc = this.get_internal_public_key().to_bytes();
          return rk.concat(ipc);
        }, "to_bytes"));
        this._re_key = re_key;
        this._internal_public_key = internal_public_key;
      }
    };
    __name(ReEncryptionKey, "ReEncryptionKey");
    ReEncryptionKey.from_bytes = function(buffer) {
      var sc_size = Scalar.expected_byte_length();
      var ge_size = GroupElement.expected_byte_length();
      if (buffer.length != ge_size + sc_size) {
        throw new Error("Invalid length of data.");
      }
      var rk = Scalar.from_bytes(buffer.slice(0, sc_size));
      var ipc = GroupElement.from_bytes(buffer.slice(sc_size, sc_size + ge_size));
      return new ReEncryptionKey(rk, ipc);
    };
    var Capsule = class {
      constructor(E, V, S, XG, is_re_encrypted) {
        /**
         * Getting particle E as a POINT_TYPE
         * @return
         */
        __publicField(this, "get_E", /* @__PURE__ */ __name(() => {
          return this._E;
        }, "get_E"));
        /**
         * Getting particle V as a POINT_TYPE
         * @return
         */
        __publicField(this, "get_V", /* @__PURE__ */ __name(() => {
          return this._V;
        }, "get_V"));
        /**
         * Getting particle S as a NUMBER_TYPE
         * @return
         */
        __publicField(this, "get_S", /* @__PURE__ */ __name(() => {
          return this._S;
        }, "get_S"));
        /**
         * Getting particle XG
         * @return
         */
        __publicField(this, "get_XG", /* @__PURE__ */ __name(() => {
          return this._XG;
        }, "get_XG"));
        /**
         * \brief Setting capsule as re-encryption capsule
         */
        __publicField(this, "set_re_encrypted", /* @__PURE__ */ __name(() => {
          this._re_encrypted = true;
        }, "set_re_encrypted"));
        /**
         * \brief Checking if we have re-encryption capsule or not
         * @return
         */
        __publicField(this, "is_re_encrypted", /* @__PURE__ */ __name(() => {
          return this._re_encrypted;
        }, "is_re_encrypted"));
        __publicField(this, "to_bytes", /* @__PURE__ */ __name(() => {
          var bytearray_E = this.get_E().to_bytes();
          var bytearray_V = this.get_V().to_bytes();
          var bytearray_S = this.get_S().to_bytes();
          var bytearray_XG = [];
          if (this.is_re_encrypted()) {
            bytearray_XG = this.get_XG().to_bytes();
          }
          return bytearray_E.concat(bytearray_V, bytearray_S, bytearray_XG);
        }, "to_bytes"));
        if (typeof is_re_encrypted == "undefined") {
          is_re_encrypted = false;
        }
        this._E = E;
        this._V = V;
        this._S = S;
        this._XG = XG;
        this._re_encrypted = is_re_encrypted;
      }
    };
    __name(Capsule, "Capsule");
    Capsule.from_bytes = function(buffer) {
      var sc_size = Scalar.expected_byte_length();
      var ge_size = GroupElement.expected_byte_length();
      var re_encrypted = false;
      if (buffer.length == 3 * ge_size + sc_size) {
        re_encrypted = true;
      } else if (buffer.length != 2 * ge_size + sc_size) {
        throw new Error("Invalid length of data.");
      }
      var E = GroupElement.from_bytes(buffer.slice(0, ge_size));
      var V = GroupElement.from_bytes(buffer.slice(ge_size, 2 * ge_size));
      var S = Scalar.from_bytes(buffer.slice(2 * ge_size, 2 * ge_size + sc_size));
      var XG = void 0;
      if (re_encrypted) {
        XG = GroupElement.from_bytes(buffer.slice(2 * ge_size + sc_size, 3 * ge_size + sc_size));
      }
      return new Capsule(E, V, S, XG, re_encrypted);
    };
    var KeyPair = class {
      constructor(prvKey, pubKey) {
        /**
         * \brief Getting public key
         * @return
         */
        __publicField(this, "get_public_key", /* @__PURE__ */ __name(function() {
          return this._public_key;
        }, "get_public_key"));
        /**
         * Getting private key
         * @return
         */
        __publicField(this, "get_private_key", /* @__PURE__ */ __name(function() {
          return this._private_key;
        }, "get_private_key"));
        this._private_key = prvKey;
        this._public_key = pubKey;
      }
    };
    __name(KeyPair, "KeyPair");
    KeyPair.generate_key_pair = function(seed) {
      var prvKey = PrivateKey.generate(seed);
      return new KeyPair(prvKey, prvKey.get_public_key());
    };
    function Proxy2() {
    }
    __name(Proxy2, "Proxy");
    Proxy2.generate_key_pair = function(seed) {
      return KeyPair.generate_key_pair(seed);
    };
    Proxy2.encapsulate = function(publicKey) {
      var kp1 = Proxy2.generate_key_pair();
      var kp2 = Proxy2.generate_key_pair();
      var sk1 = kp1.get_private_key().valueOf();
      var sk2 = kp2.get_private_key().valueOf();
      var pk1 = kp1.get_public_key().valueOf();
      var pk2 = kp2.get_public_key().valueOf();
      var tmpHash = [pk1, pk2];
      var hash = hash_to_scalar(tmpHash);
      var part_S = sk1.add(sk2.mul(hash));
      var pk_point = publicKey.valueOf();
      var point_symmetric = pk_point.mul(sk1.add(sk2));
      var symmetric_key = SHA256(point_symmetric);
      var cps = new Capsule(pk1, pk2, part_S);
      var capsule = { "capsule": cps, "symmetric_key": symmetric_key };
      return capsule;
    };
    Proxy2.decapsulate_original = function(capsule, privateKey) {
      var sk = privateKey.valueOf();
      var s = capsule.get_E().add(capsule.get_V());
      var point_symmetric = s.mul(sk);
      var symmetric_key = SHA256(point_symmetric);
      return symmetric_key;
    };
    Proxy2.generate_re_encryption_key = function(privateKey, publicKey) {
      var kp = Proxy2.generate_key_pair();
      var tmp_sk = kp.get_private_key().valueOf();
      var tmp_pk = kp.get_public_key().valueOf();
      var pk_point = publicKey.valueOf();
      var points_for_hash = [tmp_pk, pk_point, pk_point.mul(tmp_sk)];
      var hash = hash_to_scalar(points_for_hash);
      var sk = privateKey.valueOf();
      var hash_inv = hash.invm();
      var rk = sk.mul(hash_inv);
      var re_key = new ReEncryptionKey(rk, tmp_pk);
      return re_key;
    };
    Proxy2.re_encrypt_capsule = function(capsule, rk) {
      var prime_E = capsule.get_E().mul(rk.get_re_key());
      var prime_V = capsule.get_V().mul(rk.get_re_key());
      var prime_S = capsule.get_S();
      return new Capsule(prime_E, prime_V, prime_S, rk.get_internal_public_key(), true);
    };
    Proxy2.decapsulate_re_encrypted = function(capsule, privateKey) {
      var prime_XG = capsule.get_XG();
      var prime_E = capsule.get_E();
      var prime_V = capsule.get_V();
      var points_for_hash = [prime_XG, privateKey.get_public_key().valueOf(), prime_XG.mul(privateKey.valueOf())];
      var hash = hash_to_scalar(points_for_hash);
      var tmp_kdf_point = prime_E.add(prime_V).mul(hash);
      var symmetric_key = SHA256(tmp_kdf_point);
      return symmetric_key;
    };
    Proxy2.decapsulate = function(capsule, privateKey) {
      if (capsule.is_re_encrypted()) {
        return Proxy2.decapsulate_re_encrypted(capsule, privateKey);
      }
      return Proxy2.decapsulate_original(capsule, privateKey);
    };
    Proxy2.private_key_from_bytes = function(data) {
      return PrivateKey.from_bytes(data);
    };
    Proxy2.public_key_from_bytes = function(data) {
      return PublicKey.from_bytes(data);
    };
    Proxy2.re_encryption_key_from_bytes = function(data) {
      return ReEncryptionKey.from_bytes(data);
    };
    Proxy2.capsule_from_bytes = function(data) {
      return Capsule.from_bytes(data);
    };
    Proxy2.to_hex = function(data) {
      return to_hex(data);
    };
    Proxy2.from_hex = function(data) {
      return from_hex(data);
    };
    var options = {
      iv: CryptoJS__default.default.enc.Utf8.parse("0000000000000000"),
      mode: CryptoJS__default.default.mode.CBC,
      padding: CryptoJS__default.default.pad.Pkcs7
    };
    function encryptData(publicKey, data) {
      let pubKey = Proxy2.public_key_from_bytes(Proxy2.from_hex(publicKey));
      var cp = Proxy2.encapsulate(pubKey);
      var symKey = Proxy2.to_hex(cp.symmetric_key.to_bytes());
      var key = CryptoJS__default.default.enc.Utf8.parse(symKey);
      var encrypted = CryptoJS__default.default.AES.encrypt(data, key, options);
      return {
        key: Proxy2.to_hex(cp.capsule.to_bytes()),
        cipher: encrypted.toString()
      };
    }
    __name(encryptData, "encryptData");
    function decryptData(privateKey, obj) {
      let priKey = Proxy2.private_key_from_bytes(Proxy2.from_hex(privateKey));
      let capsule = Proxy2.capsule_from_bytes(Proxy2.from_hex(obj.key));
      var symKey = Proxy2.decapsulate(capsule, priKey);
      var key = CryptoJS__default.default.enc.Utf8.parse(Proxy2.to_hex(symKey.to_bytes()));
      var decrypted = CryptoJS__default.default.AES.decrypt(obj.cipher, key, options).toString(CryptoJS__default.default.enc.Utf8);
      return decrypted;
    }
    __name(decryptData, "decryptData");
    function generateReEncrytionKey(privateKey, publicKey) {
      let priKey = Proxy2.private_key_from_bytes(Proxy2.from_hex(privateKey));
      let pubKey = Proxy2.public_key_from_bytes(Proxy2.from_hex(publicKey));
      var rk = Proxy2.generate_re_encryption_key(priKey, pubKey);
      return Proxy2.to_hex(rk.to_bytes());
    }
    __name(generateReEncrytionKey, "generateReEncrytionKey");
    function reEncryption(Rk, obj) {
      let rk = Proxy2.re_encryption_key_from_bytes(Proxy2.from_hex(Rk));
      let capsule = Proxy2.capsule_from_bytes(Proxy2.from_hex(obj.key));
      let re_capsule = Proxy2.re_encrypt_capsule(capsule, rk);
      obj.key = Proxy2.to_hex(re_capsule.to_bytes());
    }
    __name(reEncryption, "reEncryption");
    module.exports = {
      encryptData,
      decryptData,
      generateReEncrytionKey,
      reEncryption,
      Proxy: Proxy2,
      PrivateKey,
      PublicKey
    };
  }
});
var index = require_src();

module.exports = index;
