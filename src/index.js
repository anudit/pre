/* tslint:disable */
import BN from "bn.js";
import CryptoJS from 'crypto-js';
import { sha256 } from 'js-sha256';

import { Curve, default_curve } from './Config';
import { Scalar } from './Math';

/**
 * \brief Elliptic curve Point class implementation based elliptic lib
 */
class GroupElement {
  constructor(point, curve) {
    this._ec_point = point; // ECPoint
    this._curve = curve;
  };

  to_bytes = () => {
    var x = this._ec_point.getX().toArray();
    var y = this._ec_point.getY().toArray();
    return [0x04].concat(x, y);
  }

  valueOf = () => { return this._ec_point; }

  add = (ge /* GroupElement */) => { return new GroupElement(this.valueOf().add(ge.valueOf())); }
  mul = (sc /* Scalar */) => { return new GroupElement(this.valueOf().mul(sc.valueOf())); }
  eq = (ge /* GroupElement */) => { return this.valueOf().eq(ge.valueOf()); }
}

GroupElement.generate_random = function (curve) {
  if (typeof curve == "undefined") {
    curve = default_curve();
  }
  return new GroupElement(curve.generator().mul(Scalar.generate_random().valueOf()));
}

GroupElement.from_bytes = function (buffer) {
  var ge_size = GroupElement.expected_byte_length();
  if (buffer.length != ge_size) {
    throw new Error("Invalid length of data.");
  }
  var sc_size = Scalar.expected_byte_length();
  var x = buffer.slice(1, sc_size + 1);
  var y = buffer.slice(sc_size + 1, ge_size);
  return new GroupElement(default_curve()._curve.curve.point(x, y));
}

GroupElement.expected_byte_length = function (curve /* Curve */, is_compressed) {
  if (typeof curve == "undefined") {
    curve = default_curve();
  }
  if (is_compressed) {
    return 1 + curve.order_size();
  }
  else {
    return 1 + 2 * curve.order_size();
  }
}

function to_hex(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

function from_hex(hexString) {
  var result = [];
  while (hexString.length >= 2) {
    result.push(parseInt(hexString.substring(0, 2), 16));
    hexString = hexString.substring(2, hexString.length);
  }
  return result;
}

/**
 * SHA256
 */
function SHA256(obj) {
  var hash = sha256.update(to_hex(obj.to_bytes())).digest();
  return new Scalar(new BN(hash));
}

/**
 * Concat of hashes of GroupElement's
 * @param points
 * @return 
 */
function hash_to_scalar(points) {
  var hash = sha256.create();
  for (var i = 0; i < points.length; i++) {
    hash.update(to_hex(points[i].to_bytes()));
  }
  var points_hash = hash.digest();
  var b1 = new BN(points_hash);
  var b2 = new BN(1);
  return new Scalar(b1.add(b2));
}


/**
 * \brief Base private key containing implementation for EC Private keys
 * \brief Main constructor for making PrivateKey object
 */
class PrivateKey {
  constructor(prvKey /* Scalar */, pubKey /* PublicKey */) {
    this._scalar = prvKey;  // prvKeyObj
    if (typeof pubKey == "undefined") {
      var curve = new Curve();
      pubKey = new PublicKey(new GroupElement(curve.generator().mul(prvKey.valueOf())));
    }
    this._public_key = pubKey;
  }

  /**
   * \brief Getting the big integer which is representing this Private Key.
   */
  valueOf = function () { return this._scalar; }

  /**
   * \brief Getting generated PublicKey
   * @return PublicKey
   */
  get_public_key = function () {
    var curve = new Curve();
    return new PublicKey(new GroupElement(curve.generator().mul(this.valueOf().valueOf())));
  }

  /**
   * \brief Getting BIGNUM bytes from existing BigInteger
   * @return vector of bytes
   */
  to_bytes = function () {
    return this.valueOf().to_bytes();
  }

}

/**
 * \brief Get BigInteger from big endian ordered bytes
 * @param buffer
 * @return
 */
PrivateKey.from_bytes = function (buffer) {
  return new PrivateKey(Scalar.from_bytes(buffer));
}

/**
 * \brief Generating PrivateKey
 * @param 
 * @return PrivateKey
 */
PrivateKey.generate = function (seed, curve, options) {
  if (typeof curve == "undefined") {
    curve = default_curve();
  }
  if (typeof seed !== "undefined") {
    seed = seed.toString('hex');
  }
  let entropy = ''
  if (seed) {
    entropy = new Uint8Array(192)
    seed.split('').map(item => item.charCodeAt(0)).map((i, index) => {
      entropy.fill(i, index, index + 1)
    })
    entropy.fill(0, seed.split('').length, 191)
    seed = undefined
  }
  var kp = curve._curve.genKeyPair(seed, {
    entropy: entropy
  });
  return new PrivateKey(new Scalar(kp.getPrivate()), new PublicKey(new GroupElement(kp.getPublic())));
}


/**
 * \brief PublicKey class is a base implementation for keeping EC Public Key as an object
 */
class PublicKey {
  constructor(pubKey /* GroupElement */) {
    this.pubKey = pubKey; // pubKeyObj
  }
  /**
   * Getting point from this public key
   * @return
   */
  valueOf = function () {
    return this.pubKey
  }

  to_bytes = function () {
    return this.valueOf().to_bytes();
  }
}

PublicKey.from_bytes = function (buffer) {
  return new PublicKey(GroupElement.from_bytes(buffer));
}


/**
 * \brief Base definition for re-encryption key
 */
class ReEncryptionKey {

  constructor(re_key /* Scalar */, internal_public_key /* GroupElement */) {
    this._re_key = re_key; // BigInteger
    this._internal_public_key = internal_public_key; // ECPoint
  }

  /**
   * \brief Getting RK number
   * @return
   */
  get_re_key = function () { return this._re_key; }

  /**
   * Getting RK point
   * @return
   */
  get_internal_public_key = function () { return this._internal_public_key; }

  to_bytes = function () {
    var rk = this.get_re_key().to_bytes();
    var ipc = this.get_internal_public_key().to_bytes();
    return rk.concat(ipc);
  }
}

ReEncryptionKey.from_bytes = function (buffer) {
  var sc_size = Scalar.expected_byte_length();
  var ge_size = GroupElement.expected_byte_length();


  if (buffer.length != ge_size + sc_size) {
    throw new Error("Invalid length of data.");
  }

  var rk = Scalar.from_bytes(buffer.slice(0, sc_size));
  var ipc = GroupElement.from_bytes(buffer.slice(sc_size, sc_size + ge_size));
  return new ReEncryptionKey(rk, ipc);
}


/**
 * \brief Combination of parameters as a definition for cryptographic capsule
 * Each capsule contains E(POINT_TYPE), V(POINT_TYPE), s(NUMBER_TYPE)
 * \brief Making capsule with given particles
 * @param E
 * @param V
 * @param S
 * @param XG
 * @param re_encrypted
 */
class Capsule {
  constructor(E, V, S, XG, is_re_encrypted) {
    if (typeof is_re_encrypted == "undefined") {
      is_re_encrypted = false;
    }
    this._E = E;  // ECPoint
    this._V = V;  // ECPoint
    this._S = S;  // BN
    this._XG = XG;// ECPoint 
    this._re_encrypted = is_re_encrypted; //bool
  }
  /**
   * Getting particle E as a POINT_TYPE
   * @return
   */
  get_E = () => { return this._E; }

  /**
   * Getting particle V as a POINT_TYPE
   * @return
   */
  get_V = () => { return this._V; }

  /**
   * Getting particle S as a NUMBER_TYPE
   * @return
   */
  get_S = () => { return this._S; }

  /**
   * Getting particle XG
   * @return
   */
  get_XG = () => { return this._XG; }

  /**
   * \brief Setting capsule as re-encryption capsule
   */
  set_re_encrypted = () => { this._re_encrypted = true; }

  /**
   * \brief Checking if we have re-encryption capsule or not
   * @return
   */
  is_re_encrypted = () => { return this._re_encrypted; }

  to_bytes = () => {
    var bytearray_E = this.get_E().to_bytes();
    var bytearray_V = this.get_V().to_bytes();
    var bytearray_S = this.get_S().to_bytes();
    var bytearray_XG = [];
    if (this.is_re_encrypted()) {
      bytearray_XG = this.get_XG().to_bytes();
    }
    return bytearray_E.concat(bytearray_V, bytearray_S, bytearray_XG);
  }

}

Capsule.from_bytes = function (buffer) {
  var sc_size = Scalar.expected_byte_length();
  var ge_size = GroupElement.expected_byte_length();

  var re_encrypted = false;

  if (buffer.length == 3 * ge_size + sc_size) {
    re_encrypted = true;
  }
  else if (buffer.length != 2 * ge_size + sc_size) {
    throw new Error("Invalid length of data.");
  }

  var E = GroupElement.from_bytes(buffer.slice(0, ge_size));
  var V = GroupElement.from_bytes(buffer.slice(ge_size, 2 * ge_size));
  var S = Scalar.from_bytes(buffer.slice(2 * ge_size, 2 * ge_size + sc_size));
  var XG = undefined;
  if (re_encrypted) {
    XG = GroupElement.from_bytes(buffer.slice(2 * ge_size + sc_size, 3 * ge_size + sc_size));
  }
  return new Capsule(E, V, S, XG, re_encrypted);

}


/**
 * \brief Key Pair for public and Private Keys
 * This class used as a combination of Public and Private keys, and can do some actions with both of them
 */
class KeyPair {
  constructor(prvKey/* PrivateKey */, pubKey/* PublicKey */) {
    this._private_key = prvKey;  // PrivateKey
    this._public_key = pubKey;   // PublicKey
  }

  /**
   * \brief Getting public key
   * @return
   */
  get_public_key = function () {
    return this._public_key;
  }

  /**
   * Getting private key
   * @return
   */
  get_private_key = function () {
    return this._private_key;
  }
}

/**
 * \brief Generating random KeyPair with their private and public keys
 * This is using Private key generator and getting public key out of generated private key
 * @return
 */
KeyPair.generate_key_pair = function (seed) {

  var prvKey = PrivateKey.generate(seed);
  return new KeyPair(prvKey, prvKey.get_public_key());
}

/**
 * \brief Proxy base class for handling library crypto operations and main functionality
 * Each initialized Proxy object should contain Context which will define
 * base parameters for crypto operations and configurations
 */
function Proxy() { }


Proxy.generate_key_pair = function (seed) { return KeyPair.generate_key_pair(seed); }

/**
 * \brief Making capsule out of given PublicKey and given crypto Context and also returning
 * symmetric key wrapped as a string object
 *
 * @param pk "Alice" Public Key
 * @param[out] symmetric_key_out
 * @return Capsule
 */
Proxy.encapsulate = function (publicKey) {
  // generating 2 random key pairs
  var kp1 = Proxy.generate_key_pair();
  var kp2 = Proxy.generate_key_pair();

  // getting random private keys out of generated KeyPair

  var sk1 = kp1.get_private_key().valueOf();
  var sk2 = kp2.get_private_key().valueOf();

  // getting random public key points 
  var pk1 = kp1.get_public_key().valueOf();
  var pk2 = kp2.get_public_key().valueOf();

  // concat public  key points 
  var tmpHash = [pk1, pk2];
  var hash = hash_to_scalar(tmpHash);

  // Calculating part S from BN hashing -> sk1 + sk2 * hash_bn
  var part_S = sk1.add(sk2.mul(hash));

  // Making symmetric key
  // getting main public key point
  var pk_point = publicKey.valueOf();

  // pk * (sk1 + sk2)
  var point_symmetric = pk_point.mul(sk1.add(sk2));
  var symmetric_key = SHA256(point_symmetric);

  // return capsule
  var cps = new Capsule(pk1, pk2, part_S);
  var capsule = { "capsule": cps, "symmetric_key": symmetric_key };
  return capsule
}

/**
 * \brief Decapsulate given capsule with private key,
 * NOTE: Provided private key, should be the original key from which Public Key capsule is created
 * @param capsule
 * @param privateKey
 * @return
 */
Proxy.decapsulate_original = function (capsule, privateKey) {
  // get private key value
  var sk = privateKey.valueOf();
  // capsule.E + capsule.V
  var s = capsule.get_E().add(capsule.get_V());
  // get symmetric key -> s * sk = (capsule.E + capsule.V) * sk
  var point_symmetric = s.mul(sk);
  var symmetric_key = SHA256(point_symmetric); //  
  return symmetric_key;
}

/**
 * \brief Getting re-encryption key out of Private key (Alice) and public key (Bob) using random private key generation
 * @param privateKeyA
 * @param publicKeyB
 * @return
 */
Proxy.generate_re_encryption_key = function (privateKey, publicKey) {
  // generate random key pair
  var kp = Proxy.generate_key_pair()
  // get random key values
  var tmp_sk = kp.get_private_key().valueOf();
  var tmp_pk = kp.get_public_key().valueOf();

  // get main public key point
  var pk_point = publicKey.valueOf();

  // concat tmp public key, main pulic key and pk * tmp_sk
  var points_for_hash = [tmp_pk, pk_point, pk_point.mul(tmp_sk)];

  var hash = hash_to_scalar(points_for_hash);

  var sk = privateKey.valueOf();
  var hash_inv = hash.invm();
  // rk = sk * (1/hash_bn)
  var rk = sk.mul(hash_inv);
  var re_key = new ReEncryptionKey(rk, tmp_pk);
  return re_key;
}

/**
 * \brief Getting re-encryption capsule from given original capsule and re-encryption key
 * @param capsuleOriginal
 * @param reEncryptionKey
 * @return
 */
Proxy.re_encrypt_capsule = function (capsule, rk) {
  // capsule.E * rk.rk
  var prime_E = capsule.get_E().mul(rk.get_re_key());
  // capsule.V * rk.rk
  var prime_V = capsule.get_V().mul(rk.get_re_key());
  var prime_S = capsule.get_S();

  return new Capsule(prime_E, prime_V, prime_S, rk.get_internal_public_key(), true);  // Is_reencrypted = true
}

/**
 * \brief Decapsulating given capsule with provided private key
 * @param re_encrypted_capsule
 * @param privateKey
 * @return
 */
Proxy.decapsulate_re_encrypted = function (capsule, privateKey) {
  var prime_XG = capsule.get_XG();
  var prime_E = capsule.get_E();
  var prime_V = capsule.get_V();

  // concat prime_XG, publicKey point, prime_XG * sk 
  var points_for_hash = [prime_XG, privateKey.get_public_key().valueOf(), prime_XG.mul(privateKey.valueOf())];
  var hash = hash_to_scalar(points_for_hash);

  // (capsule.E + capsule.V) * hash_bn
  var tmp_kdf_point = prime_E.add(prime_V).mul(hash);

  var symmetric_key = SHA256(tmp_kdf_point);
  return symmetric_key;
}

Proxy.decapsulate = function (capsule, privateKey) {
  if (capsule.is_re_encrypted()) {
    return Proxy.decapsulate_re_encrypted(capsule, privateKey);
  }
  return Proxy.decapsulate_original(capsule, privateKey);

}

Proxy.private_key_from_bytes = function (data) { return PrivateKey.from_bytes(data); }
Proxy.public_key_from_bytes = function (data) { return PublicKey.from_bytes(data); }
Proxy.re_encryption_key_from_bytes = function (data) { return ReEncryptionKey.from_bytes(data); }
Proxy.capsule_from_bytes = function (data) { return Capsule.from_bytes(data); }
Proxy.to_hex = function (data) { return to_hex(data); }
Proxy.from_hex = function (data) { return from_hex(data); }



var options = {
  iv: CryptoJS.enc.Utf8.parse("0000000000000000"),
  mode: CryptoJS.mode.CBC,
  padding: CryptoJS.pad.Pkcs7
}
function encryptData(publicKey, data) {
  let pubKey = Proxy.public_key_from_bytes(Proxy.from_hex(publicKey));
  var cp = Proxy.encapsulate(pubKey);
  var symKey = Proxy.to_hex(cp.symmetric_key.to_bytes());

  var key = CryptoJS.enc.Utf8.parse(symKey);
  var encrypted = CryptoJS.AES.encrypt(data, key, options);

  return {
    key: Proxy.to_hex(cp.capsule.to_bytes()),
    cipher: encrypted.toString()
  }
}

function decryptData(privateKey, obj) {
  let priKey = Proxy.private_key_from_bytes(Proxy.from_hex(privateKey));
  let capsule = Proxy.capsule_from_bytes(Proxy.from_hex(obj.key));
  var symKey = Proxy.decapsulate(capsule, priKey);

  var key = CryptoJS.enc.Utf8.parse(Proxy.to_hex(symKey.to_bytes()));
  var decrypted = CryptoJS.AES.decrypt(obj.cipher, key, options).toString(CryptoJS.enc.Utf8);

  return decrypted;

}

function generateReEncrytionKey(privateKey, publicKey) {
  let priKey = Proxy.private_key_from_bytes(Proxy.from_hex(privateKey));
  let pubKey = Proxy.public_key_from_bytes(Proxy.from_hex(publicKey));

  var rk = Proxy.generate_re_encryption_key(priKey, pubKey);
  return Proxy.to_hex(rk.to_bytes())
}
function reEncryption(Rk, obj) {
  let rk = Proxy.re_encryption_key_from_bytes(Proxy.from_hex(Rk));
  let capsule = Proxy.capsule_from_bytes(Proxy.from_hex(obj.key));
  let re_capsule = Proxy.re_encrypt_capsule(capsule, rk);
  obj.key = Proxy.to_hex(re_capsule.to_bytes())
}

module.exports = {
  encryptData,
  decryptData,
  generateReEncrytionKey,
  reEncryption,
  Proxy,
  PrivateKey,
  PublicKey
}