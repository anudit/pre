import CryptoJS from 'crypto-js';

import { Capsule } from './Capsule';
import { Config, Curve, default_curve } from './Config';
import { KeyPair, PrivateKey, PublicKey, ReEncryptionKey } from './Keys';
import { GroupElement, Scalar } from './Math';
import { Proxy } from './Proxy';
import { SHA256, from_hex, hash_to_scalar, to_hex } from './utils';

var options = {
  iv: CryptoJS.enc.Utf8.parse("0000000000000000"),
  mode: CryptoJS.mode.CBC,
  padding: CryptoJS.pad.Pkcs7
}

type EncryptedData = {
  key: string,
  cipher: string,
}

function encryptData(publicKey: string, data: string): EncryptedData {
  let pubKey = Proxy.public_key_from_bytes(from_hex(publicKey));
  var cp = Proxy.encapsulate(pubKey);
  var symKey = to_hex(cp.symmetric_key.to_bytes());

  var key = CryptoJS.enc.Utf8.parse(symKey);
  var encrypted = CryptoJS.AES.encrypt(data, key, options);

  return {
    key: to_hex(cp.capsule.to_bytes()),
    cipher: encrypted.toString()
  }
}

function decryptData(privateKey: string, obj: EncryptedData) {
  let priKey = Proxy.private_key_from_bytes(from_hex(privateKey));
  let capsule = Proxy.capsule_from_bytes(from_hex(obj.key));
  var symKey = Proxy.decapsulate(capsule, priKey);

  var key = CryptoJS.enc.Utf8.parse(to_hex(symKey.to_bytes()));
  var decrypted = CryptoJS.AES.decrypt(obj.cipher, key, options).toString(CryptoJS.enc.Utf8);

  return decrypted;

}

function generateReEncrytionKey(privateKey: string, publicKey: string) {
  let priKey = Proxy.private_key_from_bytes(from_hex(privateKey));
  let pubKey = Proxy.public_key_from_bytes(from_hex(publicKey));

  var rk = Proxy.generate_re_encryption_key(priKey, pubKey);
  return to_hex(rk.to_bytes())
}

function reEncryption(Rk: string, obj: EncryptedData) {
  let rk = Proxy.re_encryption_key_from_bytes(from_hex(Rk));
  let capsule = Proxy.capsule_from_bytes(from_hex(obj.key));
  let re_capsule = Proxy.re_encrypt_capsule(capsule, rk);
  obj.key = to_hex(re_capsule.to_bytes())
}

export { Capsule, Config, Curve, GroupElement, KeyPair, PrivateKey, Proxy, PublicKey, ReEncryptionKey, SHA256, Scalar, decryptData, default_curve, encryptData, from_hex, generateReEncrytionKey, hash_to_scalar, reEncryption, to_hex };

