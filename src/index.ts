import CryptoJS from 'crypto-js';

import { PrivateKey, PublicKey } from './Keys';
import { Proxy } from './Proxy';

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

function decryptData(privateKey: string, obj: EncryptedData) {
  let priKey = Proxy.private_key_from_bytes(Proxy.from_hex(privateKey));
  let capsule = Proxy.capsule_from_bytes(Proxy.from_hex(obj.key));
  var symKey = Proxy.decapsulate(capsule, priKey);

  var key = CryptoJS.enc.Utf8.parse(Proxy.to_hex(symKey.to_bytes()));
  var decrypted = CryptoJS.AES.decrypt(obj.cipher, key, options).toString(CryptoJS.enc.Utf8);

  return decrypted;

}

function generateReEncrytionKey(privateKey: string, publicKey: string) {
  let priKey = Proxy.private_key_from_bytes(Proxy.from_hex(privateKey));
  let pubKey = Proxy.public_key_from_bytes(Proxy.from_hex(publicKey));

  var rk = Proxy.generate_re_encryption_key(priKey, pubKey);
  return Proxy.to_hex(rk.to_bytes())
}

function reEncryption(Rk: string, obj: EncryptedData) {
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