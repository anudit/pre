const assert = require('assert');
let BN = require('bn.js');
let { to_hex, Config, Scalar, default_curve, KeyPair, Proxy, encryptData, generateReEncrytionKey, reEncryption, decryptData, from_hex } = require('../lib/index');
let { generatePrivateKey } = require('viem/accounts')

let alice_sk = generatePrivateKey();

var kp_A = KeyPair.from_private_key(alice_sk);
var sk_A = to_hex(kp_A.get_private_key().to_bytes());
var pk_A = to_hex(kp_A.get_public_key().to_bytes());

let bob_sk = generatePrivateKey();

var kp_B = KeyPair.from_private_key(bob_sk);
var sk_B = to_hex(kp_B.get_private_key().to_bytes());
var pk_B = to_hex(kp_B.get_public_key().to_bytes());

const msg = "test data";
let obj = encryptData(pk_A, msg)
let rk = generateReEncrytionKey(sk_A, pk_B);
reEncryption(rk, obj)

let decryptedData = decryptData(sk_B, obj)
assert(msg, decryptedData, "Decryption Failed")
console.log(msg, decryptedData)