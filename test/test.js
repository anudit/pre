const assert = require('assert');
let PRE = require('../lib/index');
let { generatePrivateKey } = require('viem/accounts')

let alice_sk = generatePrivateKey();

var kp_A = PRE.Proxy.generate_key_pair();
var sk_A = PRE.Proxy.to_hex(kp_A.get_private_key().to_bytes());
var pk_A = PRE.Proxy.to_hex(kp_A.get_public_key().to_bytes());
console.log('alice_sk', alice_sk)
console.log('sk_A', sk_A)
console.log('pk_A', pk_A)

var kp_B = PRE.Proxy.generate_key_pair();
var sk_B = PRE.Proxy.to_hex(kp_B.get_private_key().to_bytes());
var pk_B = PRE.Proxy.to_hex(kp_B.get_public_key().to_bytes());

const msg = "test data";
let obj = PRE.encryptData(pk_A, msg)
let rk = PRE.generateReEncrytionKey(sk_A, pk_B);
PRE.reEncryption(rk, obj)

let decryptedData = PRE.decryptData(sk_B, obj)
assert(msg, decryptedData, "Decryption Failed")
console.log(msg, decryptedData)