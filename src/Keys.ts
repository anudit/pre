import BN from 'bn.js';
import { Curve, default_curve } from "./Config";
import { GroupElement, Scalar } from "./Math";

/**
 * \brief Base private key containing implementation for EC Private keys
 * \brief Main constructor for making PrivateKey object
 */
class PrivateKey {
    _scalar: Scalar;
    _public_key: PublicKey;

    constructor(prvKey: Scalar) {
        this._scalar = prvKey;  // prvKeyObj
        const curve = new Curve();
        const pubKey = new PublicKey(new GroupElement(curve.generator().mul(prvKey.valueOf())));
        this._public_key = pubKey;
    }

    /**
     * \brief Getting the big integer which is representing this Private Key.
     */
    valueOf() { return this._scalar; }

    /**
     * \brief Getting generated PublicKey
     * @return PublicKey
     */
    get_public_key() {
        var curve = new Curve();
        return new PublicKey(new GroupElement(curve.generator().mul(this.valueOf().valueOf())));
    }

    /**
     * \brief Getting BIGNUM bytes from existing BigInteger
     * @return vector of bytes
     */
    to_bytes() {
        return this.valueOf().to_bytes();
    }

    /**
     * \brief Get BigInteger from big endian ordered bytes
     * @param buffer
     * @return
     */
    static from_bytes = function (buffer: Buffer) {
        return new PrivateKey(Scalar.from_bytes(buffer));
    }

    /**
     * \brief Generating PrivateKey
     * @param 
     * @return PrivateKey
     */
    static generate(seed?: Buffer) {
        const curve = default_curve();
        // TODO: use seed here.
        var kp = curve._curve.genKeyPair();
        return new PrivateKey(new Scalar(kp.getPrivate()));
    }

}

/**
 * \brief PublicKey class is a base implementation for keeping EC Public Key as an object
 */
class PublicKey {

    pubKey: GroupElement;

    constructor(pubKey: GroupElement) {
        this.pubKey = pubKey; // pubKeyObj
    }
    /**
     * Getting point from this public key
     * @return
     */
    valueOf() {
        return this.pubKey
    }

    to_bytes() {
        return this.valueOf().to_bytes();
    }

    static from_bytes(buffer: Buffer) {
        return new PublicKey(GroupElement.from_bytes(buffer));
    }
}

/**
 * \brief Base definition for re-encryption key
 */
class ReEncryptionKey {

    _re_key: Scalar;
    _internal_public_key: GroupElement;

    constructor(re_key: Scalar, internal_public_key: GroupElement) {
        this._re_key = re_key; // BigInteger
        this._internal_public_key = internal_public_key; // ECPoint
    }

    /**
     * \brief Getting RK number
     * @return
     */
    get_re_key() { return this._re_key; }

    /**
     * Getting RK point
     * @return
     */
    get_internal_public_key() { return this._internal_public_key; }

    to_bytes() {
        var rk = this.get_re_key().to_bytes();
        var ipc = this.get_internal_public_key().to_bytes();
        return rk.concat(ipc);
    }

    static from_bytes(buffer: Buffer) {
        var sc_size = Scalar.expected_byte_length();
        var ge_size = GroupElement.expected_byte_length();


        if (buffer.length != ge_size + sc_size) {
            throw new Error("Invalid length of data.");
        }

        var rk = Scalar.from_bytes(buffer.subarray(0, sc_size));
        var ipc = GroupElement.from_bytes(buffer.subarray(sc_size, sc_size + ge_size));
        return new ReEncryptionKey(rk, ipc);
    }
}

/**
 * \brief Key Pair for public and Private Keys
 * This class used as a combination of Public and Private keys, and can do some actions with both of them
 */
class KeyPair {

    _private_key: PrivateKey
    _public_key: PublicKey

    constructor(prvKey: PrivateKey, pubKey: PublicKey) {
        this._private_key = prvKey;  // PrivateKey
        this._public_key = pubKey;   // PublicKey
    }

    /**
     * \brief Getting public key
     * @return
     */
    get_public_key() {
        return this._public_key;
    }

    /**
     * Getting private key
     * @return
     */
    get_private_key() {
        return this._private_key;
    }

    /**
     * \brief Generating random KeyPair with their private and public keys
     * This is using Private key generator and getting public key out of generated private key
     * @return
     */
    static generate_key_pair() {

        var prvKey = PrivateKey.generate();
        return new KeyPair(prvKey, prvKey.get_public_key());
    }

    static from_private_key(private_key: string) {
        const prvKey = new PrivateKey(new Scalar(new BN(private_key.startsWith('0x') ? private_key.slice(2) : private_key, 'hex')));
        return new KeyPair(prvKey, prvKey.get_public_key());
    }
}

export { KeyPair, PrivateKey, PublicKey, ReEncryptionKey };
