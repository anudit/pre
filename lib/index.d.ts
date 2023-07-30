import elliptic from 'elliptic';
import BN from 'bn.js';

declare class Config {
    _curve: Curve;
    _default_curve: Curve;
    constructor();
    set_curve: () => void;
    set_curve_by_default: () => void;
    curve: () => Curve;
}
declare function default_curve(): Curve;
declare class Curve {
    _curve: elliptic.ec;
    _name: string;
    _order: any;
    _generator: any;
    _order_size: any;
    constructor();
    name: () => string;
    order: () => any;
    generator: () => any;
    order_size: () => any;
}

declare class Scalar {
    _scalar: BN;
    _curve: Curve;
    constructor(bigInt: BN);
    curve: () => Curve;
    /**
     * valueOf
     */
    valueOf: () => BN;
    /**
     * \brief Getting BIGNUM bytes from existing BigInteger
     * @return vector of bytes
     */
    to_bytes: () => number[];
    add: (sc: Scalar) => Scalar;
    sub: (sc: Scalar) => Scalar;
    mul: (sc: Scalar) => Scalar;
    eq: (sc: Scalar) => boolean;
    invm: () => Scalar;
    /**
    * \brief Generate random BigInteger.
    * @return
    */
    static generate_random: () => Scalar;
    /**
     *  get length of BN
     */
    static expected_byte_length: () => any;
    /**
     * \brief Get BigInteger from big endian ordered bytes
     * @param buffer
     * @return
     */
    static from_bytes(buffer: Buffer): Scalar;
}
/**
 * \brief Elliptic curve Point class implementation based elliptic lib
 */
declare class GroupElement {
    _ec_point: elliptic.curve.base.BasePoint;
    _curve: Curve;
    constructor(point: elliptic.curve.base.BasePoint);
    to_bytes: () => number[];
    valueOf: () => elliptic.curve.base.BasePoint;
    add: (ge: GroupElement) => GroupElement;
    mul: (sc: Scalar) => GroupElement;
    eq: (ge: GroupElement) => boolean;
    static generate_random: () => GroupElement;
    static from_bytes: (buffer: Buffer) => GroupElement;
    static expected_byte_length: (is_compressed?: boolean) => any;
}

/**
 * \brief Base private key containing implementation for EC Private keys
 * \brief Main constructor for making PrivateKey object
 */
declare class PrivateKey {
    _scalar: Scalar;
    _public_key: PublicKey;
    constructor(prvKey: Scalar);
    /**
     * \brief Getting the big integer which is representing this Private Key.
     */
    valueOf(): Scalar;
    /**
     * \brief Getting generated PublicKey
     * @return PublicKey
     */
    get_public_key(): PublicKey;
    /**
     * \brief Getting BIGNUM bytes from existing BigInteger
     * @return vector of bytes
     */
    to_bytes(): number[];
    /**
     * \brief Get BigInteger from big endian ordered bytes
     * @param buffer
     * @return
     */
    static from_bytes: (buffer: Buffer) => PrivateKey;
    /**
     * \brief Generating PrivateKey
     * @param
     * @return PrivateKey
     */
    static generate(seed?: Buffer): PrivateKey;
}
/**
 * \brief PublicKey class is a base implementation for keeping EC Public Key as an object
 */
declare class PublicKey {
    pubKey: GroupElement;
    constructor(pubKey: GroupElement);
    /**
     * Getting point from this public key
     * @return
     */
    valueOf(): GroupElement;
    to_bytes(): number[];
    static from_bytes(buffer: Buffer): PublicKey;
}
/**
 * \brief Base definition for re-encryption key
 */
declare class ReEncryptionKey {
    _re_key: Scalar;
    _internal_public_key: GroupElement;
    constructor(re_key: Scalar, internal_public_key: GroupElement);
    /**
     * \brief Getting RK number
     * @return
     */
    get_re_key(): Scalar;
    /**
     * Getting RK point
     * @return
     */
    get_internal_public_key(): GroupElement;
    to_bytes(): number[];
    static from_bytes(buffer: Buffer): ReEncryptionKey;
}
/**
 * \brief Key Pair for public and Private Keys
 * This class used as a combination of Public and Private keys, and can do some actions with both of them
 */
declare class KeyPair {
    _private_key: PrivateKey;
    _public_key: PublicKey;
    constructor(prvKey: PrivateKey, pubKey: PublicKey);
    /**
     * \brief Getting public key
     * @return
     */
    get_public_key(): PublicKey;
    /**
     * Getting private key
     * @return
     */
    get_private_key(): PrivateKey;
    /**
     * \brief Generating random KeyPair with their private and public keys
     * This is using Private key generator and getting public key out of generated private key
     * @return
     */
    static generate_key_pair(): KeyPair;
    static from_private_key(private_key: string): KeyPair;
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
declare class Capsule {
    _E: GroupElement;
    _V: GroupElement;
    _S: Scalar;
    _XG?: GroupElement;
    _re_encrypted: boolean;
    constructor(E: GroupElement, V: GroupElement, S: Scalar, XG?: GroupElement, is_re_encrypted?: boolean);
    /**
     * Getting particle E as a POINT_TYPE
     * @return
     */
    get_E(): GroupElement;
    /**
     * Getting particle V as a POINT_TYPE
     * @return
     */
    get_V(): GroupElement;
    /**
     * Getting particle S as a NUMBER_TYPE
     * @return
     */
    get_S(): Scalar;
    /**
     * Getting particle XG
     * @return
     */
    get_XG(): GroupElement | undefined;
    /**
     * \brief Setting capsule as re-encryption capsule
     */
    set_re_encrypted(): void;
    /**
     * \brief Checking if we have re-encryption capsule or not
     * @return
     */
    is_re_encrypted(): boolean;
    to_bytes(): number[];
    static from_bytes(buffer: Buffer): Capsule;
}

/**
 * \brief Proxy base class for handling library crypto operations and main functionality
 * Each initialized Proxy object should contain Context which will define
 * base parameters for crypto operations and configurations
 */
declare class Proxy {
    static generate_key_pair(): KeyPair;
    /**
     * \brief Making capsule out of given PublicKey and given crypto Context and also returning
     * symmetric key wrapped as a string object
     *
     * @param pk "Alice" Public Key
     * @param[out] symmetric_key_out
     * @return Capsule
     */
    static encapsulate: (publicKey: PublicKey) => {
        capsule: Capsule;
        symmetric_key: Scalar;
    };
    /**
     * \brief Decapsulate given capsule with private key,
     * NOTE: Provided private key, should be the original key from which Public Key capsule is created
     * @param capsule
     * @param privateKey
     * @return
     */
    static decapsulate_original: (capsule: Capsule, privateKey: PrivateKey) => Scalar;
    /**
     * \brief Getting re-encryption key out of Private key (Alice) and public key (Bob) using random private key generation
     * @param privateKeyA
     * @param publicKeyB
     * @return
     */
    static generate_re_encryption_key(privateKey: PrivateKey, publicKey: PublicKey): ReEncryptionKey;
    /**
     * \brief Getting re-encryption capsule from given original capsule and re-encryption key
     * @param capsuleOriginal
     * @param reEncryptionKey
     * @return
     */
    static re_encrypt_capsule: (capsule: Capsule, rk: ReEncryptionKey) => Capsule;
    /**
     * \brief Decapsulating given capsule with provided private key
     * @param re_encrypted_capsule
     * @param privateKey
     * @return
     */
    static decapsulate_re_encrypted: (capsule: Capsule, privateKey: PrivateKey) => Scalar;
    static decapsulate(capsule: Capsule, privateKey: PrivateKey): Scalar;
    static private_key_from_bytes: (data: Buffer) => PrivateKey;
    static public_key_from_bytes(data: Buffer): PublicKey;
    static re_encryption_key_from_bytes: (data: Buffer) => ReEncryptionKey;
    static capsule_from_bytes: (data: Buffer) => Capsule;
}

declare function to_hex(byteArray: number[]): string;
declare function from_hex(hexString: string): Buffer;
/**
 * SHA256
 */
declare function SHA256(obj: GroupElement): Scalar;
/**
 * Concat of hashes of GroupElement's
 * @param points
 * @return Scalar
 */
declare function hash_to_scalar(points: GroupElement[]): Scalar;

type EncryptedData = {
    key: string;
    cipher: string;
};
declare function encryptData(publicKey: string, data: string): EncryptedData;
declare function decryptData(privateKey: string, obj: EncryptedData): string;
declare function generateReEncrytionKey(privateKey: string, publicKey: string): string;
declare function reEncryption(Rk: string, obj: EncryptedData): void;

export { Config, Curve, GroupElement, KeyPair, PrivateKey, Proxy, PublicKey, SHA256, Scalar, decryptData, default_curve, encryptData, from_hex, generateReEncrytionKey, hash_to_scalar, reEncryption, to_hex };
