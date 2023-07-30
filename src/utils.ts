import { BN } from 'bn.js';
import { SHA256 as hasher } from 'crypto-js';
import { GroupElement, Scalar } from './Math';

function to_hex(byteArray: number[]) {
    return Array.from(byteArray, (byte) => {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

function from_hex(hexString: string) {
    return Buffer.from(hexString, 'hex');
}

/**
 * SHA256
 */
function SHA256(obj: GroupElement) {
    var hash2 = from_hex(hasher(to_hex(obj.to_bytes())).toString());
    return new Scalar(new BN(hash2));
}

/**
 * Concat of hashes of GroupElement's
 * @param points
 * @return Scalar
 */
function hash_to_scalar(points: GroupElement[]) {
    var points_hash = from_hex(
        hasher(
            to_hex(points[0].to_bytes())
        ).toString()
    );
    var b1 = new BN(points_hash);
    var b2 = new BN(1);
    return new Scalar(b1.add(b2));
}

export { SHA256, from_hex, hash_to_scalar, to_hex };
