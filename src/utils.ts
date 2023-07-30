import { BN } from 'bn.js';
import { sha256 } from 'js-sha256';
import { GroupElement, Scalar } from './Math';

function to_hex(byteArray: number[]) {
    return Array.from(byteArray, (byte) => {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

function from_hex(hexString: string) {
    const result: number[] = [];
    while (hexString.length >= 2) {
        result.push(parseInt(hexString.substring(0, 2), 16));
        hexString = hexString.substring(2, hexString.length);
    }
    return Buffer.from(result);
}

/**
 * SHA256
 */
function SHA256(obj: GroupElement) {
    var hash = sha256.update(to_hex(obj.to_bytes())).digest();
    return new Scalar(new BN(hash));
}

/**
 * Concat of hashes of GroupElement's
 * @param points
 * @return 
 */
function hash_to_scalar(points: GroupElement[]) {
    var hash = sha256.create();
    for (var i = 0; i < points.length; i++) {
        hash.update(to_hex(points[i].to_bytes()));
    }
    var points_hash = hash.digest();
    var b1 = new BN(points_hash);
    var b2 = new BN(1);
    return new Scalar(b1.add(b2));
}


export { SHA256, from_hex, hash_to_scalar, to_hex };
