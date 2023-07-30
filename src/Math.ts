import BN from "bn.js";
import elliptic from 'elliptic';

const secp256k1 = new elliptic.ec('secp256k1');

import { Curve, default_curve } from './Config';


// Scalar.
/// \brief Generic implementation for Scalar
class Scalar {

    _scalar: BN;
    _curve: Curve;

    constructor(bigInt: BN) {
        this._scalar = bigInt;
        this._curve = default_curve();
    }

    curve = () => {
        return this._curve;
    }
    /**
     * valueOf
     */
    valueOf = () => { return this._scalar; }

    /**
     * \brief Getting BIGNUM bytes from existing BigInteger
     * @return vector of bytes
     */
    to_bytes = () => {
        var bytes = this._scalar.toArray();
        if (bytes.length == 33) {
            return bytes.slice(1, 33);
        }
        return bytes;
    }

    add = (sc: Scalar) => { return new Scalar(this.valueOf().add(sc.valueOf())); }
    sub = (sc: Scalar) => { return new Scalar(this.valueOf().sub(sc.valueOf())); }
    mul = (sc: Scalar) => { return new Scalar(this.valueOf().mul(sc.valueOf()).mod(this.curve().order())); }
    eq = (sc: Scalar) => { return this.valueOf().eq(sc.valueOf()); }
    invm = () => { return new Scalar(this.valueOf().invm(this.curve().order())); }


    /**
    * \brief Generate random BigInteger.
    * @return
    */
    static generate_random = function () {
        return new Scalar(default_curve()._curve.genKeyPair().getPrivate())
    }

    /**
     *  get length of BN
     */
    static expected_byte_length = () => {
        return default_curve().order_size();
    }

    /**
     * \brief Get BigInteger from big endian ordered bytes
     * @param buffer
     * @return
     */
    static from_bytes(buffer: Buffer) {
        if (buffer.length != Scalar.expected_byte_length() && buffer.length != 2 * this.expected_byte_length()) {
            throw new Error("Invalid length of data.");
        }
        return new Scalar(new BN(buffer));
    }

}


/**
 * \brief Elliptic curve Point class implementation based elliptic lib
 */
class GroupElement {

    _ec_point: elliptic.curve.base.BasePoint;
    _curve: Curve;

    constructor(point: elliptic.curve.base.BasePoint) {
        this._ec_point = point; // ECPoint
        this._curve = default_curve();
    };

    to_bytes = () => {
        var x = this._ec_point.getX().toArray();
        var y = this._ec_point.getY().toArray();
        return [0x04].concat(x, y);
    }

    valueOf = () => { return this._ec_point; }

    add = (ge: GroupElement) => { return new GroupElement(this.valueOf().add(ge.valueOf())); }
    mul = (sc: Scalar) => { return new GroupElement(this.valueOf().mul(sc.valueOf())); }
    eq = (ge: GroupElement) => { return this.valueOf().eq(ge.valueOf()); }

    static generate_random = () => {
        return new GroupElement(default_curve().generator().mul(Scalar.generate_random().valueOf()));
    }

    static from_bytes = function (buffer: Buffer) {
        var ge_size = GroupElement.expected_byte_length();
        if (buffer.length != ge_size) {
            throw new Error("Invalid length of data.");
        }
        var sc_size = Scalar.expected_byte_length();
        var x = buffer.slice(1, sc_size + 1);
        var y = buffer.slice(sc_size + 1, ge_size);
        return new GroupElement(default_curve()._curve.curve.point(x, y));
    }

    static expected_byte_length = function (is_compressed: boolean = false) {
        if (is_compressed) {
            return 1 + default_curve().order_size();
        }
        else {
            return 1 + 2 * default_curve().order_size();
        }
    }
}


export { GroupElement, Scalar };

