import BN from "bn.js";

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
    static generate_random = function (curve: Curve) {
        if (typeof curve == "undefined") {
            curve = default_curve();
        }
        return new Scalar(curve._curve.genKeyPair().getPrivate())
    }

    /**
     * \brief Get BigInteger from big endian ordered bytes
     * @param buffer
     * @return
     */
    static from_bytes = function (buffer: Buffer) {
        if (buffer.length != Scalar.expected_byte_length() && buffer.length != 2 * this.expected_byte_length()) {
            throw new Error("Invalid length of data.");
        }
        return new Scalar(new BN(buffer));
    }

    /**
     *  get length of BN
     */
    static expected_byte_length = () => {
        return default_curve().order_size();
    }
}

export { Scalar };
