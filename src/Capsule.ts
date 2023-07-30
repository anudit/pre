import { GroupElement, Scalar } from "./Math";

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
class Capsule {

    _E: GroupElement;
    _V: GroupElement;
    _S: Scalar;
    _XG?: GroupElement;
    _re_encrypted: boolean;

    constructor(E: GroupElement, V: GroupElement, S: Scalar, XG?: GroupElement, is_re_encrypted: boolean = false) {
        if (typeof is_re_encrypted == "undefined") {
            is_re_encrypted = false;
        }
        this._E = E;  // ECPoint
        this._V = V;  // ECPoint
        this._S = S;  // BN !! GroupElement
        this._XG = XG;// ECPoint 
        this._re_encrypted = is_re_encrypted; //bool
    }
    /**
     * Getting particle E as a POINT_TYPE
     * @return
     */
    get_E() { return this._E; }

    /**
     * Getting particle V as a POINT_TYPE
     * @return
     */
    get_V() { return this._V; }

    /**
     * Getting particle S as a NUMBER_TYPE
     * @return
     */
    get_S() { return this._S; }

    /**
     * Getting particle XG
     * @return
     */
    get_XG() { return this._XG; }

    /**
     * \brief Setting capsule as re-encryption capsule
     */
    set_re_encrypted() { this._re_encrypted = true; }

    /**
     * \brief Checking if we have re-encryption capsule or not
     * @return
     */
    is_re_encrypted() { return this._re_encrypted; }

    to_bytes() {
        var bytearray_E = this.get_E().to_bytes();
        var bytearray_V = this.get_V().to_bytes();
        var bytearray_S = this.get_S().to_bytes();
        var bytearray_XG: number[] = [];
        if (this.is_re_encrypted() && this._XG) {
            bytearray_XG = this._XG.to_bytes();
        }
        return bytearray_E.concat(bytearray_V, bytearray_S, bytearray_XG);
    }

    static from_bytes(buffer: Buffer) {
        var sc_size = Scalar.expected_byte_length();
        var ge_size = GroupElement.expected_byte_length();

        var re_encrypted = false;

        if (buffer.length == 3 * ge_size + sc_size) {
            re_encrypted = true;
        }
        else if (buffer.length != 2 * ge_size + sc_size) {
            throw new Error("Invalid length of data.");
        }

        var E = GroupElement.from_bytes(buffer.subarray(0, ge_size));
        var V = GroupElement.from_bytes(buffer.subarray(ge_size, 2 * ge_size));
        var S = Scalar.from_bytes(buffer.subarray(2 * ge_size, 2 * ge_size + sc_size));
        var XG = undefined;
        if (re_encrypted) {
            XG = GroupElement.from_bytes(buffer.subarray(2 * ge_size + sc_size, 3 * ge_size + sc_size));
        }
        return new Capsule(E, V, S, XG, re_encrypted);

    }
}

export { Capsule };
