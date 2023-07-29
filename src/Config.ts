import elliptic from 'elliptic';

const secp256k1 = new elliptic.ec('secp256k1');

class Config {

    _curve: Curve;
    _default_curve: Curve;

    constructor() {
        this._default_curve = new Curve();
        this._curve = this._default_curve;
    }
    set_curve = () => {
        this._curve = this._default_curve;
    }
    set_curve_by_default = () => {
        this.set_curve()
    }
    curve = () => {
        return this._curve;
    }
}

function default_curve() {
    var config = new Config();
    config.set_curve_by_default();
    return config.curve();
}

class Curve {

    _curve: elliptic.ec;
    _name: string;
    _order = secp256k1.curve.n;
    _generator = secp256k1.curve.g;
    _order_size = secp256k1.curve.n.byteLength();

    constructor() {
        this._curve = secp256k1;
        this._name = 'secp256k1';
        this._order = secp256k1.curve.n;
        this._generator = secp256k1.curve.g;
        this._order_size = secp256k1.curve.n.byteLength();
    }
    name = () => {
        return this._name;
    }
    order = () => {
        return this._order;
    }
    generator = () => {
        return this._generator;
    }
    order_size = () => {
        return this._order_size;
    }
}

export {
    Config, Curve, default_curve
};
