// deps
import { sha512 } from "@noble/hashes/sha512";
import { sha3_512 } from "@noble/hashes/sha3";
import { randomBytes, timingSafeEqual } from "crypto";
import { mod, hashToPrivateScalar } from "@noble/curves/abstract/modular";
import { numberToBytesBE, bytesToNumberBE } from "@noble/curves/abstract/utils";
import { RistrettoPoint, ed25519 } from "@noble/curves/ed25519";

// keypair generation
function generateKeypair() {
    // generate random scalar for the private key
    const priv = hashToPrivateScalar(randomBytes(48), ed25519.CURVE.n);
    // get the public key
    const pub = RistrettoPoint.BASE.multiply(priv);
    // return
    return { secretKey: numberToBytesBE(priv, 32), publicKey: pub.toRawBytes() };
}

// h function for LSAG
function h(m, L, R) {
    return hashToPrivateScalar(sha3_512(Uint8Array.from([...m, ...L.toRawBytes(), ...R.toRawBytes()])), ed25519.CURVE.n);
}

// ring sig
function sign(msg, secretKey, ring) {
    // if the ring's too small, error
    if (ring.length < 2) throw new Error("Your ring is too small!");
    // turn the secret key into a bigint
    secretKey = bytesToNumberBE(secretKey);
    // turn the ring into a series of points
    ring = ring.map(x => RistrettoPoint.fromHex(Buffer.from(x).toString("hex")));
    // get the index of the key in the ring
    const publicKey = RistrettoPoint.BASE.multiply(secretKey);
    let index = null;
    for (let i = 0; i < ring.length; i++) {
        let equals = timingSafeEqual(publicKey.toRawBytes(), ring[i].toRawBytes()) | 0;
        index |= i & ((equals << 8) | (equals << 7) | (equals << 6) | (equals << 5) | (equals << 4) | (equals << 3) | (equals << 2) | (equals << 1) | equals);
    }
    // if index is null, throw an error
    if (index === null) throw new Error("Your key is not in the ring!");
    // init some arrays and alpha
    let L = new Array(ring.length);
    let R = new Array(ring.length);
    let c = new Array(ring.length);
    let s = new Array(ring.length);
    let alpha = hashToPrivateScalar(randomBytes(48), ed25519.CURVE.n);
    // compute the key image
    const keyImage = RistrettoPoint.hashToCurve(sha512(publicKey.toRawBytes())).multiply(secretKey);
    // compute L_j, R_j, and c_(j+1)
    L[index] = RistrettoPoint.BASE.multiply(alpha);
    R[index] = RistrettoPoint.hashToCurve(sha512(publicKey.toRawBytes())).multiply(alpha);
    c[(index + 1) % ring.length] = h(msg, L[index], R[index]);
    // now move through the whole ring
    for (let i = 1; i < ring.length; i++) {
        // compute current index
        let curIndex = (index + i) % ring.length;
        // find a random s
        s[curIndex] = hashToPrivateScalar(randomBytes(48), ed25519.CURVE.n);
        // compute L
        L[curIndex] = RistrettoPoint.BASE.multiply(s[curIndex]).add(ring[curIndex].multiply(c[curIndex]));
        // compute R
        R[curIndex] = RistrettoPoint.hashToCurve(sha512(ring[curIndex].toRawBytes())).multiply(s[curIndex]).add(keyImage.multiply(c[curIndex]));
        // compute the next c
        c[(curIndex + 1) % ring.length] = h(msg, L[curIndex], R[curIndex]);
    }
    // time to compute s_j
    s[index] = mod(alpha - mod(c[index] * secretKey, ed25519.CURVE.n), ed25519.CURVE.n);
    // now create the signature and return it
    return Uint8Array.from([...keyImage.toRawBytes(), ...numberToBytesBE(c[0], 32), ...s.reduce((acc, cur) => [...acc, ...numberToBytesBE(cur, 32)], [])]);
}

// verify sig
function verify(msg, sig, ring) {
    // turn the ring into a series of points
    ring = ring.map(x => RistrettoPoint.fromHex(Buffer.from(x).toString("hex")));
    // get key image and c_1
    const keyImage = RistrettoPoint.fromHex(Buffer.from(sig.slice(0, 32)).toString("hex"));
    const initialC = bytesToNumberBE(sig.slice(32, 64));
    // arrays!! :D
    let L = new Array(ring.length);
    let R = new Array(ring.length);
    let c = new Array(ring.length);
    let s = new Array(ring.length);
    // get s from the sig
    for (let i = 0; i < ring.length; i++) {
        s[i] = sig.slice(64 + (i * 32), 96 + (i * 32));
    }
    s = s.map(x => bytesToNumberBE(x));
    // compute L, R, and c for each member
    for (let i = 0; i < ring.length; i++) {
        L[i] = RistrettoPoint.BASE.multiply(s[i]).add(ring[i].multiply(i === 0 ? initialC : c[i]));
        R[i] = RistrettoPoint.hashToCurve(sha512(ring[i].toRawBytes())).multiply(s[i]).add(keyImage.multiply(i === 0 ? initialC : c[i]));
        c[(i + 1) % ring.length] = h(msg, L[i], R[i]);
    }
    // check if c[0] is the same as initialC
    return timingSafeEqual(numberToBytesBE(c[0], 32), numberToBytesBE(initialC, 32));
}

// link two sigs
function link(sig1, sig2) {
    return timingSafeEqual(sig1.slice(0, 32), sig2.slice(0, 32));
}

// schnorr sig
function schnorrSign(msg, secretKey) {
    // turn the secret key into a bigint
    secretKey = bytesToNumberBE(secretKey);
    // compute the public key
    const publicKey = RistrettoPoint.BASE.multiply(secretKey)
    // get a random scalar
    const r = hashToPrivateScalar(randomBytes(48), ed25519.CURVE.n);
    // get a ristretto point from the scalar
    const R = RistrettoPoint.BASE.multiply(r);
    // hash the public key, R, and msg
    const h = hashToPrivateScalar(sha512(Uint8Array.from([...R.toRawBytes(), ...publicKey.toRawBytes(), ...msg])), ed25519.CURVE.n);
    // compute s
    const s = mod(r + mod(h * secretKey, ed25519.CURVE.n), ed25519.CURVE.n);
    // output the result
    return Uint8Array.from([...R.toRawBytes(), ...numberToBytesBE(s, 32)]);
}

// schnorr sig verification
function schnorrVerify(msg, sig, publicKey) {
    // convert the public key to a ristretto point
    publicKey = RistrettoPoint.fromHex(Buffer.from(publicKey).toString("hex"));
    // split the sig into R and s
    const R = RistrettoPoint.fromHex(Buffer.from(sig.slice(0, 32)).toString("hex"));
    const s = bytesToNumberBE(sig.slice(32));
    // verify the sig
    const sB = RistrettoPoint.BASE.multiply(s);
    const rhs = R.add(publicKey.multiply(hashToPrivateScalar(sha512(Uint8Array.from([...R.toRawBytes(), ...publicKey.toRawBytes(), ...msg])), ed25519.CURVE.n)));
    return timingSafeEqual(sB.toRawBytes(), rhs.toRawBytes());
}

// ecdh
function ecdh(secretKey, publicKey) {
    return sha512(RistrettoPoint.fromHex(Buffer.from(publicKey)).multiply(bytesToNumberBE(secretKey)).toRawBytes()).slice(0, 32);
}

// public key from secret key
function getPublicKey(secretKey) {
    return RistrettoPoint.BASE.multiply(bytesToNumberBE(secretKey)).toRawBytes();
}

// exports
export default {
    generateKeypair,
    sign,
    verify,
    link,
    schnorrSign,
    schnorrVerify,
    ecdh,
    getPublicKey
};