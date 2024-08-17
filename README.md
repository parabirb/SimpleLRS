# SimpleLRS
A simple, public domain JavaScript implementation of [an efficient linkable ring signature algorithm](https://bitcointalk.org/index.php?topic=972541.msg10619684#msg10619684) (specifically, a variation of LSAG) using [noble](https://github.com/paulmillr/noble-curves)'s implementation of Ristretto255. For a more readable description of the ring signature algorithm, See Section 2.1 of [this preprint](https://eprint.iacr.org/2015/1098.pdf) in the IACR archive.

**NOTE: Do NOT use this in critical applications. This library has NOT been audited, and implements an algorithm literally described in a Bitcoin forum. Consider this a toy library.**

Limitations:
* Rings cannot have more than 256 members.
* No input checking is done; note that a signature should be 64+32n bytes long, where n is the number of people in the ring.
* The algorithm is weakly linkable; if a user in two rings signs a message in each, the two signatures cannot be linked.

For your convenience, SimpleLRS also includes Schnorr signatures (non-ring) and ECDH over Ristretto255.

## Usage
SimpleLRS provides 7 simple functions:
- `generateKeypair(): { secretKey: Uint8Array(32), publicKey: Uint8Array(32) }`: Generates a Ristretto255 keypair for use with SimpleLRS.
- `sign(msg: Uint8Array, secretKey: Uint8Array(32), ring: Uint8Array(32)[]): Uint8Array`: Generates a linkable ring signature with a message, secret key, and ring of public keys. Note that the order of the ring array is important, the ring must include at least 2 members, and your public key must be in the ring. Returns a Uint8Array of length 64+32*ring.length.
- `verify(msg: Uint8Array, sig: Uint8Array, ring: Uint8Array(32)[]): boolean`: Verifies a ring signature. Returns either true or false.
- `link(sig1: Uint8Array, sig2: Uint8Array): boolean`: Checks the key image of both signatures and returns true if the signatures are linked. Note that for signatures to be linked, they must be signed in the same ring. This method **DOES NOT** verify the signatures; you need to use the `verify` method first before checking with `link`.
- `schnorrSign(msg: Uint8Array, secretKey: Uint8Array(32)): Uint8Array(64)`: Creates a 64-byte Schnorr signature for the message with your secret key.
- `schnorrVerify(msg: Uint8Array, sig: Uint8Array(64), publicKey: Uint8Array(32)): boolean`: Checks a Schnorr signature against the public key. Returnns true if the signature is valid, and false if it isn't.
- `ecdh(secretKey: Uint8Array(32), publicKey: Uint8Array(32))`: Performs ECDH and returns a shared secret. No further processing of the output is required, as this method does it for you.
- `getPublicKey(secretKey: Uint8Array(32)): Uint8Array(32)`: Returns the public key for a given secret key.

## Example
An example is provided in `test.js`.