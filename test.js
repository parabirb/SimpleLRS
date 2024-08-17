// deps
import SimpleLRS from "./index.js";

// as a homage to the first library that got me interested in linkable ring signatures (https://github.com/VictorTaelin/lrs), here's a variation of their example
const alice = SimpleLRS.generateKeypair();
const bob = SimpleLRS.generateKeypair();
const eve = SimpleLRS.generateKeypair();

const ring = [alice, bob, eve].map(x => x.publicKey);

const aliceMessage = new TextEncoder("utf-8").encode("The body is buried in the backyard.");
const aliceSignature = SimpleLRS.sign(aliceMessage, alice.secretKey, ring);

console.log(SimpleLRS.verify(aliceMessage, aliceSignature, ring));

const aliceJk = new TextEncoder("utf-8").encode("Just kidding, he's still alive (for now).");
const aliceJkSignature = SimpleLRS.sign(aliceJk, alice.secretKey, ring);
console.log(SimpleLRS.link(aliceSignature, aliceJkSignature));

// plus a demo of schnorr sigs
const aliceSchnorr = SimpleLRS.schnorrSign(aliceMessage, alice.secretKey);
console.log(SimpleLRS.schnorrVerify(aliceMessage, aliceSchnorr, alice.publicKey));
const bobSchnorr = SimpleLRS.schnorrSign(aliceMessage, bob.secretKey);
console.log(SimpleLRS.schnorrVerify(aliceMessage, bobSchnorr, alice.publicKey));

// and ecdh!
const aliceSecret = SimpleLRS.ecdh(alice.secretKey, eve.publicKey);
const eveSecret = SimpleLRS.ecdh(eve.secretKey, alice.publicKey);
console.log(aliceSecret);
console.log(eveSecret);