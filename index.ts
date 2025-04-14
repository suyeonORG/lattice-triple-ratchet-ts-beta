/**
 * Triple Ratchet - Main exports
 */

// Export types
export * from "./types";

// Export core protocol implementation
export { TripleRatchet } from "./protocol/triple-ratchet";
export { Identity } from "./protocol/identity";

// Export crypto utilities
export { CryptoUtils } from "./crypto/crypto-utils";
export { BufferUtils } from "./utils/buffer";

// Export protocol components
export { ChainKey } from "./protocol/chain-key";
export { SymmetricRatchet } from "./protocol/symmetric-ratchet";

/**
 * Example usage of the Triple Ratchet
 */
export async function example() {
  // Import required classes
  const { Identity, TripleRatchet } = await import("./index");

  // Create identities for Alice and Bob
  const alice = await Identity.create(1);
  const bob = await Identity.create(2);

  // Bob creates a PreKeyBundle
  const bobBundle = await bob.createPreKeyBundle(0, 0);

  // Alice initiates a session with Bob using his bundle
  const aliceSession = await TripleRatchet.initFromPreKeyBundle(
    alice,
    bobBundle
  );

  // Alice encrypts a message to Bob
  const message = new TextEncoder().encode("Hello, Bob!");
  const encryptedMessage = await aliceSession.encrypt(message.buffer);

  // Bob processes the PreKey message to initialize his session
  const bobSession = await TripleRatchet.initFromPreKeyMessage(
    bob,
    encryptedMessage,
    0,
    0
  );

  // Bob decrypts the message
  const decryptedBuffer = await bobSession.decrypt(encryptedMessage);
  const decryptedMessage = new TextDecoder().decode(decryptedBuffer);

  console.log(decryptedMessage); // "Hello, Bob!"

  // Now Bob can send messages back to Alice
  const response = new TextEncoder().encode("Hi Alice, got your message!");
  const encryptedResponse = await bobSession.encrypt(response.buffer);

  // Alice can decrypt Bob's response
  const decryptedResponse = await aliceSession.decrypt(encryptedResponse);
  console.log(new TextDecoder().decode(decryptedResponse)); // "Hi Alice, got your message!"
}
