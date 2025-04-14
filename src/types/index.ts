// === File: src/types/index.ts ===

// Cryptographic key types using noble-curves format (Uint8Array) and Web Crypto
export type ECDHPublicKey = Uint8Array; // Uncompressed or Compressed Point Bytes
export type ECDHPrivateKey = Uint8Array; // 32-byte scalar
export type ECDSAPublicKey = Uint8Array; // Uncompressed or Compressed Point Bytes
export type ECDSAPrivateKey = Uint8Array; // 32-byte scalar
export type HMACKey = CryptoKey; // Web Crypto API Key Object
export type AESKey = CryptoKey; // Web Crypto API Key Object

// Key pair types
export interface ECKeyPair {
  publicKey: ECDHPublicKey;
  privateKey: ECDHPrivateKey;
}

export interface SigningKeyPair {
  publicKey: ECDSAPublicKey;
  privateKey: ECDSAPrivateKey;
}

// Serialized EC public key format (Using Hex for simplicity)
export type SerializedECPublicKey = string; // Hex representation of public key bytes

// Message types for the Triple Ratchet protocol
export enum MessageType {
  NORMAL = 0,
  PRE_KEY = 1,
}

// A message header contains metadata for a ratchet message
export interface MessageHeader {
  publicKey: ECDHPublicKey; // Sender's ratchet public key (bytes)
  previousCounter: number; // Number of messages in previous sending chain
  messageCounter: number; // Message number in current chain
}

// A ratchet message contains the encrypted data and metadata
export interface RatchetMessage {
  type: MessageType;
  header: MessageHeader;
  ciphertext: ArrayBuffer;
  // For PreKeyMessages only
  identityKey?: ECDHPublicKey; // Sender's long-term identity key (bytes)
  preKeyId?: number;
  signedPreKeyId?: number;
}

// The message keys used for encryption/decryption
export interface MessageKeys {
  encKey: AESKey; // Web Crypto AES Key
  authKey: HMACKey; // Web Crypto HMAC Key
  iv: ArrayBuffer;
}

// A PreKeyBundle is used to establish initial communication
export interface PreKeyBundle {
  identityId: number;
  identityKey: ECDHPublicKey; // bytes
  signedPreKeyId: number;
  signedPreKey: ECDHPublicKey; // bytes
  signedPreKeySignature: Uint8Array; // Signature bytes
  preKeyId: number;
  preKey: ECDHPublicKey; // bytes
  signingKey: ECDSAPublicKey; // Public signing key of the bundle owner (bytes)
}

// --- State Types for Functional Approach ---

/**
 * State for a symmetric key ratchet chain (sending or receiving)
 */
export interface RatchetChainState {
  chainKey: HMACKey; // Web Crypto Key
  chainIndex: number;
  skippedMessageKeys: Map<number, MessageKeys>; // Stores keys for out-of-order messages
}

/**
 * Represents the complete state of a Triple Ratchet session for one party
 */
export interface RatchetState {
  // Own identity info (simplified for this example)
  identityPrivateKey: ECDHPrivateKey; // bytes
  identityPublicKey: ECDHPublicKey; // bytes

  // Remote party's identity info
  remoteIdentityKey: ECDHPublicKey; // bytes
  remoteSigningKey: ECDSAPublicKey; // bytes

  // Core Ratchet State
  rootKey: HMACKey; // Web Crypto Key
  ourRatchetKeyPair: ECKeyPair; // Our current ephemeral DH key pair (bytes)
  theirRatchetKey: ECDHPublicKey | null; // Their current ephemeral DH public key (bytes)

  // Triple Ratchet Enhancement
  // This now holds the actual enhanced private key scalar bytes x_t' = x_t * H(I_t) mod q
  ourEnhancedPrivateKey: ECDHPrivateKey; // bytes

  // Symmetric Key Ratchet Chains
  sendingChain: RatchetChainState | null;
  receivingChain: RatchetChainState | null;

  // Counters
  sendMsgCounter: number; // Messages sent in the current sending chain
  recvMsgCounter: number; // Messages received in the current receiving chain (Note: might not be needed if using chainIndex)
  prevSendMsgCounter: number; // Number of messages sent in the *previous* sending chain

  // Storage for message keys skipped during DH ratchet steps
  // Key: Hex(remote public key) + message counter
  skippedRatchetKeys: Map<string, MessageKeys>;
}

/**
 * Represents the state of a user's identity keys (simplified)
 */
export interface IdentityState {
  id: number;
  signingKeyPair: SigningKeyPair; // bytes
  dhKeyPair: ECKeyPair; // bytes
  // Add maps for preKeys (ECKeyPair), signedPreKeys (ECKeyPair), signatures (Map<number, Uint8Array>) etc.
  preKeys: Map<number, ECKeyPair>;
  signedPreKeys: Map<number, ECKeyPair>;
  signedPreKeySignatures: Map<number, Uint8Array>;
}
