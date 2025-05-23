// === File: src/protocol/ratchet-logic.ts ===

import { p256 } from "@noble/curves/p256"; // For P256_ORDER and utils
import { sha256 } from "@noble/hashes/sha256"; // For hashing in enhancement
import { bytesToHex, hexToBytes } from "@noble/hashes/utils"; // Import hexToBytes

import {
  INFO_RATCHET,
  MAX_SKIP,
  P256_ORDER, // Import curve order
  HMAC_ALGORITHM, // Added import
} from "../constants";
// Import generateSigningKeyPair
import {
  generateECDHKeyPair,
  generateSigningKeyPair, // Added import
  computeDH,
  hkdfDerive,
  importHmacKey,
  importAesKey,
  encryptAES,
  decryptAES,
  exportRawKey,
  equalPublicKeys,
  verifySignature,
  hashData,
  signData,
} from "../crypto/crypto-utils";
import {
  concatBuffers,
  equalBuffers, // For general buffer comparison if needed
  stringToBytes,
  bytesToString,
} from "../utils/buffer";
import { getCrypto } from "../utils/environment"; // Added import

// Import MessageType as a value, not just a type
import {
  MessageType, // Changed from 'import type'
  type RatchetState, // Keep others as type imports if only used as types
  type RatchetChainState,
  type IdentityState,
  type MessageKeys,
  type HMACKey, // Web Crypto type
  type AESKey, // Web Crypto type
  type RatchetMessage,
  type MessageHeader,
  type PreKeyBundle,
  type ECKeyPair, // Uses Uint8Array keys now
  type ECDHPrivateKey, // Uint8Array
  type ECDHPublicKey, // Uint8Array
} from "../types";

// --- Helper Functions ---

/**
 * Converts a BigInt to a 32-byte Uint8Array (big-endian).
 * Pads with leading zeros if necessary. Truncates if necessary (unlikely for curve scalars).
 * @param num The BigInt to convert.
 * @returns A 32-byte Uint8Array.
 */
function bigIntTo32Bytes(num: bigint): Uint8Array {
  let hex = num.toString(16);
  // Ensure even length for hex bytes
  if (hex.length % 2) {
    hex = "0" + hex;
  }
  // Ensure 64 hex characters (32 bytes) by padding with leading zeros
  // Truncate *before* padding if hex is too long (e.g., from negative modulo)
  if (hex.length > 64) {
    console.warn(
      `BigInt hex representation ${hex} is longer than 32 bytes, taking last 64 chars.`
    );
    hex = hex.slice(-64);
  }
  hex = hex.padStart(64, "0");

  return hexToBytes(hex);
}

/**
 * Converts a Uint8Array to a BigInt. Assumes big-endian format.
 * @param bytes The input bytes.
 * @returns The corresponding BigInt.
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = bytesToHex(bytes); // Use imported bytesToHex
  if (hex.length % 2) {
    hex = "0" + hex;
  }
  // Handle empty string case
  if (hex === "") {
    return 0n;
  }
  return BigInt("0x" + hex);
}

// --- Symmetric Key Ratchet (Chain Key) Logic ---

/**
 * Derives message keys (AES encryption key, HMAC auth key, IV) from a chain key state.
 * Uses Web Crypto keys. Does not advance the chain state itself.
 * @param chainKey The current HMAC chain key (CryptoKey).
 * @returns A Promise resolving to the MessageKeys.
 */
async function deriveMessageKeysFromChainKey(
  chainKey: HMACKey
): Promise<MessageKeys> {
  const crypto = getCrypto();
  const messageKeyInput = stringToBytes("MessageKey"); // Constant input for message key derivation

  // Use HMAC-SHA256 with the chain key to derive the input for HKDF
  const derivedCombinedKeyMaterial = await crypto.subtle.sign(
    HMAC_ALGORITHM,
    chainKey,
    messageKeyInput
  );

  // Use HKDF to derive the actual encryption and authentication keys + IV
  // Using a fixed salt (null) and info specific to this derivation step
  const keys = await hkdfDerive(
    derivedCombinedKeyMaterial,
    null, // Salt (optional, could use a fixed one)
    INFO_RATCHET, // Context info
    3, // Derive 3 keys: AES key, Auth key, IV base
    32 // Each key material is 32 bytes
  );
  const rawEnc = new Uint8Array(keys[0]);
  const rawAuth = new Uint8Array(keys[1]);
  const rawIvMat = new Uint8Array(keys[2]);
  console.log("🔑 [HKDF] rawEncKey: ", bytesToHex(rawEnc));
  console.log("🔑 [HKDF] rawAuthKey:", bytesToHex(rawAuth));
  console.log(
    "🔑 [HKDF] rawIvMat (first 12 bytes):",
    bytesToHex(rawIvMat.slice(0, 12))
  );

  const iv = rawIvMat.subarray(0, 12); // always a Uint8Array // Use first 12 bytes of the third derived key as IV
  console.log("🔑 [Encrypt] rawEncKey:", bytesToHex(new Uint8Array(keys[0])));
  console.log("🔑 [Encrypt] rawAuthKey:", bytesToHex(new Uint8Array(keys[1])));
  console.log(
    "🔑 [Encrypt] rawIv:",
    bytesToHex(new Uint8Array(keys[2]).slice(0, 12))
  );
  return {
    encKey: await importAesKey(keys[0]), // Import raw bytes as AES key
    authKey: await importHmacKey(keys[1]), // Import raw bytes as HMAC key
    iv: iv,
  };
}

/**
 * Advances a chain key state to the next key in the sequence.
 * Uses Web Crypto keys.
 * @param chainKey The current HMAC chain key (CryptoKey).
 * @returns A Promise resolving to the next HMAC chain key (CryptoKey).
 */
async function advanceChainKey(chainKey: HMACKey): Promise<HMACKey> {
  const crypto = getCrypto();
  const nextKeyInput = stringToBytes("NextChainKey"); // Constant input for next chain key derivation

  // Use HMAC-SHA256 with the current chain key to derive the next chain key material
  const nextKeyMaterial = await crypto.subtle.sign(
    HMAC_ALGORITHM,
    chainKey,
    nextKeyInput
  );

  // Import the derived material as the new HMAC chain key
  return importHmacKey(nextKeyMaterial);
}

/**
 * Gets a message key from a symmetric ratchet chain state for a specific counter.
 * Advances the chain state past the requested counter and stores skipped keys.
 * @param chainState The current state of the symmetric ratchet chain.
 * @param counter The desired message counter index.
 * @returns A Promise resolving to an object containing the MessageKeys and the updated RatchetChainState.
 */
export async function getSymRatchetMessageKey(
  chainState: RatchetChainState,
  counter: number
): Promise<{ messageKeys: MessageKeys; nextChainState: RatchetChainState }> {
  let currentChainKey = chainState.chainKey;
  let currentIndex = chainState.chainIndex;
  const newSkippedKeys = new Map(chainState.skippedMessageKeys); // Copy skipped keys

  // Check if the requested key is already skipped
  if (newSkippedKeys.has(counter)) {
    const messageKeys = newSkippedKeys.get(counter)!;
    newSkippedKeys.delete(counter); // Consume the skipped key
    console.log(
      `Used skipped message key for index ${counter}. Remaining skipped: ${newSkippedKeys.size}`
    );
    return {
      messageKeys,
      nextChainState: { ...chainState, skippedMessageKeys: newSkippedKeys },
    };
  }

  // Check if the requested counter is in the past (and not skipped)
  if (counter < currentIndex) {
    throw new Error(
      `Message key for past counter ${counter} not found (current index: ${currentIndex})`
    );
  }

  // Check if too many messages would need to be skipped
  if (counter - currentIndex > MAX_SKIP) {
    throw new Error(
      `Skipping too many messages (${counter - currentIndex}, max: ${MAX_SKIP})`
    );
  }

  // Advance the chain until the desired counter is reached
  while (currentIndex < counter) {
    console.log(`Skipping message key for index ${currentIndex}`);
    const messageKeys = await deriveMessageKeysFromChainKey(currentChainKey);
    newSkippedKeys.set(currentIndex, messageKeys); // Store the skipped key
    currentChainKey = await advanceChainKey(currentChainKey); // Advance the chain key
    currentIndex++;

    // Optional: Prune very old skipped keys if the map grows too large
    if (newSkippedKeys.size > MAX_SKIP * 2) {
      // Example pruning strategy
      const oldestKeyIndex = Math.min(...newSkippedKeys.keys());
      if (currentIndex - oldestKeyIndex > MAX_SKIP * 2) {
        newSkippedKeys.delete(oldestKeyIndex);
        console.warn(`Pruned old skipped key for index ${oldestKeyIndex}`);
      }
    }
  }

  // Derive the keys for the requested counter
  const requestedMessageKeys = await deriveMessageKeysFromChainKey(
    currentChainKey
  );
  // Advance the chain key one more time for the next state
  const nextChainKey = await advanceChainKey(currentChainKey);
  const nextIndex = currentIndex + 1;

  // Create the next chain state
  const nextState: RatchetChainState = {
    chainKey: nextChainKey,
    chainIndex: nextIndex,
    skippedMessageKeys: newSkippedKeys,
  };

  return { messageKeys: requestedMessageKeys, nextChainState: nextState };
}

// --- Diffie-Hellman (DH) Ratchet Logic ---

/**
 * Performs the DH ratchet step calculation using Web Crypto HKDF.
 * Derives a new root key and a new chain key from the DH result and the current root key.
 * @param rootKey The current root key (HMACKey - CryptoKey).
 * @param dhOutput The result of the ECDH computation (Uint8Array).
 * @returns A Promise resolving to { newRootKey: HMACKey, newChainKey: HMACKey }.
 */
async function performDHRatchetStep(
  rootKey: HMACKey,
  dhOutput: Uint8Array
): Promise<{ newRootKey: HMACKey; newChainKey: HMACKey }> {
  // Export the current root key to use as salt in HKDF
  const rootKeyRaw = await exportRawKey(rootKey);

  // Derive two new 32-byte keys using HKDF
  // Input: DH output
  // Salt: Current root key raw bytes
  // Info: Constant ratchet info
  const derivedKeys = await hkdfDerive(dhOutput, rootKeyRaw, INFO_RATCHET, 2);

  // Import the derived raw bytes as new CryptoKeys
  const newRootKey = await importHmacKey(derivedKeys[0]);
  const newChainKey = await importHmacKey(derivedKeys[1]); // This becomes the key for the *receiving* chain after a DH step

  return { newRootKey, newChainKey };
}

// --- Triple Ratchet Enhancement ---

/**
 * Calculates the "enhanced" private key for the Triple Ratchet: x_t' = (x_t * H(I_t)) mod n
 * Uses noble-curves for modular arithmetic.
 * @param privateKeyBytes The original private key scalar bytes (x_t).
 * @param sharedSecret The shared secret derived via DH (I_t) (Uint8Array).
 * @returns The enhanced private key bytes (x_t'). Note: This is now synchronous.
 */
function calculateEnhancedPrivateKey(
  privateKeyBytes: ECDHPrivateKey,
  sharedSecret: Uint8Array // I_t
): ECDHPrivateKey {
  // 1. Hash the shared secret: H(I_t)
  const hashedSecretBytes = sha256(sharedSecret); // Use noble sha256 (synchronous)

  // 2. Convert private key and hash to BigInt scalars
  const privateScalar = bytesToBigInt(privateKeyBytes);
  const hashScalar = bytesToBigInt(hashedSecretBytes);

  // 3. Perform modular multiplication: (x_t * H(I_t)) mod n
  // Use BigInt modulo operator as p256.utils.mod was causing issues
  let enhancedScalar = (privateScalar * hashScalar) % P256_ORDER;
  // Ensure result is positive (BigInt % can return negative)
  if (enhancedScalar < 0n) {
    enhancedScalar += P256_ORDER;
  }

  // 4. Convert the resulting BigInt scalar back to 32 bytes
  // Use helper function as p256.utils.scalarToBytes was causing issues
  const enhancedPrivateKeyBytes = bigIntTo32Bytes(enhancedScalar);

  console.log("Triple Ratchet: Enhanced private key calculated.");
  return enhancedPrivateKeyBytes;
}

// --- Ratchet Initialization Logic ---

/**
 * Initializes the RatchetState for the initiator using the recipient's PreKeyBundle.
 * Uses noble-curves for EC operations.
 * @param ownIdentityState Our identity information.
 * @param preKeyBundle The recipient's PreKeyBundle.
 * @returns A Promise resolving to the initial RatchetState for the initiator.
 */
export async function initializeRatchetInitiator(
  ownIdentityState: IdentityState,
  preKeyBundle: PreKeyBundle
): Promise<RatchetState> {
  // 1. Verify the signed prekey signature
  const isSignatureValid = await verifySignature(
    preKeyBundle.signingKey, // Bob's public signing key
    preKeyBundle.signedPreKeySignature, // The signature Bob provided
    preKeyBundle.signedPreKey // The public key that was signed
  );
  if (!isSignatureValid) {
    throw new Error("Invalid signature on signed prekey in PreKeyBundle.");
  }
  console.log("Signed pre-key signature verified.");

  // 2. Generate our ephemeral key pair for this session (EKa)
  const ephemeralKeyPair = generateECDHKeyPair();
  console.log("Generated ephemeral key pair for X3DH & initial ratchet.");

  // 3. Perform X3DH calculations (Alice's perspective)
  // DH1: Alice's Identity Private Key (IKa) <-> Bob's Signed PreKey Public Key (SPKb)
  const dh1 = computeDH(
    ownIdentityState.dhKeyPair.privateKey,
    preKeyBundle.signedPreKey
  );
  // DH2: Alice's Ephemeral Private Key (EKa) <-> Bob's Identity Public Key (IKb)
  const dh2 = computeDH(ephemeralKeyPair.privateKey, preKeyBundle.identityKey);
  // DH3: Alice's Ephemeral Private Key (EKa) <-> Bob's Signed PreKey Public Key (SPKb)
  const dh3 = computeDH(ephemeralKeyPair.privateKey, preKeyBundle.signedPreKey);
  // DH4: Alice's Ephemeral Private Key (EKa) <-> Bob's One-Time PreKey Public Key (OPKb)
  const dh4 = computeDH(ephemeralKeyPair.privateKey, preKeyBundle.preKey);
  console.log("Performed X3DH calculations.");

  // 4. Combine DH outputs -> Shared Secret (SK)
  // Concatenate in a defined order (e.g., FFFFFF || DH1 || DH2 || DH3 || DH4)
  // Using a simpler concatenation for this example: DH1 || DH2 || DH3 || DH4
  const sharedSecretInput = concatBuffers(dh1, dh2, dh3, dh4);

  // 5. Derive initial Root Key from SK using HKDF
  // Use SK as IKM, no salt, standard info
  const initialKeys = await hkdfDerive(
    sharedSecretInput,
    null, // No salt for initial derivation from SK
    INFO_RATCHET,
    1 // Derive 1 key (the root key)
  );
  const initialRootKey = await importHmacKey(initialKeys[0]);
  console.log("Derived initial root key.");

  // 6. Use the X3DH ephemeral as our initial ratchet key (RKa_0)
  const initialRatchetKeyPair = ephemeralKeyPair;
  console.log("Generated initial sending ratchet key pair.");

  // 7. Initial "enhanced" private key is just x_0' = x_0 (no mini‑ratchet yet)
  const initialEnhancedPrivateKey = ephemeralKeyPair.privateKey;

  // 8. Initial State Setup for Alice (Initiator)
  const initialState: RatchetState = {
    identityPrivateKey: ownIdentityState.dhKeyPair.privateKey,
    identityPublicKey: ownIdentityState.dhKeyPair.publicKey,
    remoteIdentityKey: preKeyBundle.identityKey, // Bob's Identity Key
    remoteSigningKey: preKeyBundle.signingKey, // Bob's Signing Key
    rootKey: initialRootKey,
    ourRatchetKeyPair: initialRatchetKeyPair, // Alice's first ratchet key (EKa)
    theirRatchetKey: preKeyBundle.signedPreKey, // Alice assumes Bob's first key is SPKb initially ??? Should this be null until first message? X3DH implies SPKb is used in initial calculation, but Bob's first *ratchet* key RKb_0 is unknown. Let's set to null.
    // theirRatchetKey: null, // Bob's ratchet key is unknown until his first message
    ourEnhancedPrivateKey: initialEnhancedPrivateKey, // x'_0
    sendingChain: null, // Will be created on first send
    receivingChain: null, // Will be created on first receive
    sendMsgCounter: 0,
    recvMsgCounter: 0, // Not strictly needed, chainIndex tracks progress
    prevSendMsgCounter: 0,
    skippedRatchetKeys: new Map(),
  };

  // Correction: In X3DH, the initial symmetric key is derived, but the Double Ratchet
  // part starts *after* this. Alice needs Bob's SignedPreKey to calculate SK,
  // but Bob's first *ratchet* key (RKb_0) is sent in his first reply message.
  // However, Alice needs *something* to perform the first DH ratchet step *with* when she sends
  // her first message. Signal protocol uses Bob's Signed PreKey (SPKb) as the initial `theirRatchetKey`
  // for Alice. Let's stick with that.
  initialState.theirRatchetKey = preKeyBundle.signedPreKey;

  console.log("Initiator state initialized.");
  return initialState;
}

/**
 * Initializes the RatchetState for the receiver using the first PreKey message.
 * Uses noble-curves for EC operations.
 * @param ownIdentityState Our identity information (needs pre-keys).
 * @param preKeyMessage The received PreKey message.
 * @returns A Promise resolving to the initial RatchetState for the receiver.
 */
export async function initializeRatchetReceiver(
  ownIdentityState: IdentityState,
  preKeyMessage: RatchetMessage
): Promise<RatchetState> {
  console.log("Initializing receiver state from PreKey message.");
  // 1. Validate PreKey message structure
  if (
    // Use MessageType enum value
    preKeyMessage.type !== MessageType.PRE_KEY ||
    !preKeyMessage.identityKey || // Alice's IKa pub
    !preKeyMessage.header.publicKey || // Alice's EKa pub
    preKeyMessage.preKeyId === undefined || // ID of OPKb used by Alice
    preKeyMessage.signedPreKeyId === undefined // ID of SPKb used by Alice
  ) {
    throw new Error("Invalid PreKey message structure for initialization.");
  }
  console.log("PreKey message structure validated.");

  // 2. Retrieve our necessary private keys (Bob's perspective)
  // Need SPKb priv and OPKb priv based on IDs in message
  const ownSignedPreKeyPair = await getSignedPreKeyPair(
    ownIdentityState, // Bob's identity state
    preKeyMessage.signedPreKeyId // The ID of the SPKb Alice used
  );
  const ownPreKeyPair = await getOneTimePreKeyPair(
    ownIdentityState, // Bob's identity state
    preKeyMessage.preKeyId // The ID of the OPKb Alice used
  );
  if (!ownSignedPreKeyPair || !ownPreKeyPair) {
    throw new Error(
      `Required pre-key (ID ${preKeyMessage.preKeyId}) or signed pre-key (ID ${preKeyMessage.signedPreKeyId}) not found.`
    );
  }
  console.log("Retrieved own pre-keys for X3DH.");

  // 3. Perform X3DH calculations (Bob's perspective)
  // DH1: Bob's Signed PreKey Private Key (SPKb) <-> Alice's Identity Public Key (IKa)
  const dh1 = computeDH(
    ownSignedPreKeyPair.privateKey,
    preKeyMessage.identityKey
  );
  // DH2: Bob's Identity Private Key (IKb) <-> Alice's Ephemeral Public Key (EKa)
  const dh2 = computeDH(
    ownIdentityState.dhKeyPair.privateKey,
    preKeyMessage.header.publicKey
  );
  // DH3: Bob's Signed PreKey Private Key (SPKb) <-> Alice's Ephemeral Public Key (EKa)
  const dh3 = computeDH(
    ownSignedPreKeyPair.privateKey,
    preKeyMessage.header.publicKey
  );
  // DH4: Bob's One-Time PreKey Private Key (OPKb) <-> Alice's Ephemeral Public Key (EKa)
  const dh4 = computeDH(
    ownPreKeyPair.privateKey,
    preKeyMessage.header.publicKey
  );
  console.log("Performed X3DH calculations.");

  // 4. Combine DH outputs -> Shared Secret (SK) - Must match Alice's calculation
  const sharedSecretInput = concatBuffers(dh1, dh2, dh3, dh4);

  // 5. Derive initial Root Key from SK
  const initialKeys = await hkdfDerive(
    sharedSecretInput,
    null,
    INFO_RATCHET,
    1
  );
  const initialRootKey = await importHmacKey(initialKeys[0]);
  console.log("Derived initial root key.");

  // 6. Alice's ephemeral key (EKa pub) is our first "theirRatchetKey"
  const initialTheirRatchetKey = preKeyMessage.header.publicKey;

  // 7. Generate our first ratchet key pair (RKb_0)
  const initialRatchetKeyPair = ownSignedPreKeyPair;
  console.log("Generated initial receiving ratchet key pair.");

  // 8. Initial "enhanced" private key is just the normal private key (y'_0 = y_0)
  const initialEnhancedPrivateKey = initialRatchetKeyPair.privateKey;

  // 9. Initial State Setup for Bob (Receiver)
  // Bob needs Alice's signing key to verify future messages.
  // This should ideally be part of the PreKey message or fetched separately.
  // Assuming Alice's IKa *is* her signing key for simplicity here.
  const remoteSigningKey = preKeyMessage.identityKey; // Placeholder assumption

  const initialState: RatchetState = {
    identityPrivateKey: ownIdentityState.dhKeyPair.privateKey, // Bob's IKb priv
    identityPublicKey: ownIdentityState.dhKeyPair.publicKey, // Bob's IKb pub
    remoteIdentityKey: preKeyMessage.identityKey, // Alice's IKa pub
    remoteSigningKey: remoteSigningKey, // Alice's Signing Key pub (placeholder)
    rootKey: initialRootKey,
    ourRatchetKeyPair: initialRatchetKeyPair, // Bob's first ratchet key (RKb_0)
    theirRatchetKey: initialTheirRatchetKey, // Alice's first ratchet key (RKa_0 pub)
    ourEnhancedPrivateKey: initialEnhancedPrivateKey, // y'_0
    sendingChain: null, // Will be created by first send
    receivingChain: null, // Will be created by first decrypt call
    sendMsgCounter: 0,
    recvMsgCounter: 0,
    prevSendMsgCounter: 0,
    skippedRatchetKeys: new Map(),
  };
  console.log("Receiver state initialized.");
  return initialState;
}

// --- Encryption Logic ---

/**
 * Encrypts a plaintext message using the current RatchetState.
 * Handles DH ratchet updates and Triple Ratchet enhancement.
 * @param currentState The current RatchetState.
 * @param plaintext The plaintext ArrayBuffer to encrypt.
 * @returns A Promise resolving to { message: RatchetMessage, nextState: RatchetState }.
 */
export async function ratchetEncrypt(
  currentState: RatchetState,
  plaintext: ArrayBuffer
): Promise<{ message: RatchetMessage; nextState: RatchetState }> {
  let nextState = { ...currentState }; // Copy state to modify
  let sendingChain = nextState.sendingChain;
  let currentRatchetKeyPair = nextState.ourRatchetKeyPair; // Key pair used for DH/header

  // Prepare holders for the “next” ratchet key & enhanced private key
  let nextRatchetKeyPair: ECKeyPair | null = null;
  let nextEnhancedPrivateKey: ECDHPrivateKey | null = null;

  // --- DH Ratchet Step (if sendingChain is null) ---
  if (!sendingChain) {
    console.log("Performing DH ratchet step before sending.");
    if (!nextState.theirRatchetKey) {
      throw new Error("Cannot encrypt: Remote ratchet key not established.");
    }

    // 1) compute DH output using the *old* enhanced private key
    const dhOutput = computeDH(
      nextState.ourEnhancedPrivateKey,
      nextState.theirRatchetKey
    );
    console.log("Calculated DH output for new chain.");

    // 2) derive new root & chain keys
    const { newRootKey, newChainKey } = await performDHRatchetStep(
      nextState.rootKey,
      dhOutput
    );
    console.log("Derived new root key and sending chain key.");

    // 3) initialize the new sending chain
    sendingChain = {
      chainKey: newChainKey,
      chainIndex: 0,
      skippedMessageKeys: new Map(),
    };
    nextState.rootKey = newRootKey;
    nextState.sendingChain = sendingChain;
    nextState.sendMsgCounter = 0;
    nextState.prevSendMsgCounter = currentState.sendMsgCounter;

    // 4) generate *next* ratchet key pair but do NOT apply it yet
    nextRatchetKeyPair = generateECDHKeyPair();
    console.log("Generated next ratchet key pair.");

    // 5) calculate the *next* enhanced private key
    nextEnhancedPrivateKey = calculateEnhancedPrivateKey(
      nextRatchetKeyPair.privateKey,
      dhOutput
    );
    console.log("Calculated next enhanced private key.");

    // 6) ensure the header for this message still uses the old pair
    currentRatchetKeyPair = currentState.ourRatchetKeyPair;
  }

  // --- Symmetric Ratchet Step ---
  if (!sendingChain) {
    throw new Error(
      "Internal error: Sending chain not available after DH check."
    );
  }

  const currentSendCounter = nextState.sendMsgCounter;
  console.log(`Encrypting message ${currentSendCounter} in current chain.`);
  const { messageKeys, nextChainState: updatedSendingChain } =
    await getSymRatchetMessageKey(sendingChain, currentSendCounter);
  nextState.sendingChain = updatedSendingChain;
  nextState.sendMsgCounter = currentSendCounter + 1;

  // --- AES‐GCM Encryption ---
  const headerPublicKey = currentRatchetKeyPair.publicKey;
  const adObject = {
    pk: bytesToHex(headerPublicKey),
    pn: nextState.prevSendMsgCounter,
    n: currentSendCounter,
  };
  const aadBuffer = stringToBytes(JSON.stringify(adObject));

  console.log("Encrypting plaintext with AES-GCM.");
  const rawEncKey = new Uint8Array(await exportRawKey(messageKeys.encKey));
  console.log("🔑 [Encrypt] encKey:", bytesToHex(rawEncKey));
  console.log("🔑 [Encrypt] iv:", bytesToHex(new Uint8Array(messageKeys.iv)));
  console.log("🔑 [Encrypt] aad:", new TextDecoder().decode(aadBuffer));
  const ciphertext = await encryptAES(
    messageKeys.encKey,
    plaintext,
    messageKeys.iv,
    aadBuffer
  );

  // --- Construct RatchetMessage ---
  const header: MessageHeader = {
    publicKey: headerPublicKey,
    previousCounter: nextState.prevSendMsgCounter,
    messageCounter: currentSendCounter,
  };

  const isInitialMessage =
    currentState.sendMsgCounter === 0 &&
    currentState.prevSendMsgCounter === 0 &&
    !currentState.receivingChain &&
    currentState.theirRatchetKey !== null;

  const message: RatchetMessage = {
    type: isInitialMessage ? MessageType.PRE_KEY : MessageType.NORMAL,
    header,
    ciphertext,
  };

  if (message.type === MessageType.PRE_KEY) {
    console.log("Creating PreKey message.");
    message.identityKey = nextState.identityPublicKey;
    message.preKeyId = 0; // TODO: wire in actual bundle IDs
    message.signedPreKeyId = 0; // TODO: wire in actual bundle IDs
  }

  console.log(
    `Encryption complete. Type: ${MessageType[message.type]}, N: ${
      header.messageCounter
    }, PN: ${header.previousCounter}`
  );

  // --- Now that the message is sent with the OLD header key, advance Alice’s own ratchet key ---
  if (nextRatchetKeyPair && nextEnhancedPrivateKey) {
    nextState.ourRatchetKeyPair = nextRatchetKeyPair;
    nextState.ourEnhancedPrivateKey = nextEnhancedPrivateKey;
  }

  return { message, nextState };
}

// --- Decryption Logic ---

/**
 * Creates a unique key for storing/retrieving skipped message keys based on header info.
 * Key format: N:Hex(PublicKey) - N is message counter in the chain associated with PublicKey
 * @param header The message header containing the public key and message counter.
 * @returns A unique string key.
 */
function getSkippedKeyLookupKey(header: MessageHeader): string {
  const pkHex = bytesToHex(header.publicKey);
  // The key identifies a message key within a specific chain (identified by pkHex)
  return `${header.messageCounter}:${pkHex}`;
}

/**
 * Decrypts a received RatchetMessage using the current RatchetState.
 * Handles DH ratchet updates, Triple Ratchet enhancement, and skipped keys.
 * @param currentState The current RatchetState.
 * @param message The received RatchetMessage.
 * @returns A Promise resolving to { plaintext: ArrayBuffer, nextState: RatchetState }.
 */
export async function ratchetDecrypt(
  currentState: RatchetState,
  message: RatchetMessage
): Promise<{ plaintext: ArrayBuffer; nextState: RatchetState }> {
  let nextState = { ...currentState };
  let plaintext: ArrayBuffer | null = null;
  const header = message.header;

  console.log(
    `Attempting to decrypt message Type: ${MessageType[message.type]}, N: ${
      header.messageCounter
    }, PN: ${header.previousCounter}, PubKey: ${bytesToHex(header.publicKey)}`
  );

  // 1) Try any skipped message key first
  const lookup = `${header.messageCounter}:${bytesToHex(header.publicKey)}`;
  if (nextState.skippedRatchetKeys.has(lookup)) {
    const skipped = nextState.skippedRatchetKeys.get(lookup)!;
    nextState.skippedRatchetKeys.delete(lookup);
    const aad = stringToBytes(
      JSON.stringify({
        pk: bytesToHex(header.publicKey),
        pn: header.previousCounter,
        n: header.messageCounter,
      })
    );
    plaintext = await decryptAES(
      skipped.encKey,
      message.ciphertext,
      skipped.iv,
      aad
    );
    console.log("✔️ Decrypted with skipped key");
    return { plaintext, nextState };
  }
  console.log("No skipped key – proceeding");

  // 2) Only perform a DH‐ratchet when it’s a PRE_KEY message
  let receivingChain = nextState.receivingChain;
  if (message.type === MessageType.PRE_KEY) {
    // Store any skipped keys from the old chain first
    if (receivingChain && nextState.theirRatchetKey) {
      const oldSkipped = new Map(nextState.skippedRatchetKeys);
      const remoteKey = nextState.theirRatchetKey;

      // internal skipped
      for (let [idx, keys] of receivingChain.skippedMessageKeys) {
        const keyLookup = `${idx}:${bytesToHex(remoteKey)}`;
        if (!oldSkipped.has(keyLookup)) oldSkipped.set(keyLookup, keys);
      }
      // skip up to PN
      let tempKey = receivingChain.chainKey;
      for (let i = receivingChain.chainIndex; i < header.previousCounter; i++) {
        const k = await deriveMessageKeysFromChainKey(tempKey);
        oldSkipped.set(`${i}:${bytesToHex(remoteKey)}`, k);
        tempKey = await advanceChainKey(tempKey);
      }
      nextState.skippedRatchetKeys = oldSkipped;
      console.log("Stored skipped keys from old chain");
    }

    // Now do the DH‐ratchet step
    console.log("🔄 Performing DH ratchet (PRE_KEY)");
    const dh = computeDH(nextState.ourEnhancedPrivateKey, header.publicKey);
    const { newRootKey, newChainKey } = await performDHRatchetStep(
      nextState.rootKey,
      dh
    );
    receivingChain = {
      chainKey: newChainKey,
      chainIndex: 0,
      skippedMessageKeys: new Map(),
    };
    nextState.rootKey = newRootKey;
    nextState.receivingChain = receivingChain;
    nextState.theirRatchetKey = header.publicKey;

    // reset send counters
    nextState.prevSendMsgCounter = nextState.sendMsgCounter;
    nextState.sendMsgCounter = 0;
    nextState.sendingChain = null;

    // generate *next* ratchet key for *our* next send
    const nextRK = generateECDHKeyPair();
    const nextX = calculateEnhancedPrivateKey(nextRK.privateKey, dh);
    nextState.ourRatchetKeyPair = nextRK;
    nextState.ourEnhancedPrivateKey = nextX;
    console.log("DH ratchet completed");
  }

  // 3) Symmetric‐ratchet decryption
  if (!nextState.receivingChain) {
    throw new Error("No receiving chain!");
  }
  console.log(`🔑 Symmetric ratchet decrypt, N=${header.messageCounter}`);
  const { messageKeys, nextChainState } = await getSymRatchetMessageKey(
    nextState.receivingChain,
    header.messageCounter
  );
  nextState.receivingChain = nextChainState;

  const aad = stringToBytes(
    JSON.stringify({
      pk: bytesToHex(header.publicKey),
      pn: header.previousCounter,
      n: header.messageCounter,
    })
  );
  console.log("Decrypting with AES-GCM");
  plaintext = await decryptAES(
    messageKeys.encKey,
    message.ciphertext,
    messageKeys.iv,
    aad
  );
  console.log("✔️ Symmetric decryption successful");

  return { plaintext, nextState };
}

// --- Identity and Key Management ---
// Using LocalStorage for persistence in the browser

const LS_IDENTITY_PREFIX = "identityState";
const LS_SIGNED_PREKEY_PREFIX = "signedPreKey";
const LS_ONETIME_PREKEY_PREFIX = "oneTimePreKey";

interface StorableKeyPair {
  publicKeyHex: string;
  privateKeyHex: string;
}

/**
 * Serializes an ECKeyPair (with Uint8Array keys) into a hex-based object for storage.
 */
function serializeKeyPair(keyPair: ECKeyPair): StorableKeyPair {
  return {
    publicKeyHex: bytesToHex(keyPair.publicKey),
    privateKeyHex: bytesToHex(keyPair.privateKey),
  };
}

/**
 * Deserializes a hex-based object back into an ECKeyPair (with Uint8Array keys).
 */
function deserializeKeyPair(storable: StorableKeyPair): ECKeyPair {
  if (
    !storable ||
    typeof storable.publicKeyHex !== "string" ||
    typeof storable.privateKeyHex !== "string"
  ) {
    throw new Error("Invalid storable key pair format");
  }
  // Use imported hexToBytes
  return {
    publicKey: hexToBytes(storable.publicKeyHex),
    privateKey: hexToBytes(storable.privateKeyHex),
  };
}

// --- Persistence Functions (Example using LocalStorage) ---

/**
 * Saves a signed pre-key pair to localStorage.
 * @param userId User ID associated with the key.
 * @param keyId The ID of the signed pre-key.
 * @param keyPair The key pair to save.
 */
export function saveSignedPreKey(
  userId: number,
  keyId: number,
  keyPair: ECKeyPair
): void {
  try {
    const storageKey = `${LS_SIGNED_PREKEY_PREFIX}:${userId}:${keyId}`;
    const storable = serializeKeyPair(keyPair);
    localStorage.setItem(storageKey, JSON.stringify(storable));
    console.log(
      `[LocalStorage] Saved Signed PreKey ID: ${keyId} for User ID: ${userId}`
    );
  } catch (e) {
    console.error(
      `[LocalStorage] Failed to save Signed PreKey ID: ${keyId}`,
      e
    );
    // Handle potential storage errors (e.g., quota exceeded)
  }
}

/**
 * Saves a one-time pre-key pair to localStorage.
 * @param userId User ID associated with the key.
 * @param keyId The ID of the one-time pre-key.
 * @param keyPair The key pair to save.
 */
export function saveOneTimePreKey(
  userId: number,
  keyId: number,
  keyPair: ECKeyPair
): void {
  try {
    const storageKey = `${LS_ONETIME_PREKEY_PREFIX}:${userId}:${keyId}`;
    const storable = serializeKeyPair(keyPair);
    localStorage.setItem(storageKey, JSON.stringify(storable));
    console.log(
      `[LocalStorage] Saved One-Time PreKey ID: ${keyId} for User ID: ${userId}`
    );
  } catch (e) {
    console.error(
      `[LocalStorage] Failed to save One-Time PreKey ID: ${keyId}`,
      e
    );
  }
}

/**
 * Retrieves a signed pre-key pair from localStorage.
 * Does NOT remove the key.
 * @param identityState - The state of the identity requesting the key (used to get userId).
 * @param keyId - The ID of the signed pre-key to retrieve.
 * @returns A Promise resolving to the ECKeyPair or null if not found/error.
 */
export async function getSignedPreKeyPair(
  identityState: IdentityState, // Assuming IdentityState has an 'id' field
  keyId: number
): Promise<ECKeyPair | null> {
  // This function doesn't need to be async unless storage itself is async
  const userId = identityState.id;
  const storageKey = `${LS_SIGNED_PREKEY_PREFIX}:${userId}:${keyId}`;
  console.log(
    `[LocalStorage] Attempting to get Signed PreKey ID: ${keyId} for User ID: ${userId}`
  );

  try {
    const storedItem = localStorage.getItem(storageKey);
    if (!storedItem) {
      console.warn(`[LocalStorage] Signed PreKey ID: ${keyId} not found.`);
      return null;
    }

    const storable: StorableKeyPair = JSON.parse(storedItem);
    const keyPair = deserializeKeyPair(storable); // Uses imported deserialize
    console.log(`[LocalStorage] Found Signed PreKey ID: ${keyId}.`);
    return keyPair;
  } catch (error) {
    console.error(
      `[LocalStorage] Error retrieving Signed PreKey ID: ${keyId}`,
      error
    );
    return null;
  }
}

/**
 * Retrieves AND REMOVES a one-time pre-key pair from localStorage.
 * Simulates one-time use.
 * @param identityState - The state of the identity requesting the key (used to get userId).
 * @param keyId - The ID of the one-time pre-key to retrieve and remove.
 * @returns A Promise resolving to the ECKeyPair or null if not found/error.
 */
export async function getOneTimePreKeyPair(
  identityState: IdentityState, // Assuming IdentityState has an 'id' field
  keyId: number
): Promise<ECKeyPair | null> {
  // This function doesn't need to be async unless storage itself is async
  const userId = identityState.id;
  const storageKey = `${LS_ONETIME_PREKEY_PREFIX}:${userId}:${keyId}`;
  console.log(
    `[LocalStorage] Attempting to get OT PreKey ID: ${keyId} for User ID: ${userId}`
  );

  try {
    const storedItem = localStorage.getItem(storageKey);
    if (!storedItem) {
      console.warn(`[LocalStorage] OT PreKey ID: ${keyId} not found.`);
      return null;
    }

    // Key found, now remove it *before* returning to simulate one-time use reliably
    localStorage.removeItem(storageKey);
    console.log(`[LocalStorage] Found and REMOVED OT PreKey ID: ${keyId}.`);

    // Parse and deserialize the retrieved item
    const storable: StorableKeyPair = JSON.parse(storedItem);
    const keyPair = deserializeKeyPair(storable); // Uses imported deserialize
    return keyPair;
  } catch (error) {
    console.error(
      `[LocalStorage] Error retrieving/removing OT PreKey ID: ${keyId}`,
      error
    );
    // If there was an error *after* removal, the key is lost.
    // Depending on requirements, you might try to re-save it or handle differently.
    return null;
  }
}

/**
 * Creates a PreKeyBundle for a given identity state.
 * This would typically be done on the server after a user registers keys,
 * but is simulated here for the test.
 * @param identityState The identity state to create a bundle for.
 * @param signedPreKeyId The ID of the signed pre-key to include.
 * @param preKeyId The ID of the one-time pre-key to include.
 * @returns A Promise resolving to the generated PreKeyBundle.
 */
export async function createPreKeyBundle(
  identityState: IdentityState,
  signedPreKeyId: number,
  preKeyId: number
): Promise<PreKeyBundle> {
  console.log(
    `Creating PreKeyBundle for User ID: ${identityState.id} using SPK ID: ${signedPreKeyId}, OPK ID: ${preKeyId}`
  );
  // Get the public key of the signed pre-key from the identity state
  const signedPreKeyPair = identityState.signedPreKeys.get(signedPreKeyId);
  if (!signedPreKeyPair) {
    throw new Error(`Signed pre-key with ID ${signedPreKeyId} not found`);
  }
  const signedPreKey = signedPreKeyPair.publicKey;

  // Get the public key of the one-time pre-key from the identity state
  // Note: In a real scenario, the server would fetch this *without* removing it.
  // The removal happens when the *recipient* uses it during X3DH (`getOneTimePreKeyPair`).
  // For bundle creation, we just need the public part.
  const preKeyPair = identityState.preKeys.get(preKeyId);
  let preKey: ECDHPublicKey; // Declare preKey variable

  if (!preKeyPair) {
    // If it was already used/removed by a previous bundle request simulation, this could happen.
    // A real server manages pre-key availability.
    // Let's try fetching from localStorage directly for bundle creation simulation.
    const storedPreKey = await getPreKeyFromStorageWithoutRemoving(
      identityState.id,
      preKeyId
    );
    if (!storedPreKey) {
      throw new Error(
        `Pre-key with ID ${preKeyId} not found in state or storage.`
      );
    }
    console.warn(
      `PreKey ${preKeyId} not in memory state, fetched from storage for bundle.`
    );
    // We only need the public key for the bundle
    preKey = storedPreKey.publicKey; // Assign to preKey
  } else {
    preKey = preKeyPair.publicKey; // Assign to preKey
  }

  // Get the signature for the signed pre-key
  const signedPreKeySignature =
    identityState.signedPreKeySignatures.get(signedPreKeyId);
  if (!signedPreKeySignature) {
    throw new Error(`Signature for signed pre-key ${signedPreKeyId} not found`);
  }

  // Create the PreKeyBundle
  const bundle: PreKeyBundle = {
    identityId: identityState.id,
    identityKey: identityState.dhKeyPair.publicKey, // IK pub
    signedPreKeyId: signedPreKeyId,
    signedPreKey: signedPreKey, // SPK pub
    signedPreKeySignature: signedPreKeySignature, // Signature(SPK pub)
    preKeyId: preKeyId,
    preKey: preKey, // OPK pub
    signingKey: identityState.signingKeyPair.publicKey, // Public signing key of the bundle owner
  };
  console.log("PreKeyBundle created successfully.");
  return bundle;
}

/** Helper to get pre-key public part from storage without removing it (for bundle creation simulation) */
async function getPreKeyFromStorageWithoutRemoving(
  userId: number,
  keyId: number
): Promise<ECKeyPair | null> {
  const storageKey = `${LS_ONETIME_PREKEY_PREFIX}:${userId}:${keyId}`;
  try {
    const storedItem = localStorage.getItem(storageKey);
    if (!storedItem) return null;
    const storable: StorableKeyPair = JSON.parse(storedItem);
    return deserializeKeyPair(storable);
  } catch (error) {
    console.error(`Error fetching pre-key ${keyId} from storage:`, error);
    return null;
  }
}

/**
 * Creates and initializes a new identity state with pre-keys.
 * Generates keys, signs the signed pre-key, and saves keys to localStorage.
 * @param userId The user ID for the identity.
 * @param numPreKeys The number of one-time pre-keys to generate.
 * @returns A Promise resolving to the initialized IdentityState.
 */
export async function createIdentityState(
  userId: number,
  numPreKeys: number = 10
): Promise<IdentityState> {
  console.log(`Creating new IdentityState for User ID: ${userId}`);
  // Generate identity key pairs (long-term)
  const dhKeyPair = generateECDHKeyPair(); // Identity Key Pair (IK)
  // Use the imported generateSigningKeyPair function
  const signingKeyPair = generateSigningKeyPair(); // Signing Key Pair (SK)
  console.log("Generated identity and signing key pairs.");

  // Initialize maps for pre-keys in memory
  const preKeys = new Map<number, ECKeyPair>(); // One-Time PreKeys (OPK)
  const signedPreKeys = new Map<number, ECKeyPair>(); // Signed PreKey (SPK)
  const signedPreKeySignatures = new Map<number, Uint8Array>(); // Signature(SPK pub)

  // Generate signed pre-key (typically just one active one)
  const signedPreKeyId = 0; // Example ID
  const signedPreKeyPair = generateECDHKeyPair();
  signedPreKeys.set(signedPreKeyId, signedPreKeyPair);
  console.log(`Generated Signed PreKey ID: ${signedPreKeyId}`);

  // Sign the public part of the signed pre-key with the long-term signing key
  const signedPreKeySignature = await signData(
    signingKeyPair.privateKey, // Use the signing private key
    signedPreKeyPair.publicKey // Sign the public key bytes
  );
  signedPreKeySignatures.set(signedPreKeyId, signedPreKeySignature);
  console.log("Signed the Signed PreKey.");

  // Save signed pre-key to localStorage for persistence
  saveSignedPreKey(userId, signedPreKeyId, signedPreKeyPair);

  // Generate one-time pre-keys
  console.log(`Generating ${numPreKeys} One-Time PreKeys...`);
  for (let i = 0; i < numPreKeys; i++) {
    const preKeyPair = generateECDHKeyPair();
    preKeys.set(i, preKeyPair); // Store in memory map

    // Save to localStorage for persistence
    saveOneTimePreKey(userId, i, preKeyPair);
  }
  console.log("Generated and saved One-Time PreKeys.");

  // Create the identity state object
  const identityState: IdentityState = {
    id: userId,
    dhKeyPair, // IK
    signingKeyPair, // SK
    preKeys, // OPKs (in memory copy)
    signedPreKeys, // SPK (in memory copy)
    signedPreKeySignatures, // Signature (in memory copy)
  };

  console.log(`IdentityState created for User ID: ${userId}`);
  return identityState;
}
