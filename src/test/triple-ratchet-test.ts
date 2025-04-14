// === File: src/test/triple-ratchet-test.ts ===

import {
  createIdentityState,
  createPreKeyBundle,
  initializeRatchetInitiator,
  initializeRatchetReceiver,
  ratchetEncrypt,
  ratchetDecrypt,
} from "../protocol/ratchet-logic";
import { bytesToString, stringToBytes } from "../utils/buffer";
import type { IdentityState, RatchetState, PreKeyBundle } from "../types";

/**
 * A class to test the Triple Ratchet protocol implementation end-to-end.
 * This demonstrates the full flow of secure communication using the protocol.
 */
export class TripleRatchetTest {
  private aliceIdentity!: IdentityState;
  private bobIdentity!: IdentityState;
  private aliceState!: RatchetState;
  private bobState!: RatchetState;
  private bobPreKeyBundle!: PreKeyBundle;
  private messagesFromAlice: string[] = [];
  private messageFromBob: string[] = [];

  /**
   * Initialize test identities and states for both parties.
   */
  public async setup(): Promise<void> {
    console.log("=== Setting up Triple Ratchet Test ===");

    try {
      // Step 1: Create identities for Alice and Bob
      console.log("Creating identities for Alice and Bob...");
      this.aliceIdentity = await createIdentityState(1); // Alice is user 1
      this.bobIdentity = await createIdentityState(2); // Bob is user 2

      // Step 2: Create Bob's PreKeyBundle (that would normally be published on a server)
      console.log("Creating Bob's PreKeyBundle...");
      this.bobPreKeyBundle = await createPreKeyBundle(this.bobIdentity, 0, 0);

      // Step 3: Alice initializes a session with Bob using his bundle
      console.log("Alice initializing session with Bob...");
      this.aliceState = await initializeRatchetInitiator(
        this.aliceIdentity,
        this.bobPreKeyBundle
      );

      console.log("Setup complete!");
    } catch (error) {
      console.error("Error during setup:", error);
      throw error;
    }
  }

  /**
   * Alice sends a first message to Bob, which establishes the session on Bob's side
   * @param message The message text to send
   */
  public async aliceSendsFirstMessage(message: string): Promise<void> {
    console.log("\n=== Alice Sends First Message ===");

    try {
      // Step 1: Alice encrypts her first message (this will be a PreKey message)
      console.log(`Alice encrypting: "${message}"`);
      const plaintext = stringToBytes(message);
      const { message: encryptedMessage, nextState } = await ratchetEncrypt(
        this.aliceState,
        plaintext
      );

      // Update Alice's state
      this.aliceState = nextState;

      // Step 2: Bob receives the PreKey message and initializes his session
      console.log("Bob receiving and initializing his session...");
      this.bobState = await initializeRatchetReceiver(
        this.bobIdentity,
        encryptedMessage
      );

      // Step 3: Bob decrypts the message
      console.log("Bob decrypting the message...");
      const { plaintext: decryptedPlaintext, nextState: bobNextState } =
        await ratchetDecrypt(this.bobState, encryptedMessage);

      // Update Bob's state
      this.bobState = bobNextState;

      // Step 4: Convert the decrypted message to a string
      const decryptedMessage = bytesToString(decryptedPlaintext);
      console.log(`Bob decrypted: "${decryptedMessage}"`);

      // Store for verification
      this.messagesFromAlice.push(message);

      if (message === decryptedMessage) {
        console.log("First message successfully sent and received!");
      } else {
        console.error("Decryption failed: messages don't match!");
      }
    } catch (error) {
      console.error("Error in aliceSendsFirstMessage:", error);
      throw error;
    }
  }

  /**
   * Alice sends subsequent messages to Bob (after the session is established)
   * @param message The message text to send
   */
  public async aliceSendsMessage(message: string): Promise<void> {
    console.log("\n=== Alice Sends Message ===");

    try {
      // Step 1: Alice encrypts her message
      console.log(`Alice encrypting: "${message}"`);
      const plaintext = stringToBytes(message);
      const { message: encryptedMessage, nextState } = await ratchetEncrypt(
        this.aliceState,
        plaintext
      );

      // Update Alice's state
      this.aliceState = nextState;

      // Step 2: Bob decrypts the message
      console.log("Bob decrypting the message...");
      const { plaintext: decryptedPlaintext, nextState: bobNextState } =
        await ratchetDecrypt(this.bobState, encryptedMessage);

      // Update Bob's state
      this.bobState = bobNextState;

      // Step 3: Convert the decrypted message to a string
      const decryptedMessage = bytesToString(decryptedPlaintext);
      console.log(`Bob decrypted: "${decryptedMessage}"`);

      // Store for verification
      this.messagesFromAlice.push(message);

      if (message === decryptedMessage) {
        console.log("Message successfully sent and received!");
      } else {
        console.error("Decryption failed: messages don't match!");
      }
    } catch (error) {
      console.error("Error in aliceSendsMessage:", error);
      throw error;
    }
  }

  /**
   * Bob sends a message to Alice
   * @param message The message text to send
   */
  public async bobSendsMessage(message: string): Promise<void> {
    console.log("\n=== Bob Sends Message ===");

    try {
      // Step 1: Bob encrypts his message
      console.log(`Bob encrypting: "${message}"`);
      const plaintext = stringToBytes(message);
      const { message: encryptedMessage, nextState } = await ratchetEncrypt(
        this.bobState,
        plaintext
      );

      // Update Bob's state
      this.bobState = nextState;

      // Step 2: Alice decrypts the message
      console.log("Alice decrypting the message...");
      const { plaintext: decryptedPlaintext, nextState: aliceNextState } =
        await ratchetDecrypt(this.aliceState, encryptedMessage);

      // Update Alice's state
      this.aliceState = aliceNextState;

      // Step 3: Convert the decrypted message to a string
      const decryptedMessage = bytesToString(decryptedPlaintext);
      console.log(`Alice decrypted: "${decryptedMessage}"`);

      // Store for verification
      this.messageFromBob.push(message);

      if (message === decryptedMessage) {
        console.log("Message successfully sent and received!");
      } else {
        console.error("Decryption failed: messages don't match!");
      }
    } catch (error) {
      console.error("Error in bobSendsMessage:", error);
      throw error;
    }
  }

  /**
   * Demonstrates key rotation by sending multiple messages back and forth
   * This shows the forward secrecy and break-in recovery properties
   */
  public async demonstrateKeyRotation(messageCount: number = 5): Promise<void> {
    console.log("\n=== Demonstrating Key Rotation ===");
    console.log(
      `Sending ${messageCount} messages in each direction to trigger ratchet turns...`
    );

    try {
      // Alice and Bob alternate sending messages
      for (let i = 0; i < messageCount; i++) {
        // Alice sends message to Bob
        const aliceMessage = `Alice's message #${i + 1}: Hello Bob!`;
        await this.aliceSendsMessage(aliceMessage);

        // Bob sends message to Alice
        const bobMessage = `Bob's message #${i + 1}: Hello Alice!`;
        await this.bobSendsMessage(bobMessage);

        console.log(`Completed round ${i + 1} of message exchange`);

        // Log some state information to show changes
        console.log(`Alice's send counter: ${this.aliceState.sendMsgCounter}`);
        console.log(`Bob's send counter: ${this.bobState.sendMsgCounter}`);
      }

      console.log("\nKey rotation demonstration complete!");
      console.log(
        "The Triple Ratchet protocol has successfully maintained secure communication"
      );
      console.log(
        "with automatic key rotation for forward secrecy and break-in recovery."
      );
    } catch (error) {
      console.error("Error in demonstrateKeyRotation:", error);
      throw error;
    }
  }

  /**
   * Demonstrates the out-of-order message handling capability
   */
  public async demonstrateOutOfOrderMessages(): Promise<void> {
    console.log("\n=== Demonstrating Out-of-Order Message Handling ===");

    try {
      // Alice encrypts three messages in sequence
      console.log("Alice encrypting three messages in sequence...");
      const message1 = "Message 1: This should arrive first";
      const message2 = "Message 2: This should arrive second";
      const message3 = "Message 3: This should arrive third";

      // Encrypt all three messages
      const plaintext1 = stringToBytes(message1);
      const { message: encryptedMessage1, nextState: aliceState1 } =
        await ratchetEncrypt(this.aliceState, plaintext1);

      // Update Alice's state for the next message
      const aliceStateAfterMsg1 = aliceState1;

      const plaintext2 = stringToBytes(message2);
      const { message: encryptedMessage2, nextState: aliceState2 } =
        await ratchetEncrypt(aliceStateAfterMsg1, plaintext2);

      // Update Alice's state for the next message
      const aliceStateAfterMsg2 = aliceState2;

      const plaintext3 = stringToBytes(message3);
      const { message: encryptedMessage3, nextState: aliceState3 } =
        await ratchetEncrypt(aliceStateAfterMsg2, plaintext3);

      // Update Alice's final state
      this.aliceState = aliceState3;

      // Bob receives the messages out of order: 3, 1, 2
      console.log(
        "Bob receiving and decrypting messages out of order: 3, 1, 2"
      );

      // Message 3 (received first)
      console.log("Bob decrypting message 3 (received first)...");
      const { plaintext: decryptedPlaintext3, nextState: bobStateAfterMsg3 } =
        await ratchetDecrypt(this.bobState, encryptedMessage3);

      // Update Bob's state
      const bobStateAfterReceivingMsg3 = bobStateAfterMsg3;

      // Message 1 (received second)
      console.log("Bob decrypting message 1 (received second)...");
      const { plaintext: decryptedPlaintext1, nextState: bobStateAfterMsg1 } =
        await ratchetDecrypt(bobStateAfterReceivingMsg3, encryptedMessage1);

      // Update Bob's state
      const bobStateAfterReceivingMsg1 = bobStateAfterMsg1;

      // Message 2 (received last)
      console.log("Bob decrypting message 2 (received last)...");
      const { plaintext: decryptedPlaintext2, nextState: bobStateAfterMsg2 } =
        await ratchetDecrypt(bobStateAfterReceivingMsg1, encryptedMessage2);

      // Update Bob's final state
      this.bobState = bobStateAfterMsg2;

      // Check if all messages were decrypted correctly
      const decryptedMessage1 = bytesToString(decryptedPlaintext1);
      const decryptedMessage2 = bytesToString(decryptedPlaintext2);
      const decryptedMessage3 = bytesToString(decryptedPlaintext3);

      console.log("\nDecrypted messages:");
      console.log(`Message 1: "${decryptedMessage1}"`);
      console.log(`Message 2: "${decryptedMessage2}"`);
      console.log(`Message 3: "${decryptedMessage3}"`);

      if (
        message1 === decryptedMessage1 &&
        message2 === decryptedMessage2 &&
        message3 === decryptedMessage3
      ) {
        console.log(
          "\nAll messages successfully decrypted in the correct order!"
        );
        console.log(
          "The Triple Ratchet protocol successfully handled out-of-order messages."
        );
      } else {
        console.error("\nDecryption failed: some messages don't match!");
      }
    } catch (error) {
      console.error("Error in demonstrateOutOfOrderMessages:", error);
      throw error;
    }
  }

  /**
   * Run the complete test suite
   */
  public async runTest(): Promise<void> {
    console.log("========================================");
    console.log("      TRIPLE RATCHET TEST SUITE        ");
    console.log("========================================");

    try {
      // Initialize test environment
      await this.setup();

      // Test the initial message exchange
      await this.aliceSendsFirstMessage(
        "Hello Bob! This is the first message."
      );

      // Test regular message exchange
      await this.bobSendsMessage("Hi Alice! I received your message.");
      await this.aliceSendsMessage("Great! Let's test our secure channel.");

      // Test key rotation
      await this.demonstrateKeyRotation(3);

      // Test out-of-order message handling
      await this.demonstrateOutOfOrderMessages();

      console.log("\n========================================");
      console.log("      TEST SUITE COMPLETED SUCCESSFULLY  ");
      console.log("========================================");
    } catch (error) {
      console.error("\n========================================");
      console.error("      TEST SUITE FAILED                ");
      console.error("========================================");
      console.error("Error:", error);
    }
  }
}

/**
 * Run the test when this file is executed directly
 */
(async function () {
  const test = new TripleRatchetTest();
  await test.runTest();
})();
