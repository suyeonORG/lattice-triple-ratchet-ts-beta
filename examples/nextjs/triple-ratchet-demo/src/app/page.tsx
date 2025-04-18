"use client";

import { useState } from "react";
import styles from "./page.module.css";
import {
  createIdentityState,
  createPreKeyBundle,
  initializeRatchetInitiator,
  initializeRatchetReceiver,
  ratchetEncrypt,
  ratchetDecrypt,
} from "triple-ratchet";

export default function Home() {
  const [logs, setLogs] = useState<string[]>([]);
  const [running, setRunning] = useState(false);

  const append = (line: string) =>
    setLogs((prev) => [...prev, `${new Date().toLocaleTimeString()}: ${line}`]);

  const runDemo = async () => {
    setRunning(true);
    setLogs([]);
    try {
      append("🔑 Generating identities…");
      const alice = await createIdentityState(1);
      const bob = await createIdentityState(2);

      append("📦 Bob publishes PreKey bundle…");
      const bundle = await createPreKeyBundle(bob, 0, 0);

      append("🚀 Alice → initialize session…");
      let aliceState = await initializeRatchetInitiator(alice, bundle);

      // Alice sends first message
      append('✉️ Alice sends: "Hello Bob!"');
      let { message: msg1, nextState: nextAlice } = await ratchetEncrypt(
        aliceState,
        new TextEncoder().encode("Hello Bob!").buffer
      );
      aliceState = nextAlice;

      // Bob initializes & decrypts
      append("👂 Bob ← initialize from PreKey message…");
      let bobState = await initializeRatchetReceiver(bob, msg1);
      let { plaintext: p1, nextState: nextBob } = await ratchetDecrypt(
        bobState,
        msg1
      );
      bobState = nextBob;
      append(`✅ Bob decrypted: "${new TextDecoder().decode(p1)}"`);

      // Alice sends follow‑up
      append('✉️ Alice sends: "How are you?"');
      let { message: msg2, nextState: nextAlice2 } = await ratchetEncrypt(
        aliceState,
        new TextEncoder().encode("How are you?").buffer
      );
      aliceState = nextAlice2;
      let { plaintext: p2, nextState: nextBob2 } = await ratchetDecrypt(
        bobState,
        msg2
      );
      bobState = nextBob2;
      append(`✅ Bob decrypted: "${new TextDecoder().decode(p2)}"`);

      // Bob replies
      append('✉️ Bob sends: "I’m fine, thanks!"');
      let { message: reply, nextState: nextBob3 } = await ratchetEncrypt(
        bobState,
        new TextEncoder().encode("I’m fine, thanks!").buffer
      );
      bobState = nextBob3;
      let { plaintext: p3 } = await ratchetDecrypt(aliceState, reply);
      append(`✅ Alice decrypted: "${new TextDecoder().decode(p3)}"`);

      append("🎉 Demo complete!");
    } catch (e) {
      append(`❌ Error: ${(e as Error).message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <main className={styles.main}>
      <h1>Triple Ratchet Demo</h1>
      <button onClick={runDemo} disabled={running}>
        {running ? "Running…" : "Run Demo"}
      </button>
      <pre className={styles.console}>{logs.join("\n")}</pre>
    </main>
  );
}
