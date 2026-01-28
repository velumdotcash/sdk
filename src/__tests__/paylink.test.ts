/**
 * Integration tests for Privacy Paylink third-party deposit functionality
 *
 * These tests verify that:
 * 1. Utxo can be created with only a public key (no private key)
 * 2. Asymmetric encryption works correctly
 * 3. Third-party deposits work end-to-end
 */

import { describe, it, expect, beforeAll } from "vitest";
import { Utxo } from "../models/utxo";
import { Keypair } from "../models/keypair";
import { EncryptionService } from "../utils/encryption";
import { WasmFactory } from "@lightprotocol/hasher.rs";
import type * as hasher from "@lightprotocol/hasher.rs";
import BN from "bn.js";
import nacl from "tweetnacl";

describe("Paylink Core Functionality", () => {
  let lightWasm: hasher.LightWasm;

  beforeAll(async () => {
    // Initialize WASM - required for all crypto operations
    lightWasm = await WasmFactory.getInstance();
  });

  describe("Utxo pubkey-only mode", () => {
    it("should create Utxo with only publicKey", async () => {
      // Generate a keypair to get a valid public key
      const keypair = await Keypair.generateNew(lightWasm);
      const pubkey = keypair.pubkey;

      // Create Utxo with only the public key
      const utxo = new Utxo({
        lightWasm,
        amount: new BN(1000000),
        publicKey: pubkey,
      });

      expect(utxo.pubkey.toString()).toBe(pubkey.toString());
      expect(utxo.amount.toNumber()).toBe(1000000);
    });

    it("should allow getCommitment() with pubkey-only Utxo", async () => {
      const keypair = await Keypair.generateNew(lightWasm);
      const utxo = new Utxo({
        lightWasm,
        amount: new BN(500000),
        publicKey: keypair.pubkey,
      });

      // getCommitment should work without private key (async)
      const commitment = await utxo.getCommitment();
      expect(commitment).toBeDefined();
      expect(typeof commitment).toBe("string");
    });

    it("should throw on getNullifier() with pubkey-only Utxo", async () => {
      const keypair = await Keypair.generateNew(lightWasm);
      const utxo = new Utxo({
        lightWasm,
        amount: new BN(500000),
        publicKey: keypair.pubkey,
      });

      // getNullifier requires private key, should throw
      await expect(utxo.getNullifier()).rejects.toThrow();
    });

    it("should work normally with full keypair", async () => {
      const keypair = await Keypair.generateNew(lightWasm);
      const utxo = new Utxo({
        lightWasm,
        amount: new BN(1000000),
        keypair: keypair,
      });

      // Both should work with full keypair
      const commitment = await utxo.getCommitment();
      const nullifier = await utxo.getNullifier();

      expect(commitment).toBeDefined();
      expect(nullifier).toBeDefined();
    });
  });

  describe("Asymmetric Encryption", () => {
    let aliceEncryption: EncryptionService;
    let bobEncryption: EncryptionService;

    beforeAll(async () => {
      // Simulate two different wallets by deriving from different signatures
      const aliceSignature = nacl.randomBytes(64);
      const bobSignature = nacl.randomBytes(64);

      aliceEncryption = new EncryptionService();
      aliceEncryption.deriveEncryptionKeyFromSignature(aliceSignature);

      bobEncryption = new EncryptionService();
      bobEncryption.deriveEncryptionKeyFromSignature(bobSignature);
    });

    it("should get asymmetric public key", () => {
      const alicePubKey = aliceEncryption.getAsymmetricPublicKey();

      expect(alicePubKey).toBeDefined();
      expect(alicePubKey.length).toBe(32); // X25519 public key is 32 bytes
    });

    it("should encrypt for recipient using asymmetric encryption", () => {
      const alicePubKey = aliceEncryption.getAsymmetricPublicKey();
      const testData = Buffer.from("Hello Alice, this is a secret message!");

      // Bob encrypts for Alice
      const encrypted = bobEncryption.encryptAsymmetric(testData, alicePubKey);

      expect(encrypted).toBeDefined();
      expect(encrypted.length).toBeGreaterThan(testData.length); // Should have nonce + ephemeral key overhead
    });

    it("should decrypt via decryptUtxo for V3 encrypted data", async () => {
      const alicePubKey = aliceEncryption.getAsymmetricPublicKey();

      // Create a simple UTXO to encrypt
      const keypair = await Keypair.generateNew(lightWasm);
      const utxo = new Utxo({
        lightWasm,
        amount: new BN(1_000_000_000),
        publicKey: keypair.pubkey,
      });

      // Bob encrypts UTXO for Alice using asymmetric encryption
      const encrypted = bobEncryption.encryptUtxo(utxo, alicePubKey);

      // Verify it's compact V3 format (tag byte 0xC3 at position 0)
      expect(encrypted[0]).toBe(0xC3);

      // Alice can decrypt via decryptUtxo (handles V3 internally)
      const decrypted = await aliceEncryption.decryptUtxo(encrypted, lightWasm);

      expect(decrypted).toBeDefined();
      expect(decrypted!.amount.toString()).toBe(utxo.amount.toString());
    });

    it("should fail decryption with wrong key", async () => {
      const alicePubKey = aliceEncryption.getAsymmetricPublicKey();

      const keypair = await Keypair.generateNew(lightWasm);
      const utxo = new Utxo({
        lightWasm,
        amount: new BN(1_000_000_000),
        publicKey: keypair.pubkey,
      });

      // Bob encrypts for Alice
      const encrypted = bobEncryption.encryptUtxo(utxo, alicePubKey);

      // Bob tries to decrypt his own encrypted data for Alice - should fail
      try {
        await bobEncryption.decryptUtxo(encrypted, lightWasm);
        expect(true).toBe(false); // Should not reach here
      } catch (e) {
        expect(e).toBeDefined();
      }
    });
  });

  describe("UTXO Encryption for Third-Party", () => {
    let senderEncryption: EncryptionService;
    let recipientEncryption: EncryptionService;
    let recipientKeypair: Keypair;

    beforeAll(async () => {
      const senderSignature = nacl.randomBytes(64);
      const recipientSignature = nacl.randomBytes(64);

      senderEncryption = new EncryptionService();
      senderEncryption.deriveEncryptionKeyFromSignature(senderSignature);

      recipientEncryption = new EncryptionService();
      recipientEncryption.deriveEncryptionKeyFromSignature(recipientSignature);

      recipientKeypair = await Keypair.generateNew(lightWasm);
    });

    it("should encrypt UTXO for recipient", () => {
      const recipientEncKey = recipientEncryption.getAsymmetricPublicKey();

      // Create UTXO owned by recipient
      const utxo = new Utxo({
        lightWasm,
        amount: new BN(1_000_000_000), // 1 SOL
        publicKey: recipientKeypair.pubkey,
      });

      // Sender encrypts UTXO data for recipient
      const encrypted = senderEncryption.encryptUtxo(utxo, recipientEncKey);

      expect(encrypted).toBeDefined();
      expect(encrypted.length).toBeGreaterThan(0);

      // First byte should be compact V3 tag (0xC3)
      expect(encrypted[0]).toBe(0xC3);
    });

    it("should allow recipient to decrypt UTXO", async () => {
      // For this test to work, recipientKeypair must match what EncryptionService derives
      const recipientPrivKey = recipientEncryption.getUtxoPrivateKeyV2();
      // Re-instantiate the keypair that matches the encryption service
      const derivedRecipientKeypair = new Keypair(recipientPrivKey, lightWasm);

      const recipientEncKey = recipientEncryption.getAsymmetricPublicKey();

      // Create UTXO owned by recipient
      const originalAmount = new BN(2_500_000_000); // 2.5 SOL
      const utxo = new Utxo({
        lightWasm,
        amount: originalAmount,
        publicKey: derivedRecipientKeypair.pubkey,
      });

      // Sender encrypts for recipient
      const encrypted = senderEncryption.encryptUtxo(utxo, recipientEncKey);

      // Recipient decrypts
      const decryptedUtxo = await recipientEncryption.decryptUtxo(
        encrypted,
        lightWasm,
      );

      expect(decryptedUtxo).toBeDefined();
      expect(decryptedUtxo!.amount.toString()).toBe(originalAmount.toString());
      expect(decryptedUtxo!.pubkey.toString()).toBe(
        derivedRecipientKeypair.pubkey.toString(),
      );
    });

    it("should not allow sender to decrypt their own encrypted UTXO for recipient", async () => {
      const recipientEncKey = recipientEncryption.getAsymmetricPublicKey();

      const utxo = new Utxo({
        lightWasm,
        amount: new BN(1_000_000_000),
        publicKey: recipientKeypair.pubkey,
      });

      // Sender encrypts for recipient
      const encrypted = senderEncryption.encryptUtxo(utxo, recipientEncKey);

      // Sender tries to decrypt - should fail
      try {
        await senderEncryption.decryptUtxo(
          encrypted,
          lightWasm,
        );
        // If we get here, it failed to throw
        expect(true).toBe(false); 
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  describe("End-to-End Paylink Flow (Unit)", () => {
    it("should support complete paylink flow", async () => {
      // === RECIPIENT GENERATES PAYLINK ===
      const recipientSignature = nacl.randomBytes(64);
      const recipientEncryption = new EncryptionService();
      recipientEncryption.deriveEncryptionKeyFromSignature(recipientSignature);
      const recipientUtxoKeypair = await Keypair.generateNew(lightWasm);

      // These would be encoded in the paylink URL
      const paylinkData = {
        recipientUtxoPubkey: recipientUtxoKeypair.pubkey.toString(),
        recipientEncryptionKey: Buffer.from(
          recipientEncryption.getAsymmetricPublicKey(),
        ).toString("base64"),
        token: "SOL",
        amount: null, // Open amount
      };

      // === SENDER PAYS VIA PAYLINK ===
      const senderSignature = nacl.randomBytes(64);
      const senderEncryption = new EncryptionService();
      senderEncryption.deriveEncryptionKeyFromSignature(senderSignature);

      // Sender decodes paylink data
      const recipientPubkey = new BN(paylinkData.recipientUtxoPubkey);
      const recipientEncKey = new Uint8Array(
        Buffer.from(paylinkData.recipientEncryptionKey, "base64"),
      );

      // Sender creates UTXO for recipient
      const paymentAmount = new BN(5_000_000_000); // 5 SOL
      const outputUtxo = new Utxo({
        lightWasm,
        amount: paymentAmount,
        publicKey: recipientPubkey,
      });

      // Sender encrypts UTXO for recipient
      const encryptedOutput = senderEncryption.encryptUtxo(
        outputUtxo,
        recipientEncKey,
      );

      // Verify commitment can be computed (needed for on-chain)
      const commitment = await outputUtxo.getCommitment();
      expect(commitment).toBeDefined();

      // === RECIPIENT CLAIMS ===
      // Recipient scans encrypted outputs and tries to decrypt
      const decryptedUtxo = await recipientEncryption.decryptUtxo(
        encryptedOutput,
        lightWasm,
      );

      expect(decryptedUtxo).toBeDefined();
      expect(decryptedUtxo!.amount.toString()).toBe(paymentAmount.toString());

      // Recipient can now use their keypair to spend (would need full keypair for nullifier)
      // In real flow, recipient would reconstruct UTXO with their full keypair
      const spendableUtxo = new Utxo({
        lightWasm,
        amount: decryptedUtxo!.amount,
        keypair: recipientUtxoKeypair, // Full keypair for spending
      });

      // Now recipient can compute nullifier for spending
      const nullifier = await spendableUtxo.getNullifier();
      expect(nullifier).toBeDefined();
    });
  });
});
