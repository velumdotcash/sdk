
import { describe, it, expect, beforeAll } from 'vitest';
import { Keypair, Connection, LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js';
import { EncryptionService } from './utils/encryption.js';
import { deposit } from './deposit.js';
import { WasmFactory } from '@lightprotocol/hasher.rs';
import { LocalStorage } from 'node-localstorage';
import path from 'path';
import fs from 'fs';
import * as crypto from 'crypto';
import nacl from 'tweetnacl';
import { keccak256 } from '@ethersproject/keccak256';
import { Utxo } from './models/utxo.js';
import { Keypair as UtxoKeypair } from './models/keypair.js';

// Mock storage
const storage = new LocalStorage('./test-storage');

describe('Paylink Logic (Third-Party Deposit)', () => {
    let connection: Connection;
    let senderKeypair: Keypair;
    let receiverKeypair: Keypair;
    let encryptionServiceSender: EncryptionService;
    let encryptionServiceReceiver: EncryptionService;
    let lightWasm: any;

    beforeAll(async () => {
        // Use a local validator or devnet. For unit testing logic we might mock connection,
        // but here we want to test the flow.
        // If no local validator, we might fail network calls.
        // Let's assume we are testing the *logic* of key derivation and encryption first,
        // and mocking the actual transaction submission if possible, or just checking the function arguments.

        // Actually, we can't easily mock the whole deposit flow without a real RPC.
        // But we can test the critical parts:
        // 1. Recipient Key Derivation
        // 2. Encryption (Asymmetric)
        // 3. Decryption (by Recipient)

        lightWasm = await WasmFactory.getInstance();
        senderKeypair = Keypair.generate();
        receiverKeypair = Keypair.generate();

        encryptionServiceSender = new EncryptionService();
        encryptionServiceSender.deriveEncryptionKeyFromWallet(senderKeypair);

        encryptionServiceReceiver = new EncryptionService();
        encryptionServiceReceiver.deriveEncryptionKeyFromWallet(receiverKeypair);
    });

    it('should correctly derive keys for the recipient', () => {
        // 1. Get Recipient's UTXO Public Key (Poseidon Hash of Private Key)
        const recipientUtxoPrivateKey = encryptionServiceReceiver.getUtxoPrivateKeyV2();
        // We need to simulate how the frontend would get this.
        // The frontend would have access to the recipient's wallet signature to derive this.

        // This is the key the recipient publishes
        const recipientUtxoPubkey = encryptionServiceReceiver.getUtxoPrivateKeyV2();
        // WAIT: getUtxoPrivateKeyV2 returns the PRIVATE key.
        // We need the PUBLIC key corresponding to this.

        // Let's check how UtxoKeypair works.
        // It takes the privkey and derives the pubkey.
        // We need to instantiate it to get the pubkey.
        const recipientUtxoKeypair = new UtxoKeypair(recipientUtxoPrivateKey, lightWasm);
        const recipientPublicUtxoKey = recipientUtxoKeypair.pubkey;

        console.log('Recipient UTXO Public Key:', recipientPublicUtxoKey.toString());
        expect(recipientPublicUtxoKey).toBeDefined();

        // 2. Get Recipient's Encryption Public Key (X25519)
        const recipientAsymmetricPubKey = encryptionServiceReceiver.getAsymmetricPublicKey();
        console.log('Recipient Asymmetric Public Key:', Buffer.from(recipientAsymmetricPubKey).toString('hex'));
        expect(recipientAsymmetricPubKey).toBeDefined();
        expect(recipientAsymmetricPubKey.length).toBe(32);
    });

    it('should encrypt a message sender -> recipient using UTXO format', async () => {
        // Create a proper UTXO for encryption (not raw string)
        const recipientAsymmetricPubKey = encryptionServiceReceiver.getAsymmetricPublicKey();
        const recipientUtxoPrivateKey = encryptionServiceReceiver.getUtxoPrivateKeyV2();
        const recipientUtxoKeypair = new UtxoKeypair(recipientUtxoPrivateKey, lightWasm);
        const recipientPublicUtxoKey = recipientUtxoKeypair.pubkey;

        // Create a test UTXO
        const testUtxo = new Utxo({
            lightWasm,
            amount: '5000',
            publicKey: recipientPublicUtxoKey,
            index: 5
        });

        // Sender encrypts for Recipient using V3 (asymmetric)
        const encrypted = encryptionServiceSender.encryptUtxo(testUtxo, recipientAsymmetricPubKey);

        // Verify it's V3 format
        expect(encryptionServiceSender.getEncryptionKeyVersion(encrypted)).toBe('v3');

        // Recipient decrypts
        const decrypted = await encryptionServiceReceiver.decryptUtxo(encrypted, lightWasm);
        expect(decrypted).not.toBeNull();
        expect(decrypted!.amount.toString()).toBe('5000');
    });

    it('should encrypt and decrypt a UTXO for a third party', async () => {
        // Recipient Setup
        const recipientUtxoPrivateKey = encryptionServiceReceiver.getUtxoPrivateKeyV2();
        const recipientUtxoKeypair = new UtxoKeypair(recipientUtxoPrivateKey, lightWasm);
        const recipientPublicUtxoKey = recipientUtxoKeypair.pubkey;
        const recipientAsymmetricPubKey = encryptionServiceReceiver.getAsymmetricPublicKey();

        // Sender creates a UTXO destined for Recipient
        // Sender DOES NOT have recipientUtxoPrivateKey.
        // Sender only has recipientPublicUtxoKey.

        const utxoForRecipient = new Utxo({
            lightWasm,
            amount: '1000',
            publicKey: recipientPublicUtxoKey, // Using the new functionality we added
            index: 10
        });

        // Verify Utxo was created correctly
        expect(utxoForRecipient.pubkey.toString()).toBe(recipientPublicUtxoKey.toString());
        expect(utxoForRecipient.keypair).toBeUndefined(); // Should not have private key

        // Sender Encrypts UTXO for Recipient
        const encryptedUtxo = encryptionServiceSender.encryptUtxo(utxoForRecipient, recipientAsymmetricPubKey);

        // Verify it's V3
        expect(encryptionServiceReceiver.getEncryptionKeyVersion(encryptedUtxo)).toBe('v3');

        // Recipient Decrypts
        const decryptedUtxo = await encryptionServiceReceiver.decryptUtxo(encryptedUtxo, lightWasm);

        // Verification - decryptUtxo can return null for schema version mismatch, but should succeed here
        expect(decryptedUtxo).not.toBeNull();
        expect(decryptedUtxo!.amount.toString()).toBe('1000');
        expect(decryptedUtxo!.index).toBe(10);
        // Important: Decrypted UTXO should have the private key derived from the receiver's service!
        // The `decryptUtxo` function uses `this.getUtxoPrivateKeyWithVersion('v2')` internally.
        expect(decryptedUtxo!.keypair).toBeDefined();
        expect(decryptedUtxo!.keypair!.pubkey.toString()).toBe(recipientPublicUtxoKey.toString());

        console.log("Third-party UTXO encryption/decryption cycle successful!");
    });
});
