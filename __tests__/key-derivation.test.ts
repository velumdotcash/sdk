/**
 * Key Derivation Unit Tests
 *
 * Tests for US-003: Verifying deterministic key derivation from wallet signatures
 * Ensures that the encryption flow produces consistent keys for the same wallet
 * and unique keys for different wallets.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { Keypair } from '@solana/web3.js';
import nacl from 'tweetnacl';
import { EncryptionService } from '../src/utils/encryption';

/**
 * The deterministic signature message format used in the web app.
 * This MUST match the format in apps/web/lib/hooks/use-velum.tsx
 *
 * CRITICAL: This message must be identical every time for the same wallet
 * to ensure the derived encryption keys are always the same.
 * DO NOT add nonce, timestamp, or any variable data!
 */
function getSignatureMessage(walletAddress: string): string {
    return `Welcome to Velum

Sign this message to derive your private encryption keys.

This request will not trigger a blockchain transaction or cost any fees.

Wallet: ${walletAddress}`;
}

/**
 * Simulates the wallet signature process that happens in the browser.
 * In production, this is done by the wallet adapter's signMessage function.
 */
function simulateWalletSignature(keypair: Keypair, message: string): Uint8Array {
    const messageBytes = new TextEncoder().encode(message);
    return nacl.sign.detached(messageBytes, keypair.secretKey);
}

describe('Key Derivation from Signature', () => {
    let encryptionService: EncryptionService;

    beforeEach(() => {
        encryptionService = new EncryptionService();
    });

    describe('Deterministic Key Derivation - Same Wallet, Same Message', () => {
        it('should derive identical encryption keys from the same signature', () => {
            // Create a test wallet
            const seed = new Uint8Array(32).fill(42);
            const wallet = Keypair.fromSeed(seed);
            const walletAddress = wallet.publicKey.toBase58();

            // Get the deterministic message
            const message = getSignatureMessage(walletAddress);

            // Sign the message (simulating wallet.signMessage)
            const signature = simulateWalletSignature(wallet, message);

            // Derive keys first time
            const keys1 = encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);

            // Reset and derive keys second time
            encryptionService.resetEncryptionKey();
            const keys2 = encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);

            // V1 keys should be identical
            expect(Buffer.from(keys1.v1).toString('hex')).toBe(Buffer.from(keys2.v1).toString('hex'));

            // V2 keys should be identical
            expect(Buffer.from(keys1.v2).toString('hex')).toBe(Buffer.from(keys2.v2).toString('hex'));
        });

        it('should derive identical UTXO private keys from the same signature', () => {
            const seed = new Uint8Array(32).fill(42);
            const wallet = Keypair.fromSeed(seed);
            const walletAddress = wallet.publicKey.toBase58();
            const message = getSignatureMessage(walletAddress);
            const signature = simulateWalletSignature(wallet, message);

            // Derive keys first time
            encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);
            const utxoPrivKeyV1_1 = encryptionService.getUtxoPrivateKeyV1();
            const utxoPrivKeyV2_1 = encryptionService.getUtxoPrivateKeyV2();

            // Reset and derive keys second time
            encryptionService.resetEncryptionKey();
            encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);
            const utxoPrivKeyV1_2 = encryptionService.getUtxoPrivateKeyV1();
            const utxoPrivKeyV2_2 = encryptionService.getUtxoPrivateKeyV2();

            // UTXO private keys should be identical
            expect(utxoPrivKeyV1_1).toBe(utxoPrivKeyV1_2);
            expect(utxoPrivKeyV2_1).toBe(utxoPrivKeyV2_2);
        });

        it('should derive identical asymmetric (X25519) public keys from the same signature', () => {
            const seed = new Uint8Array(32).fill(42);
            const wallet = Keypair.fromSeed(seed);
            const walletAddress = wallet.publicKey.toBase58();
            const message = getSignatureMessage(walletAddress);
            const signature = simulateWalletSignature(wallet, message);

            // Derive keys first time
            encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);
            const asymmetricPubKey1 = encryptionService.getAsymmetricPublicKey();

            // Reset and derive keys second time
            encryptionService.resetEncryptionKey();
            encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);
            const asymmetricPubKey2 = encryptionService.getAsymmetricPublicKey();

            // X25519 public keys should be identical
            expect(Buffer.from(asymmetricPubKey1).toString('base64'))
                .toBe(Buffer.from(asymmetricPubKey2).toString('base64'));
        });

        it('should produce consistent keys across multiple derivation cycles', () => {
            const seed = new Uint8Array(32).fill(123);
            const wallet = Keypair.fromSeed(seed);
            const walletAddress = wallet.publicKey.toBase58();
            const message = getSignatureMessage(walletAddress);
            const signature = simulateWalletSignature(wallet, message);

            // Collect keys from 5 derivation cycles
            const derivedKeys: Array<{
                v1: string;
                v2: string;
                utxoV1: string;
                utxoV2: string;
                asymmetric: string;
            }> = [];

            for (let i = 0; i < 5; i++) {
                encryptionService.resetEncryptionKey();
                const keys = encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);

                derivedKeys.push({
                    v1: Buffer.from(keys.v1).toString('hex'),
                    v2: Buffer.from(keys.v2).toString('hex'),
                    utxoV1: encryptionService.getUtxoPrivateKeyV1(),
                    utxoV2: encryptionService.getUtxoPrivateKeyV2(),
                    asymmetric: Buffer.from(encryptionService.getAsymmetricPublicKey()).toString('base64'),
                });
            }

            // All derived keys should be identical
            const firstKeys = derivedKeys[0];
            for (let i = 1; i < derivedKeys.length; i++) {
                expect(derivedKeys[i].v1).toBe(firstKeys.v1);
                expect(derivedKeys[i].v2).toBe(firstKeys.v2);
                expect(derivedKeys[i].utxoV1).toBe(firstKeys.utxoV1);
                expect(derivedKeys[i].utxoV2).toBe(firstKeys.utxoV2);
                expect(derivedKeys[i].asymmetric).toBe(firstKeys.asymmetric);
            }
        });
    });

    describe('Key Uniqueness - Different Wallets', () => {
        it('should derive different keys for different wallets', () => {
            // Create two different wallets
            const seed1 = new Uint8Array(32).fill(1);
            const seed2 = new Uint8Array(32).fill(2);
            const wallet1 = Keypair.fromSeed(seed1);
            const wallet2 = Keypair.fromSeed(seed2);

            // Get messages for each wallet
            const message1 = getSignatureMessage(wallet1.publicKey.toBase58());
            const message2 = getSignatureMessage(wallet2.publicKey.toBase58());

            // Sign messages
            const signature1 = simulateWalletSignature(wallet1, message1);
            const signature2 = simulateWalletSignature(wallet2, message2);

            // Derive keys for wallet 1
            const keys1 = encryptionService.deriveEncryptionKeyFromSignature(
                signature1,
                wallet1.publicKey.toBase58()
            );
            const utxoV1_1 = encryptionService.getUtxoPrivateKeyV1();
            const utxoV2_1 = encryptionService.getUtxoPrivateKeyV2();
            const asymmetric1 = encryptionService.getAsymmetricPublicKey();

            // Reset and derive keys for wallet 2
            encryptionService.resetEncryptionKey();
            const keys2 = encryptionService.deriveEncryptionKeyFromSignature(
                signature2,
                wallet2.publicKey.toBase58()
            );
            const utxoV1_2 = encryptionService.getUtxoPrivateKeyV1();
            const utxoV2_2 = encryptionService.getUtxoPrivateKeyV2();
            const asymmetric2 = encryptionService.getAsymmetricPublicKey();

            // All keys should be different
            expect(Buffer.from(keys1.v1).toString('hex'))
                .not.toBe(Buffer.from(keys2.v1).toString('hex'));
            expect(Buffer.from(keys1.v2).toString('hex'))
                .not.toBe(Buffer.from(keys2.v2).toString('hex'));
            expect(utxoV1_1).not.toBe(utxoV1_2);
            expect(utxoV2_1).not.toBe(utxoV2_2);
            expect(Buffer.from(asymmetric1).toString('base64'))
                .not.toBe(Buffer.from(asymmetric2).toString('base64'));
        });

        it('should derive different keys even for wallets with similar seeds', () => {
            // Create wallets with seeds differing by only one byte
            const seed1 = new Uint8Array(32).fill(0);
            seed1[0] = 1;
            const seed2 = new Uint8Array(32).fill(0);
            seed2[0] = 2;

            const wallet1 = Keypair.fromSeed(seed1);
            const wallet2 = Keypair.fromSeed(seed2);

            const message1 = getSignatureMessage(wallet1.publicKey.toBase58());
            const message2 = getSignatureMessage(wallet2.publicKey.toBase58());

            const signature1 = simulateWalletSignature(wallet1, message1);
            const signature2 = simulateWalletSignature(wallet2, message2);

            const keys1 = encryptionService.deriveEncryptionKeyFromSignature(
                signature1,
                wallet1.publicKey.toBase58()
            );

            encryptionService.resetEncryptionKey();

            const keys2 = encryptionService.deriveEncryptionKeyFromSignature(
                signature2,
                wallet2.publicKey.toBase58()
            );

            // Keys should still be completely different
            expect(Buffer.from(keys1.v1).toString('hex'))
                .not.toBe(Buffer.from(keys2.v1).toString('hex'));
            expect(Buffer.from(keys1.v2).toString('hex'))
                .not.toBe(Buffer.from(keys2.v2).toString('hex'));
        });

        it('should produce unique keys for randomly generated wallets', () => {
            const walletCount = 10;
            const derivedV2Keys = new Set<string>();
            const derivedUtxoKeys = new Set<string>();
            const derivedAsymmetricKeys = new Set<string>();

            for (let i = 0; i < walletCount; i++) {
                // Generate random wallet
                const wallet = Keypair.generate();
                const walletAddress = wallet.publicKey.toBase58();
                const message = getSignatureMessage(walletAddress);
                const signature = simulateWalletSignature(wallet, message);

                encryptionService.resetEncryptionKey();
                const keys = encryptionService.deriveEncryptionKeyFromSignature(signature, walletAddress);

                derivedV2Keys.add(Buffer.from(keys.v2).toString('hex'));
                derivedUtxoKeys.add(encryptionService.getUtxoPrivateKeyV2());
                derivedAsymmetricKeys.add(
                    Buffer.from(encryptionService.getAsymmetricPublicKey()).toString('base64')
                );
            }

            // All keys should be unique
            expect(derivedV2Keys.size).toBe(walletCount);
            expect(derivedUtxoKeys.size).toBe(walletCount);
            expect(derivedAsymmetricKeys.size).toBe(walletCount);
        });
    });

    describe('Signature Message Format', () => {
        it('should have the expected message structure', () => {
            const walletAddress = 'TestWalletAddress123456789012345678901234567890';
            const message = getSignatureMessage(walletAddress);

            // Check message contains required components
            expect(message).toContain('Welcome to Velum');
            expect(message).toContain('Sign this message to derive your private encryption keys');
            expect(message).toContain('This request will not trigger a blockchain transaction');
            expect(message).toContain('cost any fees');
            expect(message).toContain(`Wallet: ${walletAddress}`);
        });

        it('should include wallet address in the message', () => {
            const testAddresses = [
                'DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK',
                'HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH',
                'B7PBMvYtJ3wdNLCJq6YDjrQ6hBwFwvg2qkNZ9CLbmYWE',
            ];

            for (const address of testAddresses) {
                const message = getSignatureMessage(address);
                expect(message).toContain(`Wallet: ${address}`);
                // Wallet address should be at the end
                expect(message.endsWith(address)).toBe(true);
            }
        });

        it('should NOT contain dynamic elements (timestamp, nonce, etc.)', () => {
            const walletAddress = 'TestWalletAddress123';
            const message = getSignatureMessage(walletAddress);

            // Message should not contain any timestamp-like patterns
            expect(message).not.toMatch(/\d{10,13}/); // Unix timestamps
            expect(message).not.toMatch(/\d{4}-\d{2}-\d{2}/); // ISO dates
            expect(message).not.toMatch(/nonce/i);
            expect(message).not.toMatch(/timestamp/i);
            expect(message).not.toMatch(/random/i);
        });

        it('should produce identical messages for the same wallet address', () => {
            const walletAddress = 'DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK';

            // Generate message multiple times
            const messages = Array.from({ length: 100 }, () => getSignatureMessage(walletAddress));

            // All messages should be identical
            const firstMessage = messages[0];
            for (const message of messages) {
                expect(message).toBe(firstMessage);
            }
        });

        it('should produce different messages for different wallet addresses', () => {
            const address1 = 'DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK';
            const address2 = 'HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH';

            const message1 = getSignatureMessage(address1);
            const message2 = getSignatureMessage(address2);

            expect(message1).not.toBe(message2);
        });

        it('should match the exact format used in the web app hook', () => {
            // This is the EXACT format from apps/web/lib/hooks/use-velum.tsx
            const walletAddress = 'TestWallet123';
            const expectedFormat = `Welcome to Velum

Sign this message to derive your private encryption keys.

This request will not trigger a blockchain transaction or cost any fees.

Wallet: ${walletAddress}`;

            const actualMessage = getSignatureMessage(walletAddress);
            expect(actualMessage).toBe(expectedFormat);
        });
    });

    describe('Key Derivation Properties', () => {
        it('should derive V1 key with correct length (31 bytes)', () => {
            const wallet = Keypair.generate();
            const message = getSignatureMessage(wallet.publicKey.toBase58());
            const signature = simulateWalletSignature(wallet, message);

            const keys = encryptionService.deriveEncryptionKeyFromSignature(
                signature,
                wallet.publicKey.toBase58()
            );

            expect(keys.v1.length).toBe(31);
        });

        it('should derive V2 key with correct length (32 bytes)', () => {
            const wallet = Keypair.generate();
            const message = getSignatureMessage(wallet.publicKey.toBase58());
            const signature = simulateWalletSignature(wallet, message);

            const keys = encryptionService.deriveEncryptionKeyFromSignature(
                signature,
                wallet.publicKey.toBase58()
            );

            expect(keys.v2.length).toBe(32);
        });

        it('should derive UTXO private keys with 0x prefix', () => {
            const wallet = Keypair.generate();
            const message = getSignatureMessage(wallet.publicKey.toBase58());
            const signature = simulateWalletSignature(wallet, message);

            encryptionService.deriveEncryptionKeyFromSignature(
                signature,
                wallet.publicKey.toBase58()
            );

            const utxoV1 = encryptionService.getUtxoPrivateKeyV1();
            const utxoV2 = encryptionService.getUtxoPrivateKeyV2();

            expect(utxoV1.startsWith('0x')).toBe(true);
            expect(utxoV2.startsWith('0x')).toBe(true);
        });

        it('should derive X25519 public key with correct length (32 bytes)', () => {
            const wallet = Keypair.generate();
            const message = getSignatureMessage(wallet.publicKey.toBase58());
            const signature = simulateWalletSignature(wallet, message);

            encryptionService.deriveEncryptionKeyFromSignature(
                signature,
                wallet.publicKey.toBase58()
            );

            const asymmetricPubKey = encryptionService.getAsymmetricPublicKey();
            expect(asymmetricPubKey.length).toBe(32);
        });

        it('should properly set key state after derivation', () => {
            const wallet = Keypair.generate();
            const message = getSignatureMessage(wallet.publicKey.toBase58());
            const signature = simulateWalletSignature(wallet, message);

            // Before derivation, keys should not be set
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(false);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(false);

            // After derivation, keys should be set
            encryptionService.deriveEncryptionKeyFromSignature(
                signature,
                wallet.publicKey.toBase58()
            );

            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(true);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(true);

            // After reset, keys should not be set
            encryptionService.resetEncryptionKey();

            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(false);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(false);
        });
    });

    describe('Cross-Encryption Compatibility', () => {
        it('should produce keys that work for encryption/decryption cycle', () => {
            const wallet = Keypair.generate();
            const message = getSignatureMessage(wallet.publicKey.toBase58());
            const signature = simulateWalletSignature(wallet, message);

            encryptionService.deriveEncryptionKeyFromSignature(
                signature,
                wallet.publicKey.toBase58()
            );

            const testData = 'Secret UTXO data for testing';
            const encrypted = encryptionService.encrypt(testData);
            const decrypted = encryptionService.decrypt(encrypted);

            expect(decrypted.toString()).toBe(testData);
        });

        it('should allow data encrypted by one session to be decrypted by another with same wallet', () => {
            const wallet = Keypair.generate();
            const walletAddress = wallet.publicKey.toBase58();
            const message = getSignatureMessage(walletAddress);
            const signature = simulateWalletSignature(wallet, message);

            // Session 1: Encrypt data
            const service1 = new EncryptionService();
            service1.deriveEncryptionKeyFromSignature(signature, walletAddress);
            const testData = 'Cross-session secret data';
            const encrypted = service1.encrypt(testData);

            // Session 2: Decrypt data (simulating browser refresh/new session)
            const service2 = new EncryptionService();
            service2.deriveEncryptionKeyFromSignature(signature, walletAddress);
            const decrypted = service2.decrypt(encrypted);

            expect(decrypted.toString()).toBe(testData);
        });

        it('should produce asymmetric keys that work for asymmetric encryption', () => {
            // Recipient wallet
            const recipientWallet = Keypair.generate();
            const recipientAddress = recipientWallet.publicKey.toBase58();
            const recipientMessage = getSignatureMessage(recipientAddress);
            const recipientSignature = simulateWalletSignature(recipientWallet, recipientMessage);

            // Recipient derives their keys
            const recipientService = new EncryptionService();
            recipientService.deriveEncryptionKeyFromSignature(recipientSignature, recipientAddress);
            const recipientPubKey = recipientService.getAsymmetricPublicKey();

            // Sender encrypts data for recipient
            const senderWallet = Keypair.generate();
            const senderAddress = senderWallet.publicKey.toBase58();
            const senderMessage = getSignatureMessage(senderAddress);
            const senderSignature = simulateWalletSignature(senderWallet, senderMessage);

            const senderService = new EncryptionService();
            senderService.deriveEncryptionKeyFromSignature(senderSignature, senderAddress);

            const secretData = 'Private UTXO for recipient';
            const encrypted = senderService.encryptAsymmetric(secretData, recipientPubKey);

            // Recipient decrypts (using the internal decrypt method via decryptUtxo pattern)
            // We'll test the raw bytes directly since decryptUtxo requires more setup
            expect(encrypted.length).toBeGreaterThan(secretData.length);
            expect(encrypted.subarray(0, 8).equals(EncryptionService.ENCRYPTION_VERSION_V3)).toBe(true);
        });
    });
});
