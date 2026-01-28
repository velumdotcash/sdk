import { Keypair, PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { gcm, ctr } from '@noble/ciphers/aes';
import { Utxo } from '../models/utxo.js';
import { WasmFactory } from '@lightprotocol/hasher.rs';
import { Keypair as UtxoKeypair } from '../models/keypair.js';
import { keccak256 } from '@ethersproject/keccak256';
import { PROGRAM_ID, TRANSACT_IX_DISCRIMINATOR, TRANSACT_SPL_IX_DISCRIMINATOR } from './constants.js';
import BN from 'bn.js';
import { debugLogger, hashForLog, bytesInfo } from './debug-logger.js';


/**
 * Represents a UTXO with minimal required fields
 */
export interface UtxoData {
  amount: string;
  blinding: string;
  index: number | string;
  // Optional additional fields
  [key: string]: any;
}

export interface EncryptionKey {
  v1: Uint8Array;
  v2: Uint8Array;
}

/**
 * Service for handling encryption and decryption of UTXO data
 */
export class EncryptionService {
  // Version identifier for encryption scheme (8-byte version)
  public static readonly ENCRYPTION_VERSION_V2 = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]); // Version 2
  public static readonly ENCRYPTION_VERSION_V3 = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]); // Version 3 (Asymmetric)

  // Signature schema version - identifies the signature message format and encryption format
  // Version 0x01: Original format without recipient ID
  // Version 0x02: New format with recipient ID hash for O(1) early termination
  public static readonly SIGNATURE_SCHEMA_VERSION = Buffer.from([0x02]); // Schema version 2

  // Compact encryption tags — single byte replaces 8-byte version + 1-byte schema
  // Uses high bytes (0xC2/0xC3) to avoid collision with legacy V1 random IV bytes
  public static readonly COMPACT_V2_TAG = 0xC2; // Compact symmetric (AES-256-GCM)
  public static readonly COMPACT_V3_TAG = 0xC3; // Compact asymmetric (nacl.box)

  // Length of recipient ID hash in bytes (first 8 bytes of SHA256(X25519 public key))
  public static readonly RECIPIENT_ID_LENGTH = 8;

  private encryptionKeyV1: Uint8Array | null = null;
  private encryptionKeyV2: Uint8Array | null = null;
  private asymmetricSecretKey: Uint8Array | null = null; // X25519 Secret Key
  private utxoPrivateKeyV1: string | null = null;
  private utxoPrivateKeyV2: string | null = null;
  private walletAddress: string | null = null; // Wallet address for key derivation logging

  /**
 * Generate an encryption key from a signature
 * @param signature The user's signature
 * @param walletAddress Optional wallet address for logging/verification
 * @returns The generated encryption key
 */
  public deriveEncryptionKeyFromSignature(signature: Uint8Array, walletAddress?: string): EncryptionKey {
    // Store wallet address for logging
    if (walletAddress) {
      this.walletAddress = walletAddress;
      debugLogger.walletKeyDerivation(walletAddress, 'derive');
    }

    debugLogger.keyDerivation('START', hashForLog(signature), 'wallet_signature');

    // Extract the first 31 bytes of the signature to create a deterministic key (legacy method)
    const encryptionKeyV1 = signature.slice(0, 31);

    // Store the V1 key in the service
    this.encryptionKeyV1 = encryptionKeyV1;
    debugLogger.keyDerivation('V1_KEY_DERIVED', hashForLog(encryptionKeyV1), 'encryption_key_v1');

    // Precompute and cache the UTXO private key
    const hashedSeedV1 = sha256(encryptionKeyV1);
    this.utxoPrivateKeyV1 = '0x' + Buffer.from(hashedSeedV1).toString('hex');
    debugLogger.keyDerivation('V1_UTXO_PRIVATE_KEY', hashForLog(hashedSeedV1), 'utxo_private_key_v1');

    // Use Keccak256 to derive a full 32-byte encryption key from the signature
    const encryptionKeyV2 = Buffer.from(keccak256(signature).slice(2), 'hex');

    // Store the V2 key in the service
    this.encryptionKeyV2 = encryptionKeyV2;
    debugLogger.keyDerivation('V2_KEY_DERIVED', hashForLog(encryptionKeyV2), 'encryption_key_v2');

    // Derive asymmetric key from V2 key (deterministic)
    // We use the first 32 bytes of a hash of the V2 key as the seed for the X25519 keypair
    const asymmetricSeed = sha256(encryptionKeyV2);
    debugLogger.keyDerivation('ASYMMETRIC_SEED', hashForLog(asymmetricSeed), 'x25519_seed');

    const keypair = nacl.box.keyPair.fromSecretKey(asymmetricSeed);
    this.asymmetricSecretKey = keypair.secretKey;
    debugLogger.asymmetricKeyGenerated(hashForLog(keypair.publicKey), hashForLog(keypair.secretKey));

    // Log X25519 public key derivation with wallet address for sender/recipient verification
    const walletAddr = this.walletAddress || '<unknown>';
    debugLogger.x25519KeyDerived(hashForLog(keypair.publicKey), walletAddr, 'recipient');

    // Precompute and cache the UTXO private key
    const hashedSeedV2 = Buffer.from(keccak256(encryptionKeyV2).slice(2), 'hex');
    this.utxoPrivateKeyV2 = '0x' + hashedSeedV2.toString('hex');
    debugLogger.keyDerivation('V2_UTXO_PRIVATE_KEY', hashForLog(hashedSeedV2), 'utxo_private_key_v2');

    debugLogger.serviceInitialized(!!this.encryptionKeyV1, !!this.encryptionKeyV2, !!this.asymmetricSecretKey);

    return {
      v1: this.encryptionKeyV1,
      v2: this.encryptionKeyV2
    };

  }

  /**
   * Generate an encryption key from a wallet keypair (V2 format)
   * @param keypair The Solana keypair to derive the encryption key from
   * @returns The generated encryption key
   */
  public deriveEncryptionKeyFromWallet(keypair: Keypair): EncryptionKey {
    // Sign a constant message with the keypair
    const message = Buffer.from('Privacy Money account sign in');
    const signature = nacl.sign.detached(message, keypair.secretKey);
    // Pass wallet address for logging
    return this.deriveEncryptionKeyFromSignature(signature, keypair.publicKey.toBase58())
  }

  /**
   * Get the Asymmetric Public Key (X25519) derived from the encryption key
   */
  public getAsymmetricPublicKey(): Uint8Array {
    if (!this.asymmetricSecretKey) {
       throw new Error('Asymmetric key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }
    return nacl.box.keyPair.fromSecretKey(this.asymmetricSecretKey).publicKey;
  }

  /**
   * Derive recipient ID hash from X25519 public key
   * Used for O(1) early termination during UTXO decryption
   * @param publicKey Optional X25519 public key. If not provided, uses own public key.
   * @returns First 8 bytes of SHA256(publicKey)
   */
  public deriveRecipientIdHash(publicKey?: Uint8Array): Buffer {
    const key = publicKey || this.getAsymmetricPublicKey();
    const hash = sha256(key);
    return Buffer.from(hash.slice(0, EncryptionService.RECIPIENT_ID_LENGTH));
  }

  /**
   * Check if encrypted data is for this wallet (O(1) operation)
   * Enables early termination without attempting expensive crypto decryption
   * @param encryptedBuffer The encrypted data buffer
   * @returns true if we should attempt decryption, false to skip
   */
  private shouldAttemptDecryption(encryptedBuffer: Buffer): boolean {
    // Compact format: [tag(1)][recipientIdHash(8)]...
    if (encryptedBuffer.length >= 9 &&
        (encryptedBuffer[0] === EncryptionService.COMPACT_V2_TAG || encryptedBuffer[0] === EncryptionService.COMPACT_V3_TAG)) {
      const storedRecipientId = encryptedBuffer.slice(1, 1 + EncryptionService.RECIPIENT_ID_LENGTH);
      const ourRecipientId = this.deriveRecipientIdHash();
      return storedRecipientId.equals(ourRecipientId);
    }

    // Minimum length for legacy format: version(8) + schema(1) + recipientId(8) = 17 bytes
    if (encryptedBuffer.length < 17) {
      // Too short for new format, let normal decryption handle it
      return true;
    }

    const schemaVersion = encryptedBuffer[8];

    // Old format (schema version 0x01 or less) - attempt decryption for backward compat
    if (schemaVersion < 0x02) {
      return true;
    }

    // Unknown future schema version (> 0x02) - reject
    if (schemaVersion > 0x02) {
      return false;
    }

    // Current format (schema version 0x02) - check recipient ID hash
    const storedRecipientId = encryptedBuffer.slice(9, 9 + EncryptionService.RECIPIENT_ID_LENGTH);
    const ourRecipientId = this.deriveRecipientIdHash();

    return storedRecipientId.equals(ourRecipientId);
  }

  /**
   * Encrypt data with the stored encryption key
   * @param data The data to encrypt
   * @returns The encrypted data as a Buffer
   * @throws Error if the encryption key has not been generated
   */
  public encrypt(data: Buffer | string): Buffer {
    if (!this.encryptionKeyV2) {
      throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }

    // Convert string to Buffer if needed
    const dataBuffer = typeof data === 'string' ? Buffer.from(data) : data;

    // Generate a standard initialization vector (12 bytes for GCM)
    const iv = nacl.randomBytes(12);

    // Use the full 32-byte V2 encryption key for AES-256
    const key = Buffer.from(this.encryptionKeyV2);

    // Use AES-256-GCM for authenticated encryption
    const stream = gcm(key, iv);
    const encryptedWithTag = stream.encrypt(dataBuffer);
    
    // Noble returns [ciphertext | authTag] (tag is last 16 bytes)
    const authTag = Buffer.from(encryptedWithTag.slice(-16));
    const encryptedData = Buffer.from(encryptedWithTag.slice(0, -16));

    // Derive recipient ID hash for O(1) early termination during decryption
    const recipientIdHash = this.deriveRecipientIdHash();

    // Version 2 format (schema 0x02): [version(8)] + [schemaVersion(1)] + [recipientIdHash(8)] + [IV(12)] + [authTag(16)] + [encryptedData]
    return Buffer.concat([
      EncryptionService.ENCRYPTION_VERSION_V2,
      EncryptionService.SIGNATURE_SCHEMA_VERSION,
      recipientIdHash,
      iv,
      authTag,
      encryptedData
    ]);
  }

  // v1 encryption, only used for testing now
  public encryptDecryptedDoNotUse(data: Buffer | string): Buffer {
    if (!this.encryptionKeyV1) {
      throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }

    // Convert string to Buffer if needed
    const dataBuffer = typeof data === 'string' ? Buffer.from(data) : data;

    // Generate a standard initialization vector (16 bytes)
    const iv = nacl.randomBytes(16);

    // Create a key from our encryption key (using only first 16 bytes for AES-128)
    const key = Buffer.from(this.encryptionKeyV1).slice(0, 16);

    // Use a more compact encryption algorithm (aes-128-ctr)
    const stream = ctr(key, iv);
    const encryptedData = Buffer.from(stream.encrypt(dataBuffer));

    // Create an authentication tag (HMAC) to verify decryption with correct key
    const hmacKey = Buffer.from(this.encryptionKeyV1).slice(16, 31);
    const authTag = Buffer.from(hmac(sha256, hmacKey, Buffer.concat([iv, encryptedData]))).slice(0, 16);

    // Combine IV, auth tag and encrypted data
    return Buffer.concat([iv, authTag, encryptedData]);
  }

  /**
   * Decrypt data with the stored encryption key
   * @param encryptedData The encrypted data to decrypt
   * @returns The decrypted data as a Buffer, or null if legacy format (no schema version byte)
   * @throws Error if the encryption key has not been generated or if the wrong key is used
   */
  public decrypt(encryptedData: Buffer): Buffer | null {
    // Check if this is the new version format (starts with 8-byte version identifier)
    if (encryptedData.length >= 8 && encryptedData.subarray(0, 8).equals(EncryptionService.ENCRYPTION_VERSION_V2)) {
      if (!this.encryptionKeyV2) {
        throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
      }
      return this.decryptV2(encryptedData);
    } else {
      // V1 format - need V1 key or keypair to derive it
      if (!this.encryptionKeyV1) {
        throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
      }
      return this.decryptV1(encryptedData);
    }
  }

  /**
   * Decrypt data using the old V1 format (120-bit HMAC with SHA256)
   * @param encryptedData The encrypted data to decrypt
   * @param keypair Optional keypair to derive V1 key for backward compatibility
   * @returns The decrypted data as a Buffer
   */
  private decryptV1(encryptedData: Buffer): Buffer {
    debugLogger.decryptionAttemptStart('V1', hashForLog(encryptedData), encryptedData.length);

    if (!this.encryptionKeyV1) {
      debugLogger.missingKey('encryptionKeyV1', 'V1 decryption');
      throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }

    // Extract the IV from the first 16 bytes
    const iv = encryptedData.slice(0, 16);
    // Extract the auth tag from the next 16 bytes
    const authTag = encryptedData.slice(16, 32);
    // The rest is the actual encrypted data
    const data = encryptedData.slice(32);

    // Verify the authentication tag
    const hmacKey = Buffer.from(this.encryptionKeyV1).slice(16, 31);
    const calculatedTag = Buffer.from(hmac(sha256, hmacKey, Buffer.concat([iv, data]))).slice(0, 16);

    // Compare tags - if they don't match, the key is wrong
    if (!this.timingSafeEqual(authTag, calculatedTag)) {
      debugLogger.decryptionFailure('V1', 'HMAC_MISMATCH', 'Authentication tag verification failed', {
        ivHash: hashForLog(iv),
        authTagHash: hashForLog(authTag),
        calculatedTagHash: hashForLog(calculatedTag)
      });
      throw new Error('Failed to decrypt data. Invalid encryption key or corrupted data.');
    }

    // Create a key from our encryption key (using only first 16 bytes for AES-128)
    const key = Buffer.from(this.encryptionKeyV1).slice(0, 16);

    // Use the same algorithm as in encrypt
    try {
      const stream = ctr(key, iv);
      const decrypted = Buffer.from(stream.decrypt(data));
      debugLogger.decryptionSuccess('V1', decrypted.length);
      return decrypted;
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error';
      debugLogger.decryptionFailure('V1', 'AES_CTR_FAILED', errMsg);
      throw new Error('Failed to decrypt data. Invalid encryption key or corrupted data.');
    }
  }
  
  // Custom timingSafeEqual for browser compatibility
  private timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  /**
   * Encrypt data using Asymmetric Encryption (X25519 + XSalsa20-Poly1305)
   * @param data The data to encrypt
   * @param recipientPublicKey The recipient's X25519 Public Key (must be exactly 32 bytes)
   */
  public encryptAsymmetric(data: Buffer | string, recipientPublicKey: Uint8Array): Buffer {
    // Validate X25519 public key length (must be exactly 32 bytes)
    if (!recipientPublicKey || recipientPublicKey.length !== 32) {
      throw new Error(
        `Invalid recipientPublicKey: X25519 public keys must be exactly 32 bytes, got ${recipientPublicKey?.length ?? 0}`
      );
    }

    const dataBuffer = typeof data === 'string' ? Buffer.from(data) : data;

    // Log the recipient's X25519 public key being used for encryption (sender side)
    debugLogger.x25519EncryptionKey(hashForLog(recipientPublicKey));

    // Generate ephemeral keypair
    const ephemeralKeypair = nacl.box.keyPair();

    // Generate nonce
    const nonce = nacl.randomBytes(nacl.box.nonceLength);

    // Encrypt
    const encrypted = nacl.box(dataBuffer, nonce, recipientPublicKey, ephemeralKeypair.secretKey);

    // Derive recipient ID hash from recipient's public key for O(1) early termination
    const recipientIdHash = this.deriveRecipientIdHash(recipientPublicKey);

    // Format (schema 0x02): [version(8)] + [schemaVersion(1)] + [recipientIdHash(8)] + [ephemeralPublicKey(32)] + [nonce(24)] + [encryptedData]
    return Buffer.concat([
        EncryptionService.ENCRYPTION_VERSION_V3,
        EncryptionService.SIGNATURE_SCHEMA_VERSION,
        recipientIdHash,
        ephemeralKeypair.publicKey,
        nonce,
        encrypted
    ]);
  }

  /**
   * Decrypt data using Asymmetric Encryption
   * @returns Buffer on success, null if legacy format (no schema version byte) - these are skipped
   */
  private decryptV3(encryptedData: Buffer): Buffer | null {
    debugLogger.decryptionAttemptStart('V3', hashForLog(encryptedData), encryptedData.length);

    if (!this.asymmetricSecretKey) {
        debugLogger.missingKey('asymmetricSecretKey', 'V3 decryption');
        throw new Error('Asymmetric secret key not set.');
    }

    // Log the derived X25519 public key (recipient side) for verification
    const derivedPublicKey = nacl.box.keyPair.fromSecretKey(this.asymmetricSecretKey).publicKey;
    debugLogger.x25519DecryptionKey(hashForLog(derivedPublicKey));

    // Check schema version byte at position 8
    const schemaVersion = encryptedData.length >= 9 ? encryptedData[8] : 0;

    // Skip very old format UTXOs (no schema version)
    if (schemaVersion < 0x01) {
      debugLogger.decryptionFailure('V3', 'LEGACY_FORMAT_SKIPPED', 'Very old format UTXO without schema version byte - skipping', {
        dataLength: encryptedData.length,
        byte8Value: schemaVersion
      });
      return null;
    }

    // Determine byte offsets based on schema version
    // Schema 0x01: [version(8)] + [schema(1)] + [ephemeralPubKey(32)] + [nonce(24)] + [encrypted]
    // Schema 0x02: [version(8)] + [schema(1)] + [recipientIdHash(8)] + [ephemeralPubKey(32)] + [nonce(24)] + [encrypted]
    let ephemeralKeyStart: number, ephemeralKeyEnd: number, nonceStart: number, nonceEnd: number, boxStart: number;

    if (schemaVersion >= 0x02) {
      // New format with recipient ID hash (8 bytes)
      ephemeralKeyStart = 9 + EncryptionService.RECIPIENT_ID_LENGTH;  // 17
      ephemeralKeyEnd = ephemeralKeyStart + 32;                        // 49
      nonceStart = ephemeralKeyEnd;                                    // 49
      nonceEnd = nonceStart + 24;                                      // 73
      boxStart = nonceEnd;                                             // 73
    } else {
      // Old format (schema 0x01) without recipient ID hash
      ephemeralKeyStart = 9;
      ephemeralKeyEnd = 41;
      nonceStart = 41;
      nonceEnd = 65;
      boxStart = 65;
    }

    const ephemeralPublicKey = encryptedData.slice(ephemeralKeyStart, ephemeralKeyEnd);
    const nonce = encryptedData.slice(nonceStart, nonceEnd);
    const box = encryptedData.slice(boxStart);

    debugLogger.v3DecryptionDetails(
      hashForLog(ephemeralPublicKey),
      hashForLog(nonce),
      box.length,
      hashForLog(this.asymmetricSecretKey)
    );

    const decrypted = nacl.box.open(box, nonce, ephemeralPublicKey, this.asymmetricSecretKey);

    if (!decrypted) {
        // Log key mismatch details for debugging
        const derivedPubKeyHash = hashForLog(derivedPublicKey);
        debugLogger.x25519KeyMismatch(
          '<encrypted_for_different_key>',
          derivedPubKeyHash,
          this.walletAddress || undefined
        );
        debugLogger.decryptionFailure('V3', 'NACL_BOX_OPEN_FAILED', 'nacl.box.open returned null - key mismatch or corrupted data', {
          ephemeralPubKeyHash: hashForLog(ephemeralPublicKey),
          nonceHash: hashForLog(nonce),
          boxLength: box.length,
          secretKeyHash: hashForLog(this.asymmetricSecretKey),
          derivedPublicKeyHash: derivedPubKeyHash,
          walletAddress: this.walletAddress || '<unknown>',
          schemaVersion
        });
        throw new Error('Failed to decrypt asymmetric data');
    }

    debugLogger.decryptionSuccess('V3', decrypted.length);
    return Buffer.from(decrypted);
  }

  /**
   * Decrypt data using the new V2 format (256-bit Keccak HMAC)
   * @param encryptedData The encrypted data to decrypt
   * @returns The decrypted data as a Buffer, or null if legacy format (no schema version byte) - these are skipped
   */
  private decryptV2(encryptedData: Buffer): Buffer | null {
    debugLogger.decryptionAttemptStart('V2', hashForLog(encryptedData), encryptedData.length);

    if (!this.encryptionKeyV2) {
      debugLogger.missingKey('encryptionKeyV2', 'V2 decryption');
      throw new Error('encryptionKeyV2 not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }

    // Check schema version byte at position 8
    const schemaVersion = encryptedData.length >= 9 ? encryptedData[8] : 0;

    // Skip very old format UTXOs (no schema version)
    if (schemaVersion < 0x01) {
      debugLogger.decryptionFailure('V2', 'LEGACY_FORMAT_SKIPPED', 'Very old format UTXO without schema version byte - skipping', {
        dataLength: encryptedData.length,
        byte8Value: schemaVersion
      });
      return null;
    }

    // Determine byte offsets based on schema version
    // Schema 0x01: [version(8)] + [schema(1)] + [IV(12)] + [authTag(16)] + [encrypted]
    // Schema 0x02: [version(8)] + [schema(1)] + [recipientIdHash(8)] + [IV(12)] + [authTag(16)] + [encrypted]
    let ivStart: number, ivEnd: number, authTagStart: number, authTagEnd: number, dataStart: number;

    if (schemaVersion >= 0x02) {
      // New format with recipient ID hash (8 bytes)
      ivStart = 9 + EncryptionService.RECIPIENT_ID_LENGTH;  // 17
      ivEnd = ivStart + 12;                                  // 29
      authTagStart = ivEnd;                                  // 29
      authTagEnd = authTagStart + 16;                        // 45
      dataStart = authTagEnd;                                // 45
    } else {
      // Old format (schema 0x01) without recipient ID hash
      ivStart = 9;
      ivEnd = 21;
      authTagStart = 21;
      authTagEnd = 37;
      dataStart = 37;
    }

    const iv = encryptedData.slice(ivStart, ivEnd);
    const authTag = encryptedData.slice(authTagStart, authTagEnd);
    const data = encryptedData.slice(dataStart);

    // Use the full 32-byte V2 encryption key for AES-256
    const key = Buffer.from(this.encryptionKeyV2!);

    // Use AES-256-GCM for authenticated decryption
    // Noble ciphers expects ciphertext + authTag
    const ciphertextWithTag = Buffer.concat([data, authTag]);

    try {
      const stream = gcm(key, iv);
      const decrypted = Buffer.from(stream.decrypt(ciphertextWithTag));
      debugLogger.decryptionSuccess('V2', decrypted.length);
      return decrypted;
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error';
      debugLogger.decryptionFailure('V2', 'AES_GCM_FAILED', errMsg, {
        ivHash: hashForLog(iv),
        authTagHash: hashForLog(authTag),
        dataLength: data.length,
        schemaVersion
      });
      throw new Error('Failed to decrypt data. Invalid encryption key or corrupted data.');
    }
  }

  /**
   * Reset the encryption keys (mainly for testing purposes)
   */
  public resetEncryptionKey(): void {
    this.encryptionKeyV1 = null;
    this.encryptionKeyV2 = null;
    this.asymmetricSecretKey = null;
    this.utxoPrivateKeyV1 = null;
    this.utxoPrivateKeyV2 = null;
    this.walletAddress = null;
  }

  /**
   * Encrypt a UTXO using compact binary v2 encoding and compact encryption headers.
   * Plaintext: 45-byte binary [0x02][amount:8][blinding:32][index:4] (no mintAddress)
   * Encryption: compact V2 (0xC2 tag, AES-GCM) or compact V3 (0xC3 tag, NaCl Box)
   * @param utxo The UTXO to encrypt (includes version property)
   * @param recipientEncryptionKey Optional recipient X25519 public key for asymmetric encryption
   * @returns The encrypted UTXO data as a Buffer
   * @throws Error if the V2 encryption key has not been set
   */
  // Binary format flags for compact UTXO encoding
  private static readonly BINARY_UTXO_FLAG = 0x01;
  private static readonly BINARY_UTXO_LENGTH = 77; // 1 + 8 + 32 + 4 + 32 (v1, with mintAddress)
  private static readonly BINARY_UTXO_V2_FLAG = 0x02;
  private static readonly BINARY_UTXO_V2_LENGTH = 45; // 1 + 8 + 32 + 4 (v2, no mintAddress)

  public encryptUtxo(utxo: Utxo, recipientEncryptionKey?: Uint8Array): Buffer {
    if (!this.encryptionKeyV2) {
      throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }

    // Compact binary v2 encoding: [0x02][amount:8 BE][blinding:32 BE][index:4 BE]
    // 45 bytes total — drops mintAddress (caller provides it from Merkle tree context)
    // Saves 32 bytes per output (64 total) vs v1, clearing the 61-byte tx size overrun
    const buf = Buffer.alloc(EncryptionService.BINARY_UTXO_V2_LENGTH);
    buf[0] = EncryptionService.BINARY_UTXO_V2_FLAG;

    // Convert via toString() to support both BN instances and plain objects
    const amountBN = new BN(utxo.amount.toString());
    const blindingBN = new BN(utxo.blinding.toString());

    // Amount: 8 bytes big-endian
    Buffer.from(amountBN.toArray('be', 8)).copy(buf, 1);

    // Blinding: 32 bytes big-endian
    Buffer.from(blindingBN.toArray('be', 32)).copy(buf, 9);

    // Index: 4 bytes big-endian (uint32)
    buf.writeUInt32BE(utxo.index, 41);

    // Use compact encryption headers (1-byte tag instead of 9-byte version+schema)
    // Saves 8 bytes per output (16 total) to keep SPL paylink deposits in one tx
    if (recipientEncryptionKey) {
        return this.encryptUtxoCompactV3(buf, recipientEncryptionKey);
    }
    return this.encryptUtxoCompactV2(buf);
  }

  /**
   * Compact V2 symmetric encryption: [0xC2][recipientIdHash(8)][IV(12)][authTag(16)][ciphertext]
   * Saves 8 bytes vs standard V2 format by using 1-byte tag instead of 8-byte version + 1-byte schema
   */
  private encryptUtxoCompactV2(data: Buffer): Buffer {
    const key = Buffer.from(this.encryptionKeyV2!);
    const iv = nacl.randomBytes(12);
    const stream = gcm(key, iv);
    const encryptedWithTag = stream.encrypt(data);
    const authTag = Buffer.from(encryptedWithTag.slice(-16));
    const ciphertext = Buffer.from(encryptedWithTag.slice(0, -16));
    const recipientIdHash = this.deriveRecipientIdHash();

    return Buffer.concat([
      Buffer.from([EncryptionService.COMPACT_V2_TAG]),
      recipientIdHash,
      iv,
      authTag,
      ciphertext
    ]);
  }

  /**
   * Compact V3 asymmetric encryption: [0xC3][recipientIdHash(8)][ephemeralPK(32)][nonce(24)][ciphertext+MAC]
   * Saves 8 bytes vs standard V3 format by using 1-byte tag instead of 8-byte version + 1-byte schema
   */
  private encryptUtxoCompactV3(data: Buffer, recipientPublicKey: Uint8Array): Buffer {
    if (!recipientPublicKey || recipientPublicKey.length !== 32) {
      throw new Error(`Invalid recipientPublicKey: X25519 keys must be exactly 32 bytes, got ${recipientPublicKey?.length ?? 0}`);
    }
    const ephemeralKeypair = nacl.box.keyPair();
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const encrypted = nacl.box(data, nonce, recipientPublicKey, ephemeralKeypair.secretKey);
    const recipientIdHash = this.deriveRecipientIdHash(recipientPublicKey);

    return Buffer.concat([
      Buffer.from([EncryptionService.COMPACT_V3_TAG]),
      recipientIdHash,
      ephemeralKeypair.publicKey,
      nonce,
      encrypted
    ]);
  }

  // Deprecated, only used for testing now
  public encryptUtxoDecryptedDoNotUse(utxo: Utxo): Buffer {
    if (!this.encryptionKeyV2) {
      throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }

    const utxoString = `${utxo.amount.toString()}|${utxo.blinding.toString()}|${utxo.index}|${utxo.mintAddress}`;

    return this.encryptDecryptedDoNotUse(utxoString);
  }

  public getEncryptionKeyVersion(encryptedData: Buffer | string): 'v1' | 'v2' | 'v3' {
    const buffer = typeof encryptedData === 'string' ? Buffer.from(encryptedData, 'hex') : encryptedData;
    const dataHash = hashForLog(buffer);

    // Check compact format tags first (single byte at position 0)
    if (buffer.length >= 1) {
      if (buffer[0] === EncryptionService.COMPACT_V2_TAG) {
        debugLogger.versionDetected(dataHash, 'v2', buffer.length);
        return 'v2';
      }
      if (buffer[0] === EncryptionService.COMPACT_V3_TAG) {
        debugLogger.versionDetected(dataHash, 'v3', buffer.length);
        return 'v3';
      }
    }

    // Log the first 8 bytes (version prefix) for debugging
    const prefixBytes = buffer.length >= 8 ? buffer.subarray(0, 8) : buffer;
    const prefixHex = Buffer.from(prefixBytes).toString('hex');
    debugLogger.versionPrefixBytes(prefixHex, buffer.length);

    let version: 'v1' | 'v2' | 'v3';
    if (buffer.length >= 8 && buffer.subarray(0, 8).equals(EncryptionService.ENCRYPTION_VERSION_V2)) {
      // V2 encryption format → V2 UTXO
      version = 'v2';
    } else if (buffer.length >= 8 && buffer.subarray(0, 8).equals(EncryptionService.ENCRYPTION_VERSION_V3)) {
      version = 'v3';
    } else {
      // V1 encryption format → UTXO (legacy mode fallback)
      version = 'v1';
      const reason = buffer.length < 8
        ? `Data too short (${buffer.length} bytes) to contain version prefix`
        : `Unrecognized version prefix: ${prefixHex}`;
      debugLogger.versionFallbackToLegacy(prefixHex, reason);
    }

    debugLogger.versionDetected(dataHash, version, buffer.length);
    return version;
  }

  /**
   * Check if the schema version at byte 9 matches the expected version.
   * Returns null if schema version matches or data is legacy format (no schema version).
   * Returns the found schema version if it doesn't match (for early termination).
   * @param encryptedBuffer The encrypted data buffer
   * @param encryptionVersion The encryption version (v1, v2, v3)
   * @returns null if schema version matches or is legacy, otherwise the mismatched version byte
   */
  private checkSchemaVersionMismatch(encryptedBuffer: Buffer, encryptionVersion: 'v1' | 'v2' | 'v3'): number | null {
    // V1 doesn't have schema version byte, skip check
    if (encryptionVersion === 'v1') {
      return null;
    }

    // Compact format has no separate schema version byte — tag encodes everything
    if (encryptedBuffer.length >= 1 &&
        (encryptedBuffer[0] === EncryptionService.COMPACT_V2_TAG || encryptedBuffer[0] === EncryptionService.COMPACT_V3_TAG)) {
      return null;
    }

    // Check if we have enough bytes to contain schema version
    if (encryptedBuffer.length < 9) {
      return null; // Too short, let decryption handle the error
    }

    const schemaVersionByte = encryptedBuffer[8];
    const expectedSchemaVersion = EncryptionService.SIGNATURE_SCHEMA_VERSION[0];

    // If schema version matches, proceed with decryption
    if (schemaVersionByte === expectedSchemaVersion) {
      return null;
    }

    // For early termination, we only skip if the schema version byte is clearly
    // a FUTURE schema version (greater than current). This maintains backward
    // compatibility with legacy data that doesn't have a schema version byte.
    //
    // Legacy format detection:
    // - Legacy V2/V3 data has IV or ephemeral pubkey bytes starting at position 8
    // - These are random/crypto bytes that could have any value
    // - We can't reliably distinguish legacy data from schema version bytes
    //
    // Conservative approach:
    // - Only skip if byte 8 > current schema version (clearly a future version)
    // - This handles the common case of different apps using different schema versions
    // - Legacy data (where byte 8 could be anything) will attempt decryption and fail naturally
    if (schemaVersionByte > expectedSchemaVersion) {
      return schemaVersionByte;
    }

    return null; // Assume legacy format or compatible version, attempt decryption
  }

  /**
   * Decrypt compact V2 format: [0xC2][recipientIdHash(8)][IV(12)][authTag(16)][ciphertext]
   */
  private decryptCompactV2(encryptedBuffer: Buffer): Buffer {
    if (!this.encryptionKeyV2) {
      throw new Error('encryptionKeyV2 not set.');
    }
    const iv = encryptedBuffer.slice(9, 21);
    const authTag = encryptedBuffer.slice(21, 37);
    const ciphertext = encryptedBuffer.slice(37);
    const key = Buffer.from(this.encryptionKeyV2);
    const ciphertextWithTag = Buffer.concat([ciphertext, authTag]);
    try {
      const stream = gcm(key, iv);
      return Buffer.from(stream.decrypt(ciphertextWithTag));
    } catch (error) {
      throw new Error('Failed to decrypt data. Invalid encryption key or corrupted data.');
    }
  }

  /**
   * Decrypt compact V3 format: [0xC3][recipientIdHash(8)][ephemeralPK(32)][nonce(24)][ciphertext+MAC]
   */
  private decryptCompactV3(encryptedBuffer: Buffer): Buffer {
    if (!this.asymmetricSecretKey) {
      throw new Error('Asymmetric secret key not set.');
    }
    const ephemeralPublicKey = encryptedBuffer.slice(9, 41);
    const nonce = encryptedBuffer.slice(41, 65);
    const box = encryptedBuffer.slice(65);
    const decrypted = nacl.box.open(box, nonce, ephemeralPublicKey, this.asymmetricSecretKey);
    if (!decrypted) {
      throw new Error('Failed to decrypt compact V3 data');
    }
    return Buffer.from(decrypted);
  }

  /**
   * Decrypt an encrypted UTXO and parse it to a Utxo instance.
   * Automatically detects the binary format: v2 (0x02, 45 bytes, no mint), v1 (0x01, 77 bytes, with mint), or legacy pipe-delimited text.
   * @param encryptedData The encrypted UTXO data
   * @param lightWasm Optional LightWasm instance. If not provided, a new one will be created
   * @param mintAddress Optional token mint address for binary v2 format (caller-provided from Merkle tree context). Defaults to system program for SOL UTXOs.
   * @returns Promise resolving to the decrypted Utxo instance, or null if schema version mismatch
   * @throws Error if the encryption key has not been set or if decryption fails
   */
  public async decryptUtxo(
    encryptedData: Buffer | string,
    lightWasm?: any,
    mintAddress?: string
  ): Promise<Utxo | null> {
    // Convert hex string to Buffer if needed
    const encryptedBuffer = typeof encryptedData === 'string'
      ? Buffer.from(encryptedData, 'hex')
      : encryptedData;

    // O(1) Early termination: Check recipient ID hash BEFORE any expensive operations
    // This is the fastest way to skip UTXOs that don't belong to this wallet
    if (!this.shouldAttemptDecryption(encryptedBuffer)) {
      debugLogger.recipientIdMismatch(hashForLog(encryptedBuffer));
      return null;
    }

    // Detect UTXO version based on encryption format
    let utxoVersion = this.getEncryptionKeyVersion(encryptedBuffer);
    const originalVersion = utxoVersion;

    // Skip V1 format entirely - V1 never had schema versions and is considered legacy
    // No backward compatibility needed for V1 format UTXOs
    if (utxoVersion === 'v1') {
      debugLogger.decryptionFailure('V1', 'LEGACY_FORMAT_SKIPPED', 'V1 format UTXO - skipping (no backward compatibility)');
      return null;
    }

    // Early termination: Check schema version at byte 9 BEFORE attempting decryption
    // This provides O(1) skip decision for UTXOs with incompatible schema versions
    const mismatchedSchemaVersion = this.checkSchemaVersionMismatch(encryptedBuffer, utxoVersion);
    if (mismatchedSchemaVersion !== null) {
      const expectedSchemaVersion = EncryptionService.SIGNATURE_SCHEMA_VERSION[0];
      debugLogger.schemaVersionMismatch(
        mismatchedSchemaVersion,
        expectedSchemaVersion,
        hashForLog(encryptedBuffer)
      );
      return null;
    }

    let decrypted: Buffer | null;

    // Compact format: single-byte tag at position 0
    const isCompactV2 = encryptedBuffer[0] === EncryptionService.COMPACT_V2_TAG;
    const isCompactV3 = encryptedBuffer[0] === EncryptionService.COMPACT_V3_TAG;

    if (isCompactV2) {
        decrypted = this.decryptCompactV2(encryptedBuffer);
        utxoVersion = 'v2';
    } else if (isCompactV3) {
        decrypted = this.decryptCompactV3(encryptedBuffer);
        utxoVersion = 'v2'; // V3 uses V2 private keys for UTXO logic
    } else if (utxoVersion === 'v3') {
        decrypted = this.decryptV3(encryptedBuffer);
        // V3 also uses V2 private keys for the UTXO logic
        utxoVersion = 'v2';
    } else {
        // For V2 format, use decrypt() which calls decryptV2()
        decrypted = this.decrypt(encryptedBuffer);
    }

    // Handle legacy format UTXOs (without schema version byte) - skip them
    if (decrypted === null) {
      debugLogger.decryptionFailure(originalVersion, 'LEGACY_FORMAT_SKIPPED', 'Old format UTXO without schema version byte - returning null');
      return null;
    }

    // Detect format: binary v2 (0x02, 45 bytes), binary v1 (0x01, 77 bytes), or legacy pipe-delimited text
    let amount: string, blinding: string, parsedIndex: number, resolvedMintAddress: string;

    if (decrypted[0] === EncryptionService.BINARY_UTXO_V2_FLAG && decrypted.length === EncryptionService.BINARY_UTXO_V2_LENGTH) {
      // Binary v2: [0x02][amount:8 BE][blinding:32 BE][index:4 BE] — no mintAddress
      amount = new BN(decrypted.subarray(1, 9), 'be').toString();
      blinding = new BN(decrypted.subarray(9, 41), 'be').toString();
      parsedIndex = decrypted.readUInt32BE(41);
      resolvedMintAddress = mintAddress || '11111111111111111111111111111112';
    } else if (decrypted[0] === EncryptionService.BINARY_UTXO_FLAG && decrypted.length === EncryptionService.BINARY_UTXO_LENGTH) {
      // Binary v1 (backward compat): [0x01][amount:8 BE][blinding:32 BE][index:4 BE][mintAddress:32 raw]
      amount = new BN(decrypted.subarray(1, 9), 'be').toString();
      blinding = new BN(decrypted.subarray(9, 41), 'be').toString();
      parsedIndex = decrypted.readUInt32BE(41);
      resolvedMintAddress = new PublicKey(decrypted.subarray(45, 77)).toBase58();
    } else {
      // Legacy pipe-delimited text: amount|blinding|index|mintAddress
      const decryptedStr = decrypted.toString();
      const parts = decryptedStr.split('|');

      if (parts.length !== 4) {
        debugLogger.decryptionFailure(originalVersion, 'INVALID_UTXO_FORMAT', `Expected 4 pipe-delimited parts, got ${parts.length}`, {
          partsCount: parts.length
        });
        throw new Error('Invalid UTXO format after decryption');
      }

      const [a, b, idx, mint] = parts;

      if (!a || !b || idx === undefined || mint === undefined) {
        debugLogger.decryptionFailure(originalVersion, 'MISSING_UTXO_FIELDS', 'One or more required UTXO fields are missing', {
          hasAmount: !!a,
          hasBlinding: !!b,
          hasIndex: idx !== undefined,
          hasMintAddress: mint !== undefined
        });
        throw new Error('Invalid UTXO format after decryption');
      }

      amount = a;
      blinding = b;
      parsedIndex = Number(idx);
      resolvedMintAddress = mint;
    }

    // Get or create a LightWasm instance
    const wasmInstance = lightWasm || await WasmFactory.getInstance();

    const privateKey = this.getUtxoPrivateKeyWithVersion(utxoVersion as 'v1' | 'v2');

    // Create a Utxo instance with the detected version
    const utxo = new Utxo({
      lightWasm: wasmInstance,
      amount: amount,
      blinding: blinding,
      keypair: new UtxoKeypair(privateKey, wasmInstance),
      index: parsedIndex,
      mintAddress: resolvedMintAddress,
      version: utxoVersion as 'v1' | 'v2'
    });

    // Log UTXO metadata after successful decryption
    const commitment = await utxo.getCommitment();
    debugLogger.utxoDecrypted(
      hashForLog(Buffer.from(commitment)),
      resolvedMintAddress,
      encryptedBuffer.length,
      parsedIndex,
      originalVersion
    );

    return utxo;
  }

  public getUtxoPrivateKeyWithVersion(version: 'v1' | 'v2'): string {
    if (version === 'v1') {
      return this.getUtxoPrivateKeyV1();
    }

    return this.getUtxoPrivateKeyV2();
  }

  public deriveUtxoPrivateKey(encryptedData?: Buffer | string): string {
    if (encryptedData && this.getEncryptionKeyVersion(encryptedData) === 'v2') {
      return this.getUtxoPrivateKeyWithVersion('v2');
    }
    
    if (encryptedData && this.getEncryptionKeyVersion(encryptedData) === 'v3') {
        return this.getUtxoPrivateKeyWithVersion('v2');
    }

    return this.getUtxoPrivateKeyWithVersion('v1');
  }

  public hasUtxoPrivateKeyWithVersion(version: 'v1' | 'v2'): boolean {
    if (version === 'v1') {
      return !!this.utxoPrivateKeyV1;
    }

    return !!this.utxoPrivateKeyV2;
  }

  /**
   * Get the cached V1 UTXO private key
   * @returns A private key in hex format that can be used to create a UTXO keypair
   * @throws Error if V1 encryption key has not been set
   */
  public getUtxoPrivateKeyV1(): string {
    if (!this.utxoPrivateKeyV1) {
      throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }
    return this.utxoPrivateKeyV1;
  }

  /**
   * Get the cached V2 UTXO private key
   * @returns A private key in hex format that can be used to create a UTXO keypair
   * @throws Error if V2 encryption key has not been set
   */
  public getUtxoPrivateKeyV2(): string {
    if (!this.utxoPrivateKeyV2) {
      throw new Error('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
    }
    return this.utxoPrivateKeyV2;
  }
}

export function serializeProofAndExtData(proof: any, extData: any, isSpl: boolean = false) {
  // Create the ExtDataMinified object for the program call (only extAmount and fee)
  const extDataMinified = {
    extAmount: extData.extAmount,
    fee: extData.fee
  };

  // Use the appropriate discriminator based on whether this is SPL or native SOL
  const discriminator = isSpl ? TRANSACT_SPL_IX_DISCRIMINATOR : TRANSACT_IX_DISCRIMINATOR;

  // Use the same serialization approach as deposit script
  const instructionData = Buffer.concat([
    discriminator,
    // Serialize proof
    Buffer.from(proof.proofA),
    Buffer.from(proof.proofB),
    Buffer.from(proof.proofC),
    Buffer.from(proof.root),
    Buffer.from(proof.publicAmount),
    Buffer.from(proof.extDataHash),
    Buffer.from(proof.inputNullifiers[0]),
    Buffer.from(proof.inputNullifiers[1]),
    Buffer.from(proof.outputCommitments[0]),
    Buffer.from(proof.outputCommitments[1]),
    // Serialize ExtDataMinified (only extAmount and fee)
    Buffer.from(new BN(extDataMinified.extAmount).toTwos(64).toArray('le', 8)),
    Buffer.from(new BN(extDataMinified.fee).toArray('le', 8)),
    // Serialize encrypted outputs as separate parameters
    Buffer.from(new BN(extData.encryptedOutput1.length).toArray('le', 4)),
    extData.encryptedOutput1,
    Buffer.from(new BN(extData.encryptedOutput2.length).toArray('le', 4)),
    extData.encryptedOutput2,
  ]);

  return instructionData;
}