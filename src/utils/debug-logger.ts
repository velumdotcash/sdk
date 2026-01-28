import { sha256 } from '@noble/hashes/sha256';

/**
 * Debug logging utility for privacy-cash SDK
 *
 * Provides detailed diagnostic logging for V3 asymmetric encryption decryption
 * to help identify failure points without exposing sensitive key material.
 */

export type DebugLogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

/**
 * Error categories for decryption failures
 */
export type DecryptionErrorCategory =
  | 'key_mismatch'      // UTXO was encrypted for a different wallet
  | 'malformed_data'    // Encrypted data is corrupted or invalid format
  | 'version_error'     // Encryption version detection failed
  | 'missing_key'       // Required encryption key not available
  | 'unknown';          // Unclassified error

/**
 * Detailed decryption failure record
 */
export interface DecryptionFailureRecord {
  category: DecryptionErrorCategory;
  errorMessage: string;
  stackTrace?: string;
  encryptedDataHash: string;
  encryptedDataLength: number;
  attemptedVersions?: string[];
  timestamp: string;
}

/**
 * Summary of decryption failures for a balance fetch operation
 */
export interface DecryptionFailureSummary {
  totalAttempted: number;
  totalDecrypted: number;
  totalFailed: number;
  totalSkipped: number;
  totalSchemaMismatch: number;
  failuresByCategory: Record<DecryptionErrorCategory, number>;
  failures: DecryptionFailureRecord[];
}

// Global failure tracking for current balance fetch operation
let currentFailureSummary: DecryptionFailureSummary | null = null;

export interface DebugLogEntry {
  timestamp: string;
  level: DebugLogLevel;
  category: string;
  message: string;
  data?: Record<string, unknown>;
}

export type DebugLoggerFn = (entry: DebugLogEntry) => void;

// Global debug state
let debugEnabled = false;
let verboseEnabled = false;
let debugLoggerFn: DebugLoggerFn | null = null;
let urlParamChecked = false;

/**
 * Check if running in development mode
 */
function isDevelopmentMode(): boolean {
  // Node.js environment
  if (typeof process !== 'undefined' && process.env) {
    const nodeEnv = process.env.NODE_ENV;
    if (nodeEnv === 'development') {
      return true;
    }
  }
  // Browser environment - check for common development indicators
  if (typeof window !== 'undefined') {
    // Check if NEXT_PUBLIC_NODE_ENV is set (Next.js)
    const win = window as unknown as {
      __NEXT_DATA__?: { props?: { pageProps?: { env?: string } } };
    };
    // Check for localhost
    if (typeof location !== 'undefined' &&
        (location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
      return true;
    }
  }
  return false;
}

/**
 * Check URL parameters for debug enablement (development only)
 * Enables via ?privacy_cash_debug=1 or ?privacy_cash_debug=true
 * SECURITY: Only works on localhost to prevent information leakage in production
 */
function checkUrlParamDebugEnabled(): boolean {
  if (typeof window === 'undefined' || typeof location === 'undefined') {
    return false;
  }

  // SECURITY: Only allow URL parameter debugging on localhost
  // This prevents attackers from enabling debug mode in production via URL manipulation
  if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
    return false;
  }

  // Only check once to avoid repeated URL parsing
  if (urlParamChecked) {
    return false;
  }
  urlParamChecked = true;

  try {
    const params = new URLSearchParams(location.search);
    const debugParam = params.get('privacy_cash_debug');
    return debugParam === 'true' || debugParam === '1';
  } catch {
    return false;
  }
}

/**
 * Check if debug mode should be enabled based on environment variable
 */
function checkEnvDebugEnabled(): boolean {
  // Check for PRIVACY_CASH_DEBUG environment variable
  if (typeof process !== 'undefined' && process.env) {
    const envValue = process.env.PRIVACY_CASH_DEBUG;
    return envValue === 'true' || envValue === '1';
  }
  // Browser environment - check window global
  if (typeof window !== 'undefined') {
    const win = window as unknown as { PRIVACY_CASH_DEBUG?: boolean | string };
    if (win.PRIVACY_CASH_DEBUG === true || win.PRIVACY_CASH_DEBUG === 'true' || win.PRIVACY_CASH_DEBUG === '1') {
      return true;
    }
  }
  return false;
}

/**
 * Check if verbose mode should be enabled based on environment variable
 */
function checkEnvVerboseEnabled(): boolean {
  // Check for PRIVACY_CASH_VERBOSE environment variable
  if (typeof process !== 'undefined' && process.env) {
    const envValue = process.env.PRIVACY_CASH_VERBOSE;
    return envValue === 'true' || envValue === '1';
  }
  // Browser environment - check window global
  if (typeof window !== 'undefined') {
    const win = window as unknown as { PRIVACY_CASH_VERBOSE?: boolean | string };
    if (win.PRIVACY_CASH_VERBOSE === true || win.PRIVACY_CASH_VERBOSE === 'true' || win.PRIVACY_CASH_VERBOSE === '1') {
      return true;
    }
  }
  return false;
}

/**
 * Enable debug logging programmatically
 * @param customLogger Optional custom logger function
 * @param verbose Enable verbose/trace mode for individual UTXO logs (default: false)
 */
export function enableDebugLogging(customLogger?: DebugLoggerFn, verbose?: boolean): void {
  debugEnabled = true;
  if (customLogger) {
    debugLoggerFn = customLogger;
  }
  if (verbose !== undefined) {
    verboseEnabled = verbose;
  }
}

/**
 * Enable verbose mode for individual UTXO logs
 */
export function enableVerboseLogging(): void {
  verboseEnabled = true;
}

/**
 * Disable verbose mode
 */
export function disableVerboseLogging(): void {
  verboseEnabled = false;
}

/**
 * Check if verbose logging is enabled
 */
export function isVerboseEnabled(): boolean {
  return verboseEnabled || checkEnvVerboseEnabled();
}

/**
 * Disable debug logging
 */
export function disableDebugLogging(): void {
  debugEnabled = false;
  verboseEnabled = false;
  debugLoggerFn = null;
}

/**
 * Install debug commands on the window object for production debugging
 * Call this from browser console: window.privacyCashDebug.enable()
 */
export function installDebugCommands(): void {
  if (typeof window === 'undefined') {
    return;
  }

  const win = window as unknown as {
    privacyCashDebug?: {
      enable: () => void;
      disable: () => void;
      verbose: (enable?: boolean) => void;
      status: () => void;
    };
  };

  win.privacyCashDebug = {
    enable: () => {
      enableDebugLogging();
      console.log('[PRIVACY-CASH-DEBUG] Debug logging enabled. Refresh or retry operations to see logs.');
    },
    disable: () => {
      disableDebugLogging();
      console.log('[PRIVACY-CASH-DEBUG] Debug logging disabled.');
    },
    verbose: (enable?: boolean) => {
      if (enable === false) {
        disableVerboseLogging();
        console.log('[PRIVACY-CASH-DEBUG] Verbose logging disabled. Individual UTXO logs suppressed.');
      } else {
        enableVerboseLogging();
        console.log('[PRIVACY-CASH-DEBUG] Verbose logging enabled. Individual UTXO logs will be shown.');
      }
    },
    status: () => {
      const enabled = isDebugEnabled();
      const verbose = isVerboseEnabled();
      const mode = isDevelopmentMode() ? 'development' : 'production';
      console.log(`[PRIVACY-CASH-DEBUG] Status: ${enabled ? 'ENABLED' : 'DISABLED'}`);
      console.log(`[PRIVACY-CASH-DEBUG] Verbose: ${verbose ? 'ENABLED' : 'DISABLED'}`);
      console.log(`[PRIVACY-CASH-DEBUG] Mode: ${mode}`);
      console.log('[PRIVACY-CASH-DEBUG] To enable: window.privacyCashDebug.enable() (or ?privacy_cash_debug=1 on localhost)');
      console.log('[PRIVACY-CASH-DEBUG] For verbose: window.privacyCashDebug.verbose() or set PRIVACY_CASH_VERBOSE=1');
    }
  };
}

// Auto-install debug commands in browser environment
if (typeof window !== 'undefined') {
  installDebugCommands();
}

/**
 * Check if debug logging is enabled
 *
 * Debug logging is enabled if any of the following conditions are met:
 * 1. Explicitly enabled via enableDebugLogging()
 * 2. PRIVACY_CASH_DEBUG environment variable is set to 'true' or '1'
 * 3. window.PRIVACY_CASH_DEBUG is set to true, 'true', or '1'
 * 4. Running in development mode (NODE_ENV=development or localhost)
 * 5. URL contains ?privacy_cash_debug=true or ?privacy_cash_debug=1 (localhost only)
 */
export function isDebugEnabled(): boolean {
  return debugEnabled || checkEnvDebugEnabled() || isDevelopmentMode() || checkUrlParamDebugEnabled();
}

/**
 * Set a custom debug logger function
 */
export function setDebugLogger(fn: DebugLoggerFn): void {
  debugLoggerFn = fn;
}

/**
 * Hash sensitive data for safe logging (first 8 chars of hex)
 */
export function hashForLog(data: Uint8Array | string | null | undefined): string {
  if (!data) return '<null>';
  const bytes = typeof data === 'string' ? Buffer.from(data, 'hex') : data;
  if (bytes.length === 0) return '<empty>';
  const hash = sha256(bytes);
  return Buffer.from(hash).toString('hex').substring(0, 16) + '...';
}

/**
 * Format bytes length for logging
 */
export function bytesInfo(data: Uint8Array | Buffer | string | null | undefined): string {
  if (!data) return '<null>';
  const len = typeof data === 'string' ? data.length / 2 : data.length;
  return `${len} bytes`;
}

/**
 * Default console logger implementation
 */
const defaultDebugLogger: DebugLoggerFn = (entry) => {
  const prefix = `[PRIVACY-CASH-DEBUG][${entry.level.toUpperCase()}][${entry.category}]`;
  const message = `${prefix} ${entry.message}`;
  if (entry.data) {
    console.log(message, entry.data);
  } else {
    console.log(message);
  }
};

/**
 * Core debug logging function
 *
 * Log levels:
 * - trace: Only shown in verbose mode (individual UTXO logs)
 * - debug: Detailed debugging info (shown when debug enabled)
 * - info: General information (shown when debug enabled)
 * - warn: Warnings (always shown when debug enabled)
 * - error: Errors (always shown when debug enabled)
 */
function logDebug(
  level: DebugLogLevel,
  category: string,
  message: string,
  data?: Record<string, unknown>
): void {
  if (!isDebugEnabled()) return;

  // Trace level requires verbose mode
  if (level === 'trace' && !isVerboseEnabled()) return;

  const entry: DebugLogEntry = {
    timestamp: new Date().toISOString(),
    level,
    category,
    message,
    data
  };

  const logger = debugLoggerFn || defaultDebugLogger;
  logger(entry);
}

/**
 * Debug logger for encryption-related operations
 */
export const debugLogger = {
  /**
   * Log the first 8 bytes (version prefix) of encrypted data
   */
  versionPrefixBytes(prefixHex: string, dataLength: number): void {
    logDebug('debug', 'VERSION_PREFIX', `First 8 bytes of encrypted data: ${prefixHex}`, {
      prefixHex,
      dataLength
    });
  },

  /**
   * Log encryption version detection
   */
  versionDetected(encryptedDataHash: string, version: 'v1' | 'v2' | 'v3', dataLength: number): void {
    logDebug('info', 'VERSION_DETECT', `Detected encryption version: ${version}`, {
      encryptedDataHash,
      version,
      dataLength
    });
  },

  /**
   * Log when version detection falls back to legacy V1 mode
   */
  versionFallbackToLegacy(prefixHex: string, reason: string): void {
    logDebug('warn', 'VERSION_FALLBACK', `Falling back to legacy V1 mode: ${reason}`, {
      prefixHex,
      reason
    });
  },

  /**
   * Log key derivation steps (with hashed keys for privacy)
   */
  keyDerivation(step: string, keyHash: string, keyType: string): void {
    logDebug('debug', 'KEY_DERIVATION', `${step}: ${keyType}`, {
      step,
      keyHash,
      keyType
    });
  },

  /**
   * Log asymmetric key pair generation
   */
  asymmetricKeyGenerated(publicKeyHash: string, secretKeyHash: string): void {
    logDebug('info', 'ASYMMETRIC_KEY', 'X25519 keypair derived from signature', {
      publicKeyHash,
      secretKeyHash: secretKeyHash.substring(0, 8) + '...'
    });
  },

  /**
   * Log decryption attempt start
   */
  decryptionAttemptStart(version: string, encryptedDataHash: string, dataLength: number): void {
    logDebug('info', 'DECRYPT_ATTEMPT', `Starting ${version} decryption`, {
      version,
      encryptedDataHash,
      dataLength
    });
  },

  /**
   * Log schema version mismatch for early termination
   * Individual UTXO logs are verbose-only; tracking is always updated
   * @param foundVersion The schema version byte found in the encrypted data
   * @param expectedVersion The expected schema version byte
   * @param encryptedDataHash Hash of the encrypted data for identification
   */
  schemaVersionMismatch(foundVersion: number, expectedVersion: number, encryptedDataHash: string): void {
    // Always track the mismatch for summary
    this.recordSchemaMismatch();

    // Individual log is verbose-only (trace level) to avoid console spam
    logDebug('trace', 'SCHEMA_VERSION_MISMATCH', 'Skipping UTXO due to incompatible schema version', {
      foundVersion: `0x${foundVersion.toString(16).padStart(2, '0')}`,
      expectedVersion: `0x${expectedVersion.toString(16).padStart(2, '0')}`,
      encryptedDataHash,
      action: 'early_termination'
    });
  },

  /**
   * Log recipient ID hash mismatch (O(1) early termination)
   * This is the fastest way to skip UTXOs that don't belong to this wallet
   */
  recipientIdMismatch(encryptedDataHash: string): void {
    // Track as skipped (not failed, because this is expected behavior for other users' UTXOs)
    this.recordDecryptionSkipped();

    // Individual log is verbose-only (trace level) to avoid console spam
    // In production, 140,000+ UTXOs will trigger this, so we only log at trace level
    logDebug('trace', 'RECIPIENT_ID_MISMATCH', 'Skipping UTXO - recipient ID hash does not match this wallet', {
      encryptedDataHash,
      action: 'early_termination_o1'
    });
  },

  /**
   * Log decryption success
   */
  decryptionSuccess(version: string, decryptedLength: number): void {
    logDebug('info', 'DECRYPT_SUCCESS', `${version} decryption succeeded`, {
      version,
      decryptedLength
    });
  },

  /**
   * Log decryption failure with detailed error info
   */
  decryptionFailure(version: string, errorType: string, errorMessage: string, context?: Record<string, unknown>): void {
    logDebug('error', 'DECRYPT_FAILURE', `${version} decryption failed: ${errorType}`, {
      version,
      errorType,
      errorMessage,
      ...context
    });
  },

  /**
   * Log V3 asymmetric decryption details
   */
  v3DecryptionDetails(
    ephemeralPubKeyHash: string,
    nonceHash: string,
    boxLength: number,
    recipientSecretKeyHash: string
  ): void {
    logDebug('debug', 'V3_DECRYPT', 'V3 asymmetric decryption parameters', {
      ephemeralPubKeyHash,
      nonceHash,
      boxLength,
      recipientSecretKeyHash: recipientSecretKeyHash.substring(0, 8) + '...'
    });
  },

  /**
   * Log UTXO metadata after successful decryption
   */
  utxoDecrypted(
    commitmentHash: string,
    tokenMint: string,
    encryptedLength: number,
    utxoIndex: number | string,
    version: string
  ): void {
    logDebug('info', 'UTXO_DECRYPTED', 'UTXO successfully decrypted', {
      commitmentHash,
      tokenMint,
      encryptedLength,
      utxoIndex,
      version
    });
  },

  /**
   * Log UTXO decryption batch summary
   */
  utxoBatchSummary(
    total: number,
    decrypted: number,
    skipped: number,
    failed: number
  ): void {
    logDebug('info', 'UTXO_BATCH', `Batch decryption complete: ${decrypted}/${total} successful`, {
      total,
      decrypted,
      skipped,
      failed
    });
  },

  /**
   * Log encryption service initialization
   */
  serviceInitialized(hasV1Key: boolean, hasV2Key: boolean, hasAsymmetricKey: boolean): void {
    logDebug('info', 'SERVICE_INIT', 'EncryptionService key state', {
      hasV1Key,
      hasV2Key,
      hasAsymmetricKey
    });
  },

  /**
   * Log when attempting decryption without required key
   */
  missingKey(keyType: string, operation: string): void {
    logDebug('error', 'MISSING_KEY', `Missing ${keyType} for ${operation}`, {
      keyType,
      operation
    });
  },

  /**
   * Generic debug log
   */
  debug(category: string, message: string, data?: Record<string, unknown>): void {
    logDebug('debug', category, message, data);
  },

  /**
   * Generic info log
   */
  info(category: string, message: string, data?: Record<string, unknown>): void {
    logDebug('info', category, message, data);
  },

  /**
   * Generic warning log
   */
  warn(category: string, message: string, data?: Record<string, unknown>): void {
    logDebug('warn', category, message, data);
  },

  /**
   * Generic error log
   */
  error(category: string, message: string, data?: Record<string, unknown>): void {
    logDebug('error', category, message, data);
  },

  /**
   * Log X25519 public key derivation for sender-side verification
   * @param publicKeyHash Hash of the derived X25519 public key
   * @param walletAddress The wallet address used for key derivation
   * @param context Whether this is sender or recipient side
   */
  x25519KeyDerived(publicKeyHash: string, walletAddress: string, context: 'sender' | 'recipient'): void {
    logDebug('info', 'X25519_KEY_DERIVED', `X25519 public key derived (${context} side)`, {
      publicKeyHash,
      walletAddress,
      context
    });
  },

  /**
   * Log X25519 public key used during encryption (sender side)
   * @param recipientPublicKeyHash Hash of the recipient's X25519 public key being encrypted to
   * @param walletAddress Sender's wallet address
   */
  x25519EncryptionKey(recipientPublicKeyHash: string, walletAddress?: string): void {
    logDebug('info', 'X25519_ENCRYPT', 'Encrypting with recipient X25519 public key', {
      recipientPublicKeyHash,
      walletAddress: walletAddress || '<not provided>'
    });
  },

  /**
   * Log X25519 public key used during decryption (recipient side)
   * @param derivedPublicKeyHash Hash of the recipient's derived X25519 public key
   * @param walletAddress Recipient's wallet address
   */
  x25519DecryptionKey(derivedPublicKeyHash: string, walletAddress?: string): void {
    logDebug('info', 'X25519_DECRYPT', 'Decrypting with derived X25519 public key', {
      derivedPublicKeyHash,
      walletAddress: walletAddress || '<not provided>'
    });
  },

  /**
   * Log key mismatch comparison when decryption fails
   * @param expectedKeyHash Hash of the expected public key (from encrypted data)
   * @param derivedKeyHash Hash of the derived public key (from wallet signature)
   * @param walletAddress The wallet address used for derivation
   */
  x25519KeyMismatch(expectedKeyHash: string, derivedKeyHash: string, walletAddress?: string): void {
    logDebug('warn', 'X25519_KEY_MISMATCH', 'X25519 public key mismatch detected - possible different wallet or signature', {
      expectedKeyHash,
      derivedKeyHash,
      walletAddress: walletAddress || '<not provided>',
      keysMatch: expectedKeyHash === derivedKeyHash
    });
  },

  /**
   * Log wallet address association with key derivation
   * @param walletAddress The wallet address being used
   * @param operation The operation being performed (encryption/decryption)
   */
  walletKeyDerivation(walletAddress: string, operation: 'encrypt' | 'decrypt' | 'derive'): void {
    logDebug('debug', 'WALLET_KEY_DERIVATION', `Wallet address associated with ${operation} operation`, {
      walletAddress,
      operation
    });
  },

  // ======== Failure Tracking Methods ========

  /**
   * Initialize failure tracking for a new balance fetch operation
   */
  startFailureTracking(): void {
    currentFailureSummary = {
      totalAttempted: 0,
      totalDecrypted: 0,
      totalFailed: 0,
      totalSkipped: 0,
      totalSchemaMismatch: 0,
      failuresByCategory: {
        key_mismatch: 0,
        malformed_data: 0,
        version_error: 0,
        missing_key: 0,
        unknown: 0
      },
      failures: []
    };
    logDebug('trace', 'FAILURE_TRACKING', 'Started failure tracking for balance fetch');
  },

  /**
   * Categorize an error based on its message and type
   */
  categorizeError(error: Error | unknown): DecryptionErrorCategory {
    if (!error) return 'unknown';

    const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();

    // Key mismatch patterns
    if (message.includes('wrong tag') ||
        message.includes('authentication failed') ||
        message.includes('decrypt') && message.includes('fail') ||
        message.includes('nacl.box.open') ||
        message.includes('null') && message.includes('box')) {
      return 'key_mismatch';
    }

    // Malformed data patterns
    if (message.includes('malformed') ||
        message.includes('invalid') && (message.includes('format') || message.includes('data')) ||
        message.includes('unexpected') && message.includes('length') ||
        message.includes('cannot read') ||
        message.includes('parse') ||
        message.includes('buffer') ||
        message.includes('too short') ||
        message.includes('truncated')) {
      return 'malformed_data';
    }

    // Version error patterns
    if (message.includes('version') ||
        message.includes('unsupported') ||
        message.includes('unknown encryption')) {
      return 'version_error';
    }

    // Missing key patterns
    if (message.includes('no encryption key') ||
        message.includes('key not') ||
        message.includes('missing key') ||
        message.includes('derive')) {
      return 'missing_key';
    }

    return 'unknown';
  },

  /**
   * Record a decryption failure with full context
   * Individual failure logs are only shown in verbose mode to avoid console spam
   */
  recordDecryptionFailure(
    error: Error | unknown,
    encryptedDataHex: string,
    attemptedVersions?: string[]
  ): void {
    const category = this.categorizeError(error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    const stackTrace = error instanceof Error ? error.stack : undefined;

    const record: DecryptionFailureRecord = {
      category,
      errorMessage,
      stackTrace,
      encryptedDataHash: hashForLog(encryptedDataHex),
      encryptedDataLength: encryptedDataHex ? encryptedDataHex.length / 2 : 0,
      attemptedVersions,
      timestamp: new Date().toISOString()
    };

    if (currentFailureSummary) {
      currentFailureSummary.totalFailed++;
      currentFailureSummary.failuresByCategory[category]++;
      // Keep last 100 failure records to avoid memory issues
      if (currentFailureSummary.failures.length < 100) {
        currentFailureSummary.failures.push(record);
      }
    }

    // Individual UTXO failure logs are verbose-only (trace level) to avoid console spam
    logDebug('trace', 'DECRYPT_FAILURE_RECORDED', `Decryption failed: ${category}`, {
      category,
      errorMessage,
      encryptedDataHash: record.encryptedDataHash,
      encryptedDataLength: record.encryptedDataLength,
      attemptedVersions,
      hasStackTrace: !!stackTrace
    });
  },

  /**
   * Record a schema version mismatch (early termination)
   * These are tracked separately since they're expected behavior for UTXOs not belonging to the user
   */
  recordSchemaMismatch(): void {
    if (currentFailureSummary) {
      currentFailureSummary.totalSchemaMismatch++;
    }
  },

  /**
   * Record a successful decryption
   */
  recordDecryptionSuccess(): void {
    if (currentFailureSummary) {
      currentFailureSummary.totalDecrypted++;
    }
  },

  /**
   * Record a skipped UTXO (empty/null encrypted data)
   */
  recordDecryptionSkipped(): void {
    if (currentFailureSummary) {
      currentFailureSummary.totalSkipped++;
    }
  },

  /**
   * Increment the total attempted counter
   */
  recordDecryptionAttempt(): void {
    if (currentFailureSummary) {
      currentFailureSummary.totalAttempted++;
    }
  },

  /**
   * Get the current failure summary and log it
   * Logs a single summary line per balance fetch (not per-UTXO)
   */
  endFailureTracking(): DecryptionFailureSummary | null {
    if (!currentFailureSummary) {
      return null;
    }

    const summary = { ...currentFailureSummary };

    // Only log summary if there were any UTXOs processed
    if (summary.totalAttempted === 0 && summary.totalSchemaMismatch === 0 && summary.totalSkipped === 0) {
      currentFailureSummary = null;
      return summary;
    }

    // Build summary message - single line for quick understanding
    const parts: string[] = [];
    parts.push(`processed: ${summary.totalAttempted}`);
    if (summary.totalSchemaMismatch > 0) {
      parts.push(`schema_skipped: ${summary.totalSchemaMismatch}`);
    }
    if (summary.totalFailed > 0) {
      parts.push(`failed: ${summary.totalFailed}`);
    }
    parts.push(`decrypted: ${summary.totalDecrypted}`);

    const hasIssues = summary.totalFailed > 0;
    const level = hasIssues ? 'warn' : 'info';

    // Log single summary line
    logDebug(level, 'BALANCE_FETCH_SUMMARY',
      `Balance fetch complete - ${parts.join(', ')}`, {
      totalAttempted: summary.totalAttempted,
      totalDecrypted: summary.totalDecrypted,
      totalFailed: summary.totalFailed,
      totalSkipped: summary.totalSkipped,
      totalSchemaMismatch: summary.totalSchemaMismatch,
      failuresByCategory: summary.failuresByCategory
    });

    // Log category breakdown only if there are actual failures (not schema mismatches)
    if (hasIssues) {
      const categoryBreakdown = Object.entries(summary.failuresByCategory)
        .filter(([_, count]) => count > 0)
        .map(([cat, count]) => `${cat}: ${count}`)
        .join(', ');

      logDebug('warn', 'FAILURE_BREAKDOWN', `Failure categories: ${categoryBreakdown}`, {
        breakdown: summary.failuresByCategory
      });
    }

    currentFailureSummary = null;
    return summary;
  },

  /**
   * Get the current failure summary without ending tracking
   */
  getCurrentFailureSummary(): DecryptionFailureSummary | null {
    return currentFailureSummary ? { ...currentFailureSummary } : null;
  }
};
