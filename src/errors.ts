/**
 * Custom error classes for Velum SDK
 *
 * These provide typed errors with:
 * - Error codes for logging/analytics
 * - Recoverable flag to indicate if retry is possible
 * - Cause preservation for debugging
 */

/**
 * Base error class for all Velum SDK errors
 */
export class VelumError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly recoverable: boolean = false,
    public readonly cause?: Error,
  ) {
    super(message);
    this.name = "VelumError";

    // Maintains proper stack trace in V8 environments
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * ZK proof generation errors
 * These are generally not recoverable without fixing inputs
 */
export class ZKProofError extends VelumError {
  constructor(message: string, code: string = "ZK_GENERIC", cause?: Error) {
    super(message, code, false, cause);
    this.name = "ZKProofError";
  }
}

/**
 * Network/RPC related errors
 * These are often recoverable with retry
 */
export class NetworkError extends VelumError {
  constructor(
    message: string,
    code: string = "NETWORK_GENERIC",
    cause?: Error,
  ) {
    super(message, code, true, cause);
    this.name = "NetworkError";
  }
}

/**
 * Insufficient balance for operation
 */
export class InsufficientBalanceError extends VelumError {
  constructor(
    public readonly required: number,
    public readonly available: number,
    public readonly token: string = "SOL",
  ) {
    super(
      `Insufficient ${token} balance: need ${required} lamports, have ${available}`,
      "INSUFFICIENT_BALANCE",
      false,
    );
    this.name = "InsufficientBalanceError";
  }
}

/**
 * Deposit limit exceeded
 */
export class DepositLimitError extends VelumError {
  constructor(
    public readonly limit: number,
    public readonly attempted: number,
  ) {
    super(
      `Deposit limit exceeded: max ${limit} lamports, attempted ${attempted}`,
      "DEPOSIT_LIMIT_EXCEEDED",
      false,
    );
    this.name = "DepositLimitError";
  }
}

/**
 * Transaction confirmation timeout
 */
export class TransactionTimeoutError extends VelumError {
  constructor(
    message: string,
    public readonly signature?: string,
  ) {
    super(message, "TRANSACTION_TIMEOUT", true);
    this.name = "TransactionTimeoutError";
  }
}

/**
 * UTXO related errors
 */
export class UTXOError extends VelumError {
  constructor(message: string, code: string = "UTXO_GENERIC", cause?: Error) {
    super(message, code, false, cause);
    this.name = "UTXOError";
  }
}

/**
 * Encryption/decryption errors
 */
export class EncryptionError extends VelumError {
  constructor(
    message: string,
    code: string = "ENCRYPTION_GENERIC",
    cause?: Error,
  ) {
    super(message, code, false, cause);
    this.name = "EncryptionError";
  }
}

/**
 * Relayer API errors
 */
export class RelayerError extends VelumError {
  constructor(
    message: string,
    public readonly statusCode?: number,
    cause?: Error,
  ) {
    super(message, "RELAYER_ERROR", true, cause);
    this.name = "RelayerError";
  }
}

/**
 * Helper to wrap unknown errors
 */
export function wrapError(
  error: unknown,
  fallbackMessage: string,
): VelumError {
  if (error instanceof VelumError) {
    return error;
  }

  if (error instanceof Error) {
    return new VelumError(
      error.message || fallbackMessage,
      "UNKNOWN_ERROR",
      false,
      error,
    );
  }

  return new VelumError(
    typeof error === "string" ? error : fallbackMessage,
    "UNKNOWN_ERROR",
    false,
  );
}
