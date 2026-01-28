import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  VersionedTransaction,
} from "@solana/web3.js";
import { deposit } from "./deposit.js";
import { getBalanceFromUtxos, getUtxos, localstorageKey } from "./getUtxos.js";
import { getBalanceFromUtxosSPL, getUtxosSPL } from "./getUtxosSPL.js";

// Re-export error classes for consumers
export {
  VelumError,
  ZKProofError,
  NetworkError,
  InsufficientBalanceError,
  DepositLimitError,
  TransactionTimeoutError,
  RelayerError,
} from "./errors.js";

// Re-export debug logging utilities for consumers
export {
  enableDebugLogging,
  disableDebugLogging,
  isDebugEnabled,
  setDebugLogger,
  enableVerboseLogging,
  disableVerboseLogging,
  isVerboseEnabled,
  type DebugLoggerFn,
  type DebugLogEntry,
  type DecryptionErrorCategory,
  type DecryptionFailureRecord,
  type DecryptionFailureSummary,
} from "./utils/debug-logger.js";

import {
  LSK_ENCRYPTED_OUTPUTS,
  LSK_FETCH_OFFSET,
  SplList,
  TokenList,
  tokens,
  USDC_MINT,
} from "./utils/constants.js";
import { logger, type LoggerFn, setLogger } from "./utils/logger.js";
import { EncryptionService } from "./utils/encryption.js";
import {
  enableDebugLogging,
  disableDebugLogging,
  isDebugEnabled,
  setDebugLogger,
  enableVerboseLogging,
  disableVerboseLogging,
  isVerboseEnabled,
  debugLogger,
  type DebugLoggerFn,
  type DebugLogEntry,
  type DecryptionFailureSummary,
} from "./utils/debug-logger.js";
import { WasmFactory } from "@lightprotocol/hasher.rs";
import bs58 from "bs58";
import { withdraw } from "./withdraw.js";
import { depositSPL } from "./depositSPL.js";
import { withdrawSPL } from "./withdrawSPL.js";
import { getAssociatedTokenAddress } from "@solana/spl-token";
import { Keypair as UtxoKeypair } from "./models/keypair.js";

export class Velum {
  private connection: Connection;
  public publicKey: PublicKey;
  private encryptionService: EncryptionService;
  private keypair?: Keypair;
  private transactionSigner?: (
    tx: VersionedTransaction,
  ) => Promise<VersionedTransaction>;
  private isRuning?: boolean = false;
  private status: string = "";
  private storage: Storage;
  private circuitPath: string;
  private debugMode: boolean = false;

  constructor({
    RPC_url,
    owner,
    publicKey,
    signature,
    transactionSigner,
    enableDebug,
    debugLogger: customDebugLogger,
    storage,
    circuitPath,
  }: {
    RPC_url: string;
    owner?: string | number[] | Uint8Array | Keypair;
    publicKey?: PublicKey;
    signature?: Uint8Array;
    transactionSigner?: (
      tx: VersionedTransaction,
    ) => Promise<VersionedTransaction>;
    /** Enable verbose console logging for general SDK operations */
    enableDebug?: boolean;
    /** Enable detailed debug logging for V3 decryption diagnostics.
     *  Can be a boolean (true to enable with default console logger)
     *  or a custom DebugLoggerFn for custom logging integration.
     *  Also checks PRIVACY_CASH_DEBUG environment variable. */
    debugLogger?: boolean | DebugLoggerFn;
    storage?: Storage;
    circuitPath?: string;
  }) {
    this.connection = new Connection(RPC_url, "confirmed");
    this.encryptionService = new EncryptionService();

    // Configure debug logging for V3 decryption diagnostics
    if (customDebugLogger === true) {
      enableDebugLogging();
      this.debugMode = true;
    } else if (typeof customDebugLogger === 'function') {
      enableDebugLogging(customDebugLogger);
      this.debugMode = true;
    } else if (isDebugEnabled()) {
      // Environment variable is already set
      this.debugMode = true;
    }

    if (owner) {
      let keypair = getSolanaKeypair(owner);
      if (!keypair) {
        throw new Error('param "owner" is not a valid Private Key or Keypair');
      }
      this.keypair = keypair;
      this.publicKey = keypair.publicKey;
      this.encryptionService.deriveEncryptionKeyFromWallet(this.keypair);
    } else if (publicKey && signature) {
      this.publicKey = publicKey;
      this.encryptionService.deriveEncryptionKeyFromSignature(signature);
      this.transactionSigner = transactionSigner;
    } else {
      throw new Error(
        'Either "owner" (Keypair) or "publicKey" + "signature" must be provided',
      );
    }

    if (storage) {
      this.storage = storage;
    } else if (typeof window !== "undefined" && window.localStorage) {
      this.storage = window.localStorage;
    } else {
      throw new Error(
        "Storage implementation must be provided in non-browser environments",
      );
    }

    this.circuitPath = circuitPath || "/circuit";

    if (!enableDebug) {
      this.startStatusRender();
      this.setLogger((level, message) => {
        if (level == "info") {
          this.status = message;
        } else if (level == "error") {
          console.error(message);
        }
      });
    }
  }

  /**
   * Enable debug logging for V3 decryption diagnostics.
   * Useful for troubleshooting paylink balance issues.
   * @param customLogger Optional custom logger function
   */
  enableDecryptionDebug(customLogger?: DebugLoggerFn): this {
    enableDebugLogging(customLogger);
    this.debugMode = true;
    return this;
  }

  /**
   * Disable debug logging
   */
  disableDecryptionDebug(): this {
    disableDebugLogging();
    this.debugMode = false;
    return this;
  }

  /**
   * Check if debug logging is currently enabled
   */
  isDecryptionDebugEnabled(): boolean {
    return this.debugMode || isDebugEnabled();
  }

  setLogger(loger: LoggerFn) {
    setLogger(loger);
    return this;
  }

  private getSigner(): (
    tx: VersionedTransaction,
  ) => Promise<VersionedTransaction> {
    if (this.transactionSigner) {
      return this.transactionSigner;
    }
    return async (tx: VersionedTransaction) => {
      if (!this.keypair) throw new Error("No signer available");
      tx.sign([this.keypair]);
      return tx;
    };
  }

  /**
   * Clears the cache of utxos.
   *
   * By default, downloaded utxos will be cached in the local storage. Thus the next time when you makes another
   * deposit or withdraw or getPrivateBalance, the SDK only fetches the utxos that are not in the cache.
   *
   * This method clears the cache of utxos.
   */
  async clearCache() {
    if (!this.publicKey) {
      return this;
    }
    this.storage.removeItem(LSK_FETCH_OFFSET + localstorageKey(this.publicKey));
    this.storage.removeItem(
      LSK_ENCRYPTED_OUTPUTS + localstorageKey(this.publicKey),
    );
    // spl
    for (let token of tokens) {
      let ata = await getAssociatedTokenAddress(token.pubkey, this.publicKey);
      this.storage.removeItem(LSK_FETCH_OFFSET + localstorageKey(ata));
      this.storage.removeItem(LSK_ENCRYPTED_OUTPUTS + localstorageKey(ata));
    }
    return this;
  }

  /**
   * Deposit SOL to the Privacy Cash.
   *
   * Lamports is the amount of SOL in lamports. e.g. if you want to deposit 0.01 SOL (10000000 lamports), call deposit({ lamports: 10000000 })
   */
  async deposit({
    lamports,
    recipientUtxoPublicKey,
    recipientEncryptionKey,
  }: {
    lamports: number;
    recipientUtxoPublicKey?: any;
    recipientEncryptionKey?: Uint8Array;
  }) {
    this.isRuning = true;
    logger.info("start depositting");
    let lightWasm = await WasmFactory.getInstance();

    const transactionSigner = this.getSigner();

    let res = await deposit({
      lightWasm,
      amount_in_lamports: lamports,
      connection: this.connection,
      encryptionService: this.encryptionService,
      publicKey: this.publicKey,
      transactionSigner,
      keyBasePath: this.circuitPath,
      storage: this.storage,
      recipientUtxoPublicKey,
      recipientEncryptionKey,
    });
    this.isRuning = false;
    return res;
  }

  /**
   * Deposit USDC to the Privacy Cash.
   */
  async depositUSDC({
    base_units,
    recipientUtxoPublicKey,
    recipientEncryptionKey,
  }: {
    base_units: number;
    recipientUtxoPublicKey?: any;
    recipientEncryptionKey?: Uint8Array;
  }) {
    this.isRuning = true;
    logger.info("start depositting");
    let lightWasm = await WasmFactory.getInstance();

    const transactionSigner = this.getSigner();

    let res = await depositSPL({
      mintAddress: USDC_MINT,
      lightWasm,
      base_units: base_units,
      connection: this.connection,
      encryptionService: this.encryptionService,
      publicKey: this.publicKey,
      transactionSigner,
      keyBasePath: this.circuitPath,
      storage: this.storage,
      recipientUtxoPublicKey,
      recipientEncryptionKey,
    });
    this.isRuning = false;
    return res;
  }

  /**
   * Withdraw SOL from the Privacy Cash.
   *
   * Lamports is the amount of SOL in lamports. e.g. if you want to withdraw 0.01 SOL (10000000 lamports), call withdraw({ lamports: 10000000 })
   */
  async withdraw({
    lamports,
    recipientAddress,
    referrer,
  }: {
    lamports: number;
    recipientAddress?: string;
    referrer?: string;
  }) {
    this.isRuning = true;
    logger.info("start withdrawing");
    let lightWasm = await WasmFactory.getInstance();
    let recipient = recipientAddress
      ? new PublicKey(recipientAddress)
      : this.publicKey;
    let res = await withdraw({
      lightWasm,
      amount_in_lamports: lamports,
      connection: this.connection,
      encryptionService: this.encryptionService,
      publicKey: this.publicKey,
      recipient,
      keyBasePath: this.circuitPath,
      storage: this.storage,
      referrer,
    });
    logger.debug(
      `Withdraw successful. Recipient ${recipient} received ${res.amount_in_lamports / LAMPORTS_PER_SOL} SOL, with ${res.fee_in_lamports / LAMPORTS_PER_SOL} SOL relayers fees`,
    );
    this.isRuning = false;
    return res;
  }

  /**
   * Withdraw USDC from the Privacy Cash.
   *
   * base_units is the amount of USDC in base unit. e.g. if you want to withdraw 1 USDC (1,000,000 base unit), call withdraw({ base_units: 1000000, recipientAddress: 'some_address' })
   */
  async withdrawUSDC({
    base_units,
    recipientAddress,
    referrer,
  }: {
    base_units: number;
    recipientAddress?: string;
    referrer?: string;
  }) {
    this.isRuning = true;
    logger.info("start withdrawing");
    let lightWasm = await WasmFactory.getInstance();
    let recipient = recipientAddress
      ? new PublicKey(recipientAddress)
      : this.publicKey;
    let res = await withdrawSPL({
      mintAddress: USDC_MINT,
      lightWasm,
      base_units,
      connection: this.connection,
      encryptionService: this.encryptionService,
      publicKey: this.publicKey,
      recipient,
      keyBasePath: this.circuitPath,
      storage: this.storage,
      referrer,
    });
    logger.debug(
      `Withdraw successful. Recipient ${recipient} received ${base_units} USDC units`,
    );
    this.isRuning = false;
    return res;
  }

  /**
   * Returns the amount of lamports current wallet has in Privacy Cash.
   * Also tracks and summarizes any decryption failures for debugging.
   */
  async getPrivateBalance(abortSignal?: AbortSignal): Promise<{
    lamports: number;
    failureSummary?: DecryptionFailureSummary | null;
  }> {
    logger.info("getting private balance");
    this.isRuning = true;

    // Start failure tracking for this balance fetch
    debugLogger.startFailureTracking();

    let utxos = await getUtxos({
      publicKey: this.publicKey,
      connection: this.connection,
      encryptionService: this.encryptionService,
      storage: this.storage,
      abortSignal,
    });

    // End failure tracking and get summary
    const failureSummary = debugLogger.endFailureTracking();

    this.isRuning = false;
    const balance = getBalanceFromUtxos(utxos);
    return { ...balance, failureSummary };
  }

  /**
   * Returns the amount of base units current wallet has in Privacy Cash.
   * Also tracks and summarizes any decryption failures for debugging.
   */
  async getPrivateBalanceUSDC(): Promise<{
    base_units: number;
    amount: number;
    lamports: number;
    failureSummary?: DecryptionFailureSummary | null;
  }> {
    logger.info("getting private balance");
    this.isRuning = true;

    // Start failure tracking for this balance fetch
    debugLogger.startFailureTracking();

    let utxos = await getUtxosSPL({
      publicKey: this.publicKey,
      connection: this.connection,
      encryptionService: this.encryptionService,
      storage: this.storage,
      mintAddress: USDC_MINT,
    });

    // End failure tracking and get summary
    const failureSummary = debugLogger.endFailureTracking();

    this.isRuning = false;
    const balance = getBalanceFromUtxosSPL(utxos);
    return { ...balance, failureSummary };
  }

  /**
   * Returns the amount of base units current wallet has in Privacy Cash.
   * Also tracks and summarizes any decryption failures for debugging.
   */
  async getPrivateBalanceSpl(mintAddress: PublicKey | string): Promise<{
    base_units: number;
    amount: number;
    lamports: number;
    failureSummary?: DecryptionFailureSummary | null;
  }> {
    logger.info("getting private balance for SPL token");
    this.isRuning = true;

    // Start failure tracking for this balance fetch
    debugLogger.startFailureTracking();

    let utxos = await getUtxosSPL({
      publicKey: this.publicKey,
      connection: this.connection,
      encryptionService: this.encryptionService,
      storage: this.storage,
      mintAddress,
    });

    // End failure tracking and get summary
    const failureSummary = debugLogger.endFailureTracking();

    this.isRuning = false;
    const balance = getBalanceFromUtxosSPL(utxos);
    return { ...balance, failureSummary };
  }

  /**
   * Returns true if the code is running in a browser.
   */
  isBrowser() {
    return typeof window !== "undefined";
  }

  async startStatusRender() {
    let frames = ["-", "\\", "|", "/"];
    let i = 0;
    while (true) {
      if (this.isRuning) {
        let k = i % frames.length;
        i++;
        stdWrite(this.status, frames[k]);
      }
      await new Promise((r) => setTimeout(r, 250));
    }
  }

  /**
   * Deposit SPL to the Privacy Cash.
   */
  async depositSPL({
    base_units,
    mintAddress,
    amount,
    recipientUtxoPublicKey,
    recipientEncryptionKey,
  }: {
    base_units?: number;
    amount?: number;
    mintAddress: PublicKey | string;
    recipientUtxoPublicKey?: any;
    recipientEncryptionKey?: Uint8Array;
  }) {
    this.isRuning = true;
    logger.info("start depositting");
    let lightWasm = await WasmFactory.getInstance();

    const transactionSigner = this.getSigner();

    let res = await depositSPL({
      lightWasm,
      base_units,
      amount,
      connection: this.connection,
      encryptionService: this.encryptionService,
      publicKey: this.publicKey,
      transactionSigner,
      keyBasePath: this.circuitPath,
      storage: this.storage,
      mintAddress,
      recipientUtxoPublicKey,
      recipientEncryptionKey,
    });
    this.isRuning = false;
    return res;
  }

  /**
   * Withdraw SPL from the Privacy Cash.
   */
  async withdrawSPL({
    base_units,
    mintAddress,
    recipientAddress,
    amount,
    referrer,
  }: {
    base_units?: number;
    amount?: number;
    mintAddress: PublicKey | string;
    recipientAddress?: string;
    referrer?: string;
  }) {
    this.isRuning = true;
    logger.info("start withdrawing");
    let lightWasm = await WasmFactory.getInstance();
    let recipient = recipientAddress
      ? new PublicKey(recipientAddress)
      : this.publicKey;

    let res = await withdrawSPL({
      lightWasm,
      base_units,
      amount,
      connection: this.connection,
      encryptionService: this.encryptionService,
      publicKey: this.publicKey,
      recipient,
      keyBasePath: this.circuitPath,
      storage: this.storage,
      mintAddress,
      referrer,
    });
    logger.debug(
      `Withdraw successful. Recipient ${recipient} received ${base_units} USDC units`,
    );
    this.isRuning = false;
    return res;
  }

  /**
   * Returns the asymmetric encryption public key (X25519) for receiving encrypted paylink data.
   * This key is used by senders to encrypt UTXO data that only this wallet can decrypt.
   */
  getAsymmetricPublicKey(): Uint8Array {
    return this.encryptionService.getAsymmetricPublicKey();
  }

  /**
   * Returns the shielded public key (BN254 curve point) for receiving private payments.
   * This is the UTXO ownership key derived from the wallet signature.
   */
  async getShieldedPublicKey(): Promise<string> {
    const lightWasm = await WasmFactory.getInstance();
    const privateKeyHex = this.encryptionService.getUtxoPrivateKeyV2();
    const keypair = new UtxoKeypair(privateKeyHex, lightWasm);
    return keypair.pubkey.toString();
  }
}

function getSolanaKeypair(
  secret: string | number[] | Uint8Array | Keypair,
): Keypair | null {
  try {
    if (secret instanceof Keypair) {
      return secret;
    }

    let keyArray: Uint8Array;

    if (typeof secret === "string") {
      keyArray = bs58.decode(secret);
    } else if (secret instanceof Uint8Array) {
      keyArray = secret;
    } else {
      // number[]
      keyArray = Uint8Array.from(secret);
    }

    if (keyArray.length !== 32 && keyArray.length !== 64) {
      return null;
    }
    return Keypair.fromSecretKey(keyArray);
  } catch {
    return null;
  }
}

function stdWrite(status: string, frame: string) {
  if (typeof process !== "undefined" && process.stdout?.write) {
    let blue = "\x1b[34m";
    let reset = "\x1b[0m";
    process.stdout.write(`${frame}status: ${blue}${status}${reset}\r`);
  }
}
