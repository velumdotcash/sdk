# @velumdotcash/sdk

[![npm](https://img.shields.io/npm/v/@velumdotcash/sdk)](https://www.npmjs.com/package/@velumdotcash/sdk)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

TypeScript SDK for private payments on Solana using Zero-Knowledge proofs. Deposit, withdraw, and transfer shielded funds with ZK-SNARKs.

## 📦 Installation

```bash
npm install @velumdotcash/sdk
```

## 🚀 Quick Start

### Browser (with wallet adapter)

```typescript
import { Velum } from "@velumdotcash/sdk";

// Sign a deterministic message to derive shielded keys
const message = new TextEncoder().encode(
  `Welcome to Velum\n\nSign this message to derive your private encryption keys.\n\nThis request will not trigger a blockchain transaction or cost any fees.\n\nWallet: ${publicKey.toBase58()}`
);
const signature = await wallet.signMessage(message);

const sdk = new Velum({
  RPC_url: "https://api.mainnet-beta.solana.com",
  publicKey: walletPublicKey,
  signature: walletSignature,
  transactionSigner: async (tx) => wallet.signTransaction(tx),
});
```

### Node.js (with keypair)

```typescript
import { Keypair } from "@solana/web3.js";
import { Velum } from "@velumdotcash/sdk";

const sdk = new Velum({
  RPC_url: process.env.SOLANA_RPC_URL!,
  owner: Keypair.fromSecretKey(secretKey),
  circuitPath: "./circuits",
});
```

## 💰 Deposits

```typescript
// Deposit SOL to your shielded account
await sdk.deposit({ lamports: 10_000_000 }); // 0.01 SOL

// Deposit USDC
await sdk.depositUSDC({ base_units: 1_000_000 }); // 1 USDC

// Deposit any SPL token
await sdk.depositSPL({
  base_units: 1_000_000,
  mintAddress: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
});

// Deposit to a third-party recipient (payment link flow)
await sdk.deposit({
  lamports: 10_000_000,
  recipientUtxoPublicKey: recipientPubkey,
  recipientEncryptionKey: recipientEncKey,
});
```

## 💸 Withdrawals

```typescript
// Withdraw SOL to any address
await sdk.withdraw({
  lamports: 10_000_000,
  recipientAddress: "Destination...",
});

// Withdraw USDC
await sdk.withdrawUSDC({
  base_units: 1_000_000,
  recipientAddress: "Destination...",
});

// Withdraw any SPL token
await sdk.withdrawSPL({
  base_units: 1_000_000,
  mintAddress: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
  recipientAddress: "Destination...",
});
```

## 🔒 Private Balance

```typescript
const sol = await sdk.getPrivateBalance();
const usdc = await sdk.getPrivateBalanceUSDC();
const spl = await sdk.getPrivateBalanceSpl(mintAddress);
```

## 🔑 Key Derivation

```typescript
// Get your shielded public keys (share these to receive payments)
const encryptionKey = sdk.getAsymmetricPublicKey(); // Uint8Array (X25519)
const utxoPubkey = await sdk.getShieldedPublicKey(); // string (BN254)
```

## ⚙️ How It Works

1. **Key derivation**: A wallet signature deterministically derives two keypairs — BN254 (UTXO ownership) and X25519 (note encryption)
2. **Deposit**: Funds enter a shielded pool via a ZK-SNARK that proves validity without revealing the amount or recipient
3. **UTXO creation**: An encrypted note is stored onchain — only the recipient's X25519 key can decrypt it
4. **Withdraw**: A second ZK proof verifies UTXO ownership without revealing which deposit created it

The result: no onchain link between sender and receiver.

## 📁 Circuit Files

The SDK requires ZK circuit files (`circuit.wasm` ~3MB, `circuit.zkey` ~16MB) for proof generation.

**Browser**: Serve from your public directory. Files are lazy-loaded on first deposit/withdraw and cached in IndexedDB.

```typescript
const sdk = new Velum({
  // ...
  circuitPath: "/circuit", // relative to your public dir
});
```

**Node.js**: Point to a local directory containing the circuit files.

## ⚠️ Error Types

```typescript
import {
  InsufficientBalanceError,
  ZKProofError,
  NetworkError,
  TransactionTimeoutError,
} from "@velumdotcash/sdk";
```

## 🔗 Related

- [`@velumdotcash/api`](https://www.npmjs.com/package/@velumdotcash/api) — Server-side REST client for paylinks and transactions
- [Developer Guide](https://velum.cash/docs/developer-guide) — Full integration documentation
- [How It Works](https://velum.cash/docs/how-it-works) — Cryptographic architecture

## 📄 License

[MIT](./LICENSE)
