/**
 * UTXO (Unspent Transaction Output) module for ZK Cash
 * 
 * Provides UTXO functionality for the ZK Cash system
 * Based on: https://github.com/tornadocash/tornado-nova
 */

import BN from 'bn.js';
import nacl from 'tweetnacl';
import { Keypair } from './keypair.js';
import * as hasher from '@lightprotocol/hasher.rs';
import { ethers } from 'ethers';
import { getMintAddressField } from '../utils/utils.js';
import { PublicKey } from '@solana/web3.js';
import { FIELD_SIZE } from '../utils/constants.js';

/**
 * Generate a cryptographically secure random blinding factor.
 * Uses nacl.randomBytes() instead of Math.random() for security.
 */
function generateSecureBlinding(): BN {
    const randomBytes = nacl.randomBytes(32);
    const randomBN = new BN(randomBytes);
    // Reduce modulo FIELD_SIZE to ensure it's within the valid range
    return randomBN.mod(FIELD_SIZE);
}
/**
 * Simplified Utxo class inspired by Tornado Cash Nova
 * Based on: https://github.com/tornadocash/tornado-nova/blob/f9264eeffe48bf5e04e19d8086ee6ec58cdf0d9e/src/utxo.js
 */
export class Utxo {
    amount: BN;
    blinding: BN;
    keypair?: Keypair;
    pubkey: BN;
    index: number;
    mintAddress: string;
    version: 'v1' | 'v2';
    private lightWasm: hasher.LightWasm;

    constructor({
        lightWasm,
        amount = new BN(0),
        /**
         * Tornado nova doesn't use solana eddsa with curve 25519 but their own "keypair"
         * which is:
         * - private key: random [31;u8]
         * - public key: PoseidonHash(privateKey)
         * 
         * Generate a new keypair for each UTXO
         */
        keypair,
        publicKey,
        blinding = generateSecureBlinding(), // Cryptographically secure random blinding
        index = 0,
        mintAddress = '11111111111111111111111111111112', // Default to Solana native SOL mint address,
        version = 'v2'
    }: {
        lightWasm: hasher.LightWasm,
        amount?: BN | number | string,
        keypair?: Keypair,
        publicKey?: BN | string,
        blinding?: BN | number | string,
        index?: number,
        mintAddress?: string,
        version?: 'v1' | 'v2'
    }) {
        this.amount = new BN(amount.toString());
        this.blinding = new BN(blinding.toString());
        this.lightWasm = lightWasm;
        
        if (keypair) {
            this.keypair = keypair;
            this.pubkey = keypair.pubkey;
        } else if (publicKey) {
            this.pubkey = new BN(publicKey.toString());
        } else {
            this.keypair = new Keypair(ethers.Wallet.createRandom().privateKey, lightWasm);
            this.pubkey = this.keypair.pubkey;
        }

        this.index = index;
        this.mintAddress = mintAddress;
        this.version = version;
    }

    async getCommitment(): Promise<string> {
        // return this.lightWasm.poseidonHashString([this.amount.toString(), this.keypair.pubkey.toString(), this.blinding.toString(), this.mintAddress]);
        const mintAddressField = getMintAddressField(new PublicKey(this.mintAddress));
        return this.lightWasm.poseidonHashString([
            this.amount.toString(),
            this.pubkey.toString(),
            this.blinding.toString(),
            mintAddressField
        ]);
    }

    async getNullifier(): Promise<string> {
        if (!this.keypair) {
            throw new Error('Cannot generate nullifier without private key');
        }
        const commitmentValue = await this.getCommitment();
        const signature = this.keypair.sign(commitmentValue, new BN(this.index).toString());

        return this.lightWasm.poseidonHashString([commitmentValue, new BN(this.index).toString(), signature]);
    }

    /**
     * Log all the UTXO's public properties and derived values in JSON format
     * @returns Promise that resolves once all logging is complete
     */
    async log(): Promise<void> {
        // Prepare the UTXO data object
        const utxoData: any = {
            amount: this.amount.toString(),
            blinding: this.blinding.toString(),
            index: this.index,
            mintAddress: this.mintAddress,
            keypair: {
                pubkey: this.pubkey.toString()
            }
        };

        // Add derived values
        try {
            utxoData.commitment = await this.getCommitment();
            utxoData.nullifier = await this.getNullifier();
        } catch (error: any) {
            utxoData.error = error.message;
        }

        // Output as formatted JSON
        console.log(JSON.stringify(utxoData, null, 2));
    }
} 