import { RELAYER_API_URL } from "./utils/constants.js";

type Config = {
    withdraw_fee_rate: number
    withdraw_rent_fee: number
    deposit_fee_rate: number
    usdc_withdraw_rent_fee: number
    rent_fees: any
}

// Cache TTL in milliseconds (5 minutes)
const CONFIG_CACHE_TTL_MS = 5 * 60 * 1000;

let config: Config | undefined;
let configFetchedAt: number | undefined;

/**
 * Check if cached config is still valid
 */
function isCacheValid(): boolean {
    if (!config || !configFetchedAt) return false;
    return Date.now() - configFetchedAt < CONFIG_CACHE_TTL_MS;
}

/**
 * Get config value with automatic cache refresh
 */
export async function getConfig<K extends keyof Config>(key: K): Promise<Config[K]> {
    if (!isCacheValid()) {
        const res = await fetch(RELAYER_API_URL + '/config');
        config = await res.json();
        configFetchedAt = Date.now();
    }
    if (typeof config![key] == 'undefined') {
        throw new Error(`can not get ${key} from ${RELAYER_API_URL}/config`);
    }
    return config![key];
}

/**
 * Force refresh the config cache
 */
export async function refreshConfig(): Promise<void> {
    const res = await fetch(RELAYER_API_URL + '/config');
    config = await res.json();
    configFetchedAt = Date.now();
}

/**
 * Clear the config cache (useful for testing)
 */
export function clearConfigCache(): void {
    config = undefined;
    configFetchedAt = undefined;
}