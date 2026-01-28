/**
 * Exponential backoff delay calculation
 *
 * @param attempt Current attempt number (0-based)
 * @param baseDelayMs Base delay in milliseconds (default: 2000ms)
 * @param maxDelayMs Maximum delay cap in milliseconds (default: 30000ms)
 * @param jitterFactor Random jitter factor 0-1 (default: 0.1 = 10%)
 * @returns Delay in milliseconds
 */
export function getExponentialBackoffDelay(
  attempt: number,
  baseDelayMs: number = 2000,
  maxDelayMs: number = 30000,
  jitterFactor: number = 0.1
): number {
  // Exponential: base * 2^attempt (e.g., 2s, 4s, 8s, 16s, 30s max)
  const exponentialDelay = baseDelayMs * Math.pow(2, attempt);

  // Cap at maximum delay
  const cappedDelay = Math.min(exponentialDelay, maxDelayMs);

  // Add jitter to prevent thundering herd
  const jitter = cappedDelay * jitterFactor * Math.random();
  const finalDelay = cappedDelay + jitter;

  return Math.floor(finalDelay);
}

/**
 * Sleep for a specified duration with exponential backoff
 *
 * @param attempt Current attempt number (0-based)
 * @param options Optional configuration
 */
export async function sleepWithBackoff(
  attempt: number,
  options?: {
    baseDelayMs?: number;
    maxDelayMs?: number;
    jitterFactor?: number;
  }
): Promise<number> {
  const delayMs = getExponentialBackoffDelay(
    attempt,
    options?.baseDelayMs,
    options?.maxDelayMs,
    options?.jitterFactor
  );
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  return delayMs;
}
