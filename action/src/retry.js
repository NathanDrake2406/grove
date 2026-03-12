import * as core from "@actions/core";

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_BASE_DELAY_MS = 1000;
const RETRYABLE_STATUS_CODES = new Set([403, 429, 500, 502, 503]);

export async function withRetry(fn, { maxRetries = DEFAULT_MAX_RETRIES, baseDelayMs = DEFAULT_BASE_DELAY_MS } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const status = error.status ?? error.response?.status;
      if (!RETRYABLE_STATUS_CODES.has(status) || attempt === maxRetries) {
        throw error;
      }
      const delay = baseDelayMs * Math.pow(2, attempt);
      core.warning(`GitHub API returned ${status}, retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}
