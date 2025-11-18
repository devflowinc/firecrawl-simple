import crypto from "crypto";

/**
 * Generate HMAC SHA-256 signature for webhook payloads (v2.2.0)
 * This allows webhook consumers to verify that the webhook came from firecrawl
 *
 * @param payload - The webhook payload object
 * @param secret - The webhook secret key (from WEBHOOK_SECRET env var)
 * @returns HMAC signature as hex string
 */
export function generateWebhookSignature(payload: any, secret?: string): string | undefined {
  // If no secret is configured, skip signature generation (backward compatibility)
  if (!secret) {
    return undefined;
  }

  try {
    const payloadString = JSON.stringify(payload);
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(payloadString);
    return hmac.digest("hex");
  } catch (error) {
    console.error("Error generating webhook signature:", error);
    return undefined;
  }
}

/**
 * Verify a webhook signature
 * This function can be used by webhook consumers to verify incoming webhooks
 *
 * @param payload - The webhook payload object
 * @param signature - The signature from the X-Firecrawl-Signature header
 * @param secret - The webhook secret key
 * @returns true if signature is valid
 */
export function verifyWebhookSignature(
  payload: any,
  signature: string,
  secret: string
): boolean {
  const expectedSignature = generateWebhookSignature(payload, secret);
  if (!expectedSignature) {
    return false;
  }

  // Use timing-safe comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, "hex"),
      Buffer.from(expectedSignature, "hex")
    );
  } catch {
    return false;
  }
}
