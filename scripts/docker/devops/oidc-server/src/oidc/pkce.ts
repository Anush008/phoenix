import { createHash } from "crypto";

export class PKCEUtils {
  /**
   * Validates PKCE parameters during authorization request
   */
  static validatePKCEChallenge(
    codeChallenge?: string,
    codeChallengeMethod?: string
  ): { valid: boolean; error?: string } {
    if (!codeChallenge) {
      return {
        valid: false,
        error: "code_challenge is required for PKCE flow",
      };
    }

    if (!codeChallengeMethod) {
      return {
        valid: false,
        error: "code_challenge_method is required for PKCE flow",
      };
    }

    if (!["S256", "plain"].includes(codeChallengeMethod)) {
      return {
        valid: false,
        error: "code_challenge_method must be 'S256' or 'plain'",
      };
    }

    // Validate code_challenge format
    if (
      codeChallengeMethod === "S256" &&
      !/^[A-Za-z0-9\-._~]{43,128}$/.test(codeChallenge)
    ) {
      return { valid: false, error: "Invalid code_challenge format for S256" };
    }

    if (
      codeChallengeMethod === "plain" &&
      !/^[A-Za-z0-9\-._~]{43,128}$/.test(codeChallenge)
    ) {
      return {
        valid: false,
        error: "Invalid code_challenge format for plain method",
      };
    }

    return { valid: true };
  }

  /**
   * Verifies PKCE code_verifier against stored code_challenge
   */
  static verifyPKCECodeVerifier(
    codeVerifier: string,
    codeChallenge: string,
    codeChallengeMethod: string
  ): boolean {
    if (!codeVerifier || !codeChallenge || !codeChallengeMethod) {
      return false;
    }

    // Validate code_verifier format
    if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) {
      return false;
    }

    if (codeChallengeMethod === "plain") {
      return codeVerifier === codeChallenge;
    }

    if (codeChallengeMethod === "S256") {
      const hash = createHash("sha256");
      hash.update(codeVerifier);
      const computedChallenge = hash.digest("base64url");
      return computedChallenge === codeChallenge;
    }

    return false;
  }

  /**
   * Generates a code verifier for testing purposes
   */
  static generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(array);
    } else {
      // Node.js fallback
      const { randomBytes } = require("crypto");
      const buffer = randomBytes(32);
      for (let i = 0; i < 32; i++) {
        array[i] = buffer[i];
      }
    }
    return Buffer.from(array).toString("base64url");
  }

  /**
   * Generates code challenge from code verifier for testing purposes
   */
  static generateCodeChallenge(
    codeVerifier: string,
    method: "S256" | "plain" = "S256"
  ): string {
    if (method === "plain") {
      return codeVerifier;
    }

    if (method === "S256") {
      const hash = createHash("sha256");
      hash.update(codeVerifier);
      return hash.digest("base64url");
    }

    throw new Error(`Unsupported code challenge method: ${method}`);
  }
}
