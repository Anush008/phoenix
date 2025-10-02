/**
 * Token generation factory with comprehensive logging
 * DRYs up access token and ID token creation patterns
 */

import { SignJWT } from "jose";
import type { User, TokenClaims } from "../types/index.js";
import { Logger } from "./logger.js";

export class TokenFactory {
  constructor(
    private keyPair: { privateKey: any; publicKey: any },
    private issuer: string,
    private audienceClientId: string
  ) {}

  /**
   * Generate access token with comprehensive logging
   */
  async generateAccessToken(
    user: User,
    nonce?: string,
    scope?: string
  ): Promise<string> {
    const includeRole = scope?.includes("roles") || false;

    const claims: TokenClaims = {
      sub: user.id,
      email: user.email,
      name: user.name,
      iss: this.issuer,
      aud: this.audienceClientId,
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      iat: Math.floor(Date.now() / 1000),
      ...(nonce && { nonce }),
      ...(includeRole && { role: user.role }),
      // Groups are intentionally NOT included in access token
      // They should be fetched from the userinfo endpoint
    };

    Logger.logTokenEvent("access_token_creation", "access", {
      claims,
      key_id: "phoenix-dev-key-1",
      algorithm: "RS256",
    });

    const startTime = Date.now();
    const token = await new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "phoenix-dev-key-1" })
      .sign(this.keyPair.privateKey);

    Logger.logEvent("access_token_created", {
      token_length: token.length,
      user_email: user.email,
    });

    Logger.logEvent("access_token_generated", {
      generation_time_ms: Date.now() - startTime,
      token_length: token.length,
      token_preview: token.substring(0, 50) + "...",
    });

    return token;
  }

  /**
   * Generate ID token with comprehensive logging
   * NOTE: Groups claim should NOT be in ID token - only in userinfo endpoint
   * This is the recommended approach for Grafana and other OIDC clients
   */
  async generateIdToken(
    user: User,
    nonce?: string,
    scope?: string
  ): Promise<string> {
    const includeRole = scope?.includes("roles") || false;

    const claims: TokenClaims = {
      sub: user.id,
      email: user.email,
      name: user.name,
      iss: this.issuer,
      aud: this.audienceClientId,
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      iat: Math.floor(Date.now() / 1000),
      ...(nonce && { nonce }),
      ...(includeRole && { role: user.role }),
      // Groups are intentionally NOT included in ID token
      // They should be fetched from the userinfo endpoint
    };

    Logger.logTokenEvent("id_token_creation", "id", {
      claims,
      key_id: "phoenix-dev-key-1",
      algorithm: "RS256",
      audience: this.audienceClientId,
    });

    const startTime = Date.now();
    const token = await new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "phoenix-dev-key-1" })
      .sign(this.keyPair.privateKey);

    Logger.logEvent("id_token_created", {
      token_length: token.length,
      user_email: user.email,
      audience: this.audienceClientId,
    });

    Logger.logEvent("id_token_generated", {
      generation_time_ms: Date.now() - startTime,
      token_length: token.length,
      token_preview: token.substring(0, 50) + "...",
      audience_client_id: this.audienceClientId,
    });

    return token;
  }

  /**
   * Generate both tokens with single call
   */
  async generateTokenPair(user: User, nonce?: string, scope?: string) {
    Logger.logEvent("token_generation_started", {
      user_email: user.email,
      nonce: nonce || null,
      scope: scope || "openid",
      groups_requested: scope?.includes("groups") || false,
      roles_requested: scope?.includes("roles") || false,
    });

    const [accessToken, idToken] = await Promise.all([
      this.generateAccessToken(user, nonce, scope),
      this.generateIdToken(user, nonce, scope),
    ]);

    return { accessToken, idToken };
  }
}
