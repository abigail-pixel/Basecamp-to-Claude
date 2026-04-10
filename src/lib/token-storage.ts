import { promises as fs } from 'fs';
import { join } from 'path';
import axios from 'axios';
import type { OAuthTokens } from '../types/basecamp.js';

const TOKEN_FILE = join(process.cwd(), 'oauth_tokens.json');

interface TokenStorage {
  basecamp?: OAuthTokens;
}

export class TokenStorageManager {
  private static instance: TokenStorageManager;
  private tokenCache: TokenStorage | null = null;

  static getInstance(): TokenStorageManager {
    if (!TokenStorageManager.instance) {
      TokenStorageManager.instance = new TokenStorageManager();
    }
    return TokenStorageManager.instance;
  }

  private readTokensFromEnv(): TokenStorage | null {
    const accessToken = process.env.BASECAMP_ACCESS_TOKEN;
    const refreshToken = process.env.BASECAMP_REFRESH_TOKEN;
    const accountId = process.env.BASECAMP_ACCOUNT_ID;
    const expiresAt = process.env.BASECAMP_TOKEN_EXPIRES_AT;

    if (!accessToken) return null;

    return {
      basecamp: {
        accessToken,
        refreshToken,
        accountId: accountId || '',
        expiresAt,
        updatedAt: new Date().toISOString(),
      },
    };
  }

  private async readTokens(): Promise<TokenStorage> {
    if (this.tokenCache) {
      return this.tokenCache;
    }

    // In HTTP/production mode (PORT set), read from environment variables
    if (process.env.PORT) {
      const envTokens = this.readTokensFromEnv();
      if (envTokens) {
        this.tokenCache = envTokens;
        return this.tokenCache;
      }
    }

    try {
      const data = await fs.readFile(TOKEN_FILE, 'utf-8');
      this.tokenCache = JSON.parse(data);
      return this.tokenCache || {};
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        return {};
      }
      console.warn(`Error reading tokens: ${error.message}`);
      return {};
    }
  }

  private async writeTokens(tokens: TokenStorage): Promise<void> {
    // In HTTP/production mode, only update in-memory cache — no file writes
    if (process.env.PORT) {
      this.tokenCache = tokens;
      return;
    }

    try {
      await fs.writeFile(TOKEN_FILE, JSON.stringify(tokens, null, 2));
      await fs.chmod(TOKEN_FILE, 0o600);
      this.tokenCache = tokens;
    } catch (error: any) {
      console.error(`Error writing tokens: ${error.message}`);
      throw error;
    }
  }

  async storeToken(
    accessToken: string,
    refreshToken?: string,
    expiresIn?: number,
    accountId?: string
  ): Promise<boolean> {
    if (!accessToken) {
      return false;
    }

    const tokens = await this.readTokens();

    const expiresAt = expiresIn
      ? new Date(Date.now() + expiresIn * 1000).toISOString()
      : undefined;

    tokens.basecamp = {
      accessToken,
      refreshToken,
      accountId: accountId || tokens.basecamp?.accountId || '',
      expiresAt,
      updatedAt: new Date().toISOString(),
    };

    await this.writeTokens(tokens);
    return true;
  }

  async getToken(): Promise<OAuthTokens | null> {
    const tokens = await this.readTokens();
    return tokens.basecamp || null;
  }

  async isTokenExpired(): Promise<boolean> {
    const tokenData = await this.getToken();

    if (!tokenData || !tokenData.expiresAt) {
      return true;
    }

    try {
      const expiresAt = new Date(tokenData.expiresAt);
      // Add 5-minute buffer to account for clock differences
      const bufferTime = new Date(Date.now() + 5 * 60 * 1000);
      return expiresAt <= bufferTime;
    } catch {
      return true;
    }
  }

  async refreshAccessToken(): Promise<boolean> {
    const tokenData = await this.getToken();
    if (!tokenData?.refreshToken) {
      console.error('No refresh token available');
      return false;
    }

    const clientId = process.env.BASECAMP_CLIENT_ID;
    const clientSecret = process.env.BASECAMP_CLIENT_SECRET;
    const redirectUri = process.env.BASECAMP_REDIRECT_URI || 'http://localhost:8000/auth/callback';

    if (!clientId || !clientSecret) {
      console.error('Missing BASECAMP_CLIENT_ID or BASECAMP_CLIENT_SECRET for token refresh');
      return false;
    }

    try {
      const response = await axios.post('https://launchpad.37signals.com/authorization/token', {
        type: 'refresh',
        refresh_token: tokenData.refreshToken,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
      });

      const { access_token, refresh_token, expires_in } = response.data;

      // Update in-memory cache directly
      const tokens = await this.readTokens();
      if (tokens.basecamp) {
        tokens.basecamp.accessToken = access_token;
        if (refresh_token) tokens.basecamp.refreshToken = refresh_token;
        if (expires_in) {
          tokens.basecamp.expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();
        }
        tokens.basecamp.updatedAt = new Date().toISOString();
        this.tokenCache = tokens;
      }

      console.error('OAuth token refreshed successfully');
      return true;
    } catch (error: any) {
      console.error('Failed to refresh OAuth token:', error.response?.data || error.message);
      return false;
    }
  }

  async clearTokens(): Promise<boolean> {
    if (process.env.PORT) {
      this.tokenCache = null;
      return true;
    }

    try {
      await fs.unlink(TOKEN_FILE);
      this.tokenCache = null;
      return true;
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        return true;
      }
      console.error(`Error clearing tokens: ${error.message}`);
      return false;
    }
  }

  async hasValidToken(): Promise<boolean> {
    const token = await this.getToken();
    if (!token?.accessToken) {
      return false;
    }

    const expired = await this.isTokenExpired();
    return !expired;
  }
}

// Singleton instance
export const tokenStorage = TokenStorageManager.getInstance();
