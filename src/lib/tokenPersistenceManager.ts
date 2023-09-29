import * as crypto from 'crypto'
import { redisClient } from './redisClient';

export type SavedTokens = {
    idToken: string,
    refreshToken?: string,
}

interface TokenPersistenceManager {
    saveTokens: (tokens: SavedTokens) => Promise<string>
    saveTokensForSession: (tokens: SavedTokens, sessionId: string) => Promise<void>
    getTokens: (key: string) => Promise<SavedTokens>
    deleteTokens: (key: string) => Promise<void>
}

class RedisTokenPersistenceManager implements TokenPersistenceManager {

    async saveTokens(tokens: SavedTokens): Promise<string> {
        const sessionId = crypto.randomBytes(32).toString('base64');
        await this.saveTokensForSession(tokens, sessionId)
        return sessionId
    }

    async saveTokensForSession(tokens: SavedTokens, sessionId: string): Promise<void> {
        const idTokenKey = `idtoken:${sessionId}`
        // TODO: see if we can store both using 1 DB call
        // TODO: see if we need a await here
        redisClient.set(idTokenKey, tokens.idToken)

        if (tokens.refreshToken) {
            const refreshTokenKey = `refreshtoken:${sessionId}`
            redisClient.set(refreshTokenKey, tokens.refreshToken)
        }
    }

    async getTokens(key: string): Promise<SavedTokens> {
        // TODO: see if we can retrieve both using 1 DB call
        const idTokenKey = `idtoken:${key}`
        const idToken = await redisClient.get(idTokenKey)

        if (!idToken) {
            throw new Error(`No ID token found for key ${key}`)
        }

        const refreshTokenKey = `refreshtoken:${key}`
        const refreshToken = await redisClient.get(refreshTokenKey)

        return {
            idToken,
            refreshToken: refreshToken || undefined // TODO: see if we can avoid this
        }
    }

    async deleteTokens(key: string): Promise<void> {
        const idTokenKey = `idtoken:${key}`
        const refreshTokenKey = `refreshtoken:${key}`
        await redisClient.del(idTokenKey)
        await redisClient.del(refreshTokenKey)
    }
}

export const tokenPersistenceManager: TokenPersistenceManager = new RedisTokenPersistenceManager()