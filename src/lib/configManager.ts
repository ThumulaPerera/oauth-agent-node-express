import * as express from 'express'
import AppConfiguration from './appConfiguration';
import { hgetallWithRetry } from './redisClient';
import { getRedisKey } from './getRedisKey';
import { InvalidConfigException } from './exceptions';

class ConfigManager {
    async getConfigForRequest(req: express.Request): Promise<AppConfiguration> {
        try {
            const key = getRedisKey(req)
            return await this.getConfig(key);
        } catch (e) {
            const error = new InvalidConfigException(e as Error)
            error.logInfo = 'Could not retrieve config for the request'
            throw error
        }
        
    }

    private async getConfig(key:string): Promise<AppConfiguration> {
        const result = await hgetallWithRetry(key);
        const config = AppConfiguration.create(result)
        if (!config) {
            throw new Error(`No config found for key ${key}`)
        }
        return config
    }
}

export default new ConfigManager();
