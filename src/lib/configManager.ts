import * as express from 'express'
import AppConfiguration from './appConfiguration';
import { getRedisClient } from './redisClient';
import { getRedisKey } from './getRedisKey';
import {config as defaultConfig} from '../appConfig'

class ConfigManager {
    async getConfigForRequest(req: express.Request): Promise<AppConfiguration> {
        return this.getConfig(getRedisKey(req));
    }

    async getConfig(key:string): Promise<AppConfiguration> {
        const redisClient = await getRedisClient()
        const result = await redisClient.hGetAll(key);
        const config = AppConfiguration.create(result)
        if (!config) {
            // TODO: currently this sends 500. Try to handle more gracefully
            // maybe redirect to error page?
            throw new Error(`No config found for key ${key}`)
        }
        return config
    }
}

export default new ConfigManager();
