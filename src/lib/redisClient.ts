// ref https://github.com/redis/ioredis/tree/main/examples/express

import { createRedisClient } from './redisConfig';

const redisClient = createRedisClient();

const hgetallWithRetry = async (key: string, retries = 2): Promise<Record<string, string>> => {
  try {
    return await redisClient.hgetall(key);
  } catch (err) {
    if (retries === 0) {
      throw err;
    }
    return hgetallWithRetry(key, retries - 1);
  }
}

export { redisClient, hgetallWithRetry };
