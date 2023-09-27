import { Redis as ProdRedis } from 'ioredis';
const Redis = require('ioredis-mock');

const createRedisClient = () => {
  if (process.env.NODE_ENV === 'test') {
    console.log('Using mock Redis client');
    // Mock the Redis client for testing
    return new Redis();
  }
  return new ProdRedis({
    port: parseInt(process.env.REDIS_PORT || '6379'),
    host: process.env.REDIS_HOST || 'localhost',
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD,
  });
};

export { createRedisClient };