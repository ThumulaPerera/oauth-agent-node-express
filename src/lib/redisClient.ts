import { Redis } from 'ioredis'

const redisClient = new Redis({
  port: parseInt(process.env.REDIS_PORT || '6379'), // Redis port
  host: process.env.REDIS_HOST || 'localhost', // Redis host
  username: process.env.REDIS_USERNAME, // needs Redis >= 6
  password: process.env.REDIS_PASSWORD,
});

export default redisClient;