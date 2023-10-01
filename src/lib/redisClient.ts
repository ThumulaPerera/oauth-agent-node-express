let Redis: any;

if (process.env.NODE_ENV === 'test') {
    Redis = require('ioredis-mock');
} else {
    // ref https://github.com/redis/ioredis/tree/main/examples/express
    Redis = require('ioredis');
}

const redisClient = new Redis({
    port: parseInt(process.env.REDIS_PORT || '6379'),
    host: process.env.REDIS_HOST || 'localhost',
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD,
});

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
