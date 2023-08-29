import type { RedisClientType } from 'redis'
import { createClient } from 'redis'

let redisClient: RedisClientType
let isReady: boolean

const redisClientConfigs = {
  socket: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
  },
  password: process.env.REDIS_PASSWORD,
  username: process.env.REDIS_USERNAME,
}

async function getRedisClient(): Promise<RedisClientType> {
  if (!isReady) {
    redisClient = createClient({
      ...redisClientConfigs,
    })
    redisClient.on('error', err => console.warn(`Redis Error: ${err}`))
    redisClient.on('connect', () => console.log('Redis connected'))
    redisClient.on('reconnecting', () => console.log('Redis reconnecting'))
    redisClient.on('ready', () => {
      isReady = true
      console.log('Redis ready!')
    })
    await redisClient.connect()
  }
  return redisClient
}

getRedisClient().then(connection => {
  redisClient = connection
}).catch(err => {
  console.warn({ err }, 'Failed to connect to Redis')
})

export {
  getRedisClient,
}
