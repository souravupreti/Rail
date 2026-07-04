const Redis = require('ioredis');

class RedisClient {
    static instance = null;
    static isConnected = false;

    static getInstance() {
        if (!RedisClient.instance) {
            RedisClient.instance = new Redis(process.env.REDIS_URL, {
                retryStrategy: (times) => {
                    const delay = Math.min(times * 50, 2000);
                    return delay;
                },
                maxRetriesPerRequest: 3,
            });

            RedisClient.instance.on('connect', () => {
                RedisClient.isConnected = true;
                console.log('Redis connected');
            });

            RedisClient.instance.on('error', (err) => {
                RedisClient.isConnected = false;
                console.error('Redis error:', err.message);
            });
        }
        return RedisClient.instance; // ← fixed: was inside the if block
    }
}

module.exports = { redis: RedisClient.getInstance(), RedisClient };