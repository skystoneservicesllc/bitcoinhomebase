import crypto from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createClient } from 'redis';

// Redis client for persistent download counting
let redisClient = null;

async function getRedisClient() {
  if (!redisClient || !redisClient.isOpen) {
    redisClient = createClient({ url: process.env.REDIS_URL });
    redisClient.on('error', (err) => console.error('Redis error:', err));
    await redisClient.connect();
  }
  return redisClient;
}

async function getDownloadCount(tokenHash) {
  try {
    const redis = await getRedisClient();
    const count = await redis.get(`dl:${tokenHash}`);
    return parseInt(count || '0', 10);
  } catch (err) {
    console.error('Redis get error:', err);
    return 0; // Fail open on Redis errors
  }
}

async function incrementDownloadCount(tokenHash) {
  try {
    const redis = await getRedisClient();
    const newCount = await redis.incr(`dl:${tokenHash}`);
    // Set TTL of 72 hours (extra buffer beyond 48hr token expiry)
    await redis.expire(`dl:${tokenHash}`, 72 * 60 * 60);
    return newCount;
  } catch (err) {
    console.error('Redis incr error:', err);
    return 1; // Fail open on Redis errors
  }
}

function verifyToken(token) {
  const secret = process.env.WEBHOOK_SECRET || process.env.STRIPE_WEBHOOK_SECRET;

  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [payloadStr, signature] = parts;

  // Verify signature
  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(payloadStr)
    .digest('base64url');

  if (signature !== expectedSig) return null;

  // Decode payload
  try {
    const payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString());
    return payload;
  } catch {
    return null;
  }
}

function errorPage(title, message) {
  return `<!DOCTYPE html>
<html><head><title>${title} - BitcoinHomeBase</title>
<style>
  body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #1a1a2e; color: #fff; }
  .container { text-align: center; padding: 40px; max-width: 500px; }
  h1 { color: #f7931a; }
  p { color: #ccc; line-height: 1.6; }
  a { color: #f7931a; text-decoration: none; }
</style></head><body>
<div class="container">
  <h1>${title}</h1>
  <p>${message}</p>
  <p><a href="https://bitcoinhomebase.com">Return to BitcoinHomeBase</a></p>
</div></body></html>`;
}

export default async function handler(req, res) {
  const { token } = req.query;

  if (!token) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(400).send(errorPage('Missing Token', 'No download token provided. Please use the link from your purchase confirmation email.'));
  }

  // Verify the token signature and decode payload
  const payload = verifyToken(token);
  if (!payload) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(403).send(errorPage('Invalid Token', 'This download link is invalid. Please check your purchase confirmation email for the correct link.'));
  }

  // Check expiration
  if (Date.now() > payload.expiresAt) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(410).send(errorPage('Link Expired', 'This download link has expired (48-hour limit). Please contact support at skystoneservicesllc@gmail.com for a new download link.'));
  }

  // Check download count using Redis (persistent across cold starts)
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex').substring(0, 16);
  const currentCount = await getDownloadCount(tokenHash);

  if (currentCount >= (payload.maxDownloads || 3)) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(429).send(errorPage('Download Limit Reached', `This link has been used the maximum number of times (${payload.maxDownloads || 3} downloads). Please contact support at skystoneservicesllc@gmail.com if you need additional access.`));
  }

  // Increment download count BEFORE serving file (atomic)
  await incrementDownloadCount(tokenHash);

  // Serve the file
  try {
    const filePath = join(process.cwd(), 'Bitcoin-Bonus-Bundle.zip');
    const fileBuffer = readFileSync(filePath);

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="Bitcoin-Bonus-Bundle.zip"');
    res.setHeader('Content-Length', fileBuffer.length);
    return res.status(200).send(fileBuffer);
  } catch (err) {
    console.error('File read error:', err);
    res.setHeader('Content-Type', 'text/html');
    return res.status(500).send(errorPage('Download Error', 'There was an error preparing your download. Please try again or contact support at skystoneservicesllc@gmail.com'));
  }
}
