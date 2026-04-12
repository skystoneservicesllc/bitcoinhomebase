import crypto from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';

// In-memory download counter (persists while the serverless function is warm)
// Maps token -> download count
const downloadCounts = new Map();

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

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { token } = req.query;

  if (!token) {
    return res.status(400).send(errorPage('Missing download token', 'This download link appears to be incomplete. Please check the link in your email.'));
  }

  // Verify the token signature
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(403).send(errorPage('Invalid download link', 'This download link is invalid or has been tampered with. If you purchased the ebook, please check your email for the original link.'));
  }

  // Check expiration
  if (Date.now() > payload.expiresAt) {
    return res.status(410).send(errorPage('Download link expired', 'This download link has expired (48-hour limit). Please contact <a href="mailto:skystoneservicesllc@gmail.com">skystoneservicesllc@gmail.com</a> for a new link.'));
  }

  // Check download count
  const currentCount = downloadCounts.get(token) || 0;
  if (currentCount >= (payload.maxDownloads || 3)) {
    return res.status(429).send(errorPage('Download limit reached', 'This link has reached its maximum number of downloads (3). Please contact <a href="mailto:skystoneservicesllc@gmail.com">skystoneservicesllc@gmail.com</a> if you need to download again.'));
  }

  // Increment download count
  downloadCounts.set(token, currentCount + 1);

  // Serve the file
  try {
    const filePath = join(process.cwd(), 'Bitcoin-Bonus-Bundle.zip');
    const fileBuffer = readFileSync(filePath);

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="Bitcoin-Bonus-Bundle.zip"');
    res.setHeader('Content-Length', fileBuffer.length);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');

    return res.status(200).send(fileBuffer);
  } catch (err) {
    console.error('File serve error:', err);
    return res.status(500).send(errorPage('Download error', 'There was a problem preparing your download. Please try again or contact <a href="mailto:skystoneservicesllc@gmail.com">skystoneservicesllc@gmail.com</a>.'));
  }
}

function errorPage(title, message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>\${title} | BitcoinHomeBase.com</title>
<meta name="robots" content="noindex, nofollow">
<style>
  *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #080B10;
    color: #E6EDF3;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 24px;
  }
  .error-card {
    background: #161B22;
    border: 1px solid #21262D;
    border-radius: 16px;
    padding: 48px 36px;
    max-width: 480px;
    text-align: center;
  }
  .error-icon {
    width: 64px; height: 64px;
    border-radius: 50%;
    background: rgba(248,81,73,0.15);
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 24px;
    font-size: 28px;
  }
  h1 {
    font-size: 22px;
    font-weight: 700;
    margin-bottom: 12px;
    color: #fff;
  }
  p {
    font-size: 16px;
    color: #8B949E;
    line-height: 1.7;
  }
  a { color: #F7931A; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .home-link {
    display: inline-block;
    margin-top: 24px;
    padding: 12px 32px;
    background: #F7931A;
    color: #000;
    font-weight: 700;
    border-radius: 8px;
    text-decoration: none;
  }
  .home-link:hover { background: #E8850F; text-decoration: none; }
</style>
</head>
<body>
  <div class="error-card">
    <div class="error-icon">&#9888;&#65039;</div>
    <h1>\${title}</h1>
    <p>\${message}</p>
    <a href="https://www.bitcoinhomebase.com" class="home-link">Back to BitcoinHomeBase</a>
  </div>
</body>
</html>`;
}
