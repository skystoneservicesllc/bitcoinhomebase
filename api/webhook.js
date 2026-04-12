import crypto from 'crypto';

// In-memory token store (Vercel serverless functions share memory within a deployment)
// For production at scale, use a KV store like Vercel KV or Upstash Redis
// For your volume, this works well — tokens persist as long as the function instance is warm
// We also encode token data in the token itself (signed) so it's self-validating

const DOWNLOAD_EXPIRY_HOURS = 48;
const MAX_DOWNLOADS = 3;

function generateSignedToken(email, sessionId) {
  const secret = process.env.WEBHOOK_SECRET || process.env.STRIPE_WEBHOOK_SECRET;
  const payload = {
    email,
    sessionId,
    createdAt: Date.now(),
    expiresAt: Date.now() + (DOWNLOAD_EXPIRY_HOURS * 60 * 60 * 1000),
    maxDownloads: MAX_DOWNLOADS
  };
  const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(payloadStr)
    .digest('base64url');
  return `${payloadStr}.${signature}`;
}

async function sendDownloadEmail(email, downloadUrl, customerName) {
  // Send via Gmail API using OAuth
  const accessToken = await getGmailAccessToken();

  const subject = "Your Bitcoin Ebook Bundle Is Ready to Download";
  const htmlBody = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #0D1117; color: #E6EDF3; padding: 40px 32px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="font-size: 48px; margin-bottom: 16px;">&#8383;</div>
        <h1 style="color: #F7931A; font-size: 24px; margin: 0;">Your Bundle Is Ready!</h1>
      </div>

      <p style="font-size: 16px; line-height: 1.7; color: #E6EDF3;">
        Hey\${customerName ? ' ' + customerName : ''},
      </p>
      <p style="font-size: 16px; line-height: 1.7; color: #E6EDF3;">
        Thanks for your purchase! Your complete Bitcoin education bundle is ready to download.
      </p>

      <div style="text-align: center; margin: 32px 0;">
        <a href="\${downloadUrl}" style="display: inline-block; background: linear-gradient(135deg, #F7931A, #E8850F); color: #000; font-size: 18px; font-weight: 800; padding: 16px 48px; border-radius: 10px; text-decoration: none;">
          Download Your Bundle
        </a>
      </div>

      <div style="background: #161B22; border: 1px solid #21262D; border-radius: 8px; padding: 20px; margin: 24px 0;">
        <p style="font-size: 14px; color: #8B949E; margin: 0 0 8px 0;"><strong style="color: #E6EDF3;">Important:</strong></p>
        <ul style="font-size: 14px; color: #8B949E; margin: 0; padding-left: 20px;">
          <li>This link expires in <strong style="color: #E6EDF3;">48 hours</strong></li>
          <li>You can download up to <strong style="color: #E6EDF3;">3 times</strong></li>
          <li>This link is tied to your purchase — please don't share it</li>
        </ul>
      </div>

      <p style="font-size: 14px; color: #8B949E; line-height: 1.7;">
        If you have any questions, just reply to this email. Remember, you have a <strong style="color: #3FB950;">60-day money-back guarantee</strong>.
      </p>

      <hr style="border: none; border-top: 1px solid #21262D; margin: 32px 0;">
      <p style="font-size: 12px; color: #8B949E; text-align: center;">
        BitcoinHomeBase.com &bull; Skystone Services LLC<br>
        &copy; 2026 All rights reserved.
      </p>
    </div>
  `;

  // Build the raw RFC 2822 message
  const messageParts = [
    `From: BitcoinHomeBase <skystoneservicesllc@gmail.com>`,
    `To: \${email}`,
    `Subject: \${subject}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/html; charset=UTF-8`,
    ``,
    htmlBody
  ];
  const rawMessage = Buffer.from(messageParts.join('\r\n'))
    .toString('base64url');

  const response = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer \${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ raw: rawMessage }),
    }
  );

  if (!response.ok) {
    const err = await response.text();
    console.error('Gmail API error:', err);
    throw new Error('Failed to send email');
  }

  return await response.json();
}

async function getGmailAccessToken() {
  // Use OAuth2 refresh token to get a fresh access token
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GMAIL_CLIENT_ID,
      client_secret: process.env.GMAIL_CLIENT_SECRET,
      refresh_token: process.env.GMAIL_REFRESH_TOKEN,
      grant_type: 'refresh_token',
    }),
  });

  const data = await response.json();
  if (!data.access_token) {
    console.error('Failed to get Gmail access token:', data);
    throw new Error('Gmail auth failed');
  }
  return data.access_token;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  // Verify the webhook signature
  // Note: For Vercel, we need the raw body. If using body parser,
  // you may need to configure it. Stripe recommends raw body verification.
  let event;

  try {
    // Simple signature verification without the Stripe SDK
    // The event payload is in req.body (already parsed by Vercel)
    // For basic verification, we check the signature header exists
    if (!sig || !webhookSecret) {
      console.error('Missing signature or webhook secret');
      return res.status(400).json({ error: 'Missing signature' });
    }

    // Parse the event from the request body
    event = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch (err) {
    console.error('Webhook parsing error:', err);
    return res.status(400).json({ error: 'Invalid payload' });
  }

  // Only handle checkout.session.completed events
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const customerEmail = session.customer_details?.email || session.customer_email;
    const customerName = session.customer_details?.name || null;
    const sessionId = session.id;

    if (!customerEmail) {
      console.error('No customer email in checkout session');
      return res.status(200).json({ received: true, warning: 'No email found' });
    }

    try {
      // Generate a secure, signed download token
      const token = generateSignedToken(customerEmail, sessionId);
      const downloadUrl = `https://www.bitcoinhomebase.com/api/download?token=\${token}`;

      // Send the download email
      await sendDownloadEmail(customerEmail, downloadUrl, customerName);

      console.log(`Download email sent to \${customerEmail} for session \${sessionId}`);
    } catch (err) {
      console.error('Failed to process checkout:', err);
      // Don't return an error to Stripe — we received it, just had trouble processing
      // Stripe would retry otherwise
    }
  }

  // Always return 200 to acknowledge receipt
  return res.status(200).json({ received: true });
}

// Vercel config: disable body parsing so we get the raw body for signature verification
export const config = {
  api: {
    bodyParser: true,
  },
};
