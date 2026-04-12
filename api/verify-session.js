import crypto from 'crypto';

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

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', 'https://www.bitcoinhomebase.com');
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { session_id } = req.body;

  if (!session_id) {
    return res.status(400).json({ error: 'Missing session_id' });
  }

  try {
    // Verify the Checkout Session with Stripe API
    const stripeResponse = await fetch(
      `https://api.stripe.com/v1/checkout/sessions/${session_id}`,
      {
        headers: {
          'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
        },
      }
    );

    if (!stripeResponse.ok) {
      return res.status(403).json({ error: 'Invalid session' });
    }

    const session = await stripeResponse.json();

    // Verify payment was successful
    if (session.payment_status !== 'paid') {
      return res.status(403).json({ error: 'Payment not completed' });
    }

    const email = session.customer_details?.email || session.customer_email;
    if (!email) {
      return res.status(400).json({ error: 'No email found for session' });
    }

    // Generate a secure download token
    const token = generateSignedToken(email, session_id);

    return res.status(200).json({
      success: true,
      downloadUrl: `/api/download?token=${token}`,
      email: email,
      expiresIn: '48 hours',
      maxDownloads: MAX_DOWNLOADS,
    });
  } catch (err) {
    console.error('Session verification error:', err);
    return res.status(500).json({ error: 'Verification failed' });
  }
}
