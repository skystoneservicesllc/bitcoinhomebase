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

async function sendDownloadEmail(email, downloadUrl, customerName) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL || 'BitcoinHomeBase <onboarding@resend.dev>',
      to: [email],
      subject: 'Your Bitcoin Ebook Bundle Is Ready to Download',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="text-align: center; padding: 20px 0;">
            <h1 style="color: #f7931a; margin: 0;">BitcoinHomeBase</h1>
            <p style="color: #666; margin: 5px 0;">Your Digital Download</p>
          </div>
          <div style="background: #f9f9f9; border-radius: 8px; padding: 30px; margin: 20px 0;">
            <h2 style="color: #333; margin-top: 0;">Thank You for Your Purchase!</h2>
            <p style="color: #555; line-height: 1.6;">
              Hi${customerName ? ' ' + customerName : ''},
            </p>
            <p style="color: #555; line-height: 1.6;">
              Your Bitcoin ebook bundle is ready for download. Click the button below to get your files:
            </p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${downloadUrl}"
                 style="background: #f7931a; color: white; padding: 15px 40px; text-decoration: none; border-radius: 6px; font-size: 18px; font-weight: bold; display: inline-block;">
                Download Your Bundle
              </a>
            </div>
            <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 15px; margin: 20px 0;">
              <p style="color: #856404; margin: 0; font-size: 14px;">
                <strong>Important:</strong> This download link expires in 48 hours and can be used up to 3 times. Please download your files soon!
              </p>
            </div>
          </div>
          <div style="text-align: center; padding: 20px 0; border-top: 1px solid #eee;">
            <p style="color: #999; font-size: 12px; margin: 5px 0;">
              60-Day Money-Back Guarantee | Questions? Reply to this email.
            </p>
            <p style="color: #999; font-size: 12px; margin: 5px 0;">
              &copy; 2026 BitcoinHomeBase.com | All Rights Reserved
            </p>
          </div>
        </div>
      `,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(`Failed to send email: ${response.status} ${JSON.stringify(errorData)}`);
  }

  return await response.json();
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!sig || !webhookSecret) {
    console.error('Missing signature or webhook secret');
    return res.status(400).json({ error: 'Missing signature or webhook secret' });
  }

  let event;
  try {
    const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);

    // Verify webhook signature manually (without Stripe SDK)
    const timestamp = sig.split(',').find(s => s.startsWith('t=')).split('=')[1];
    const signatures = sig.split(',').filter(s => s.startsWith('v1=')).map(s => s.split('=')[1]);

    const signedPayload = `${timestamp}.${rawBody}`;
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(signedPayload)
      .digest('hex');

    const isValid = signatures.some(s => {
      try {
        return crypto.timingSafeEqual(
          Buffer.from(s, 'hex'),
          Buffer.from(expectedSignature, 'hex')
        );
      } catch {
        return false;
      }
    });

    if (!isValid) {
      console.error('Invalid webhook signature');
      return res.status(400).json({ error: 'Invalid signature' });
    }

    event = JSON.parse(rawBody);
  } catch (err) {
    console.error('Webhook parsing error:', err.message);
    return res.status(400).json({ error: 'Webhook parsing failed' });
  }

  // Handle checkout.session.completed
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const customerEmail = session.customer_details?.email || session.customer_email;
    const customerName = session.customer_details?.name || '';

    if (!customerEmail) {
      console.error('No customer email found in session');
      return res.status(200).json({ received: true, warning: 'No email found' });
    }

    try {
      const token = generateSignedToken(customerEmail, session.id);
      const baseUrl = process.env.VERCEL_URL
        ? `https://${process.env.VERCEL_URL}`
        : 'https://bitcoinhomebase.com';
      const downloadUrl = `${baseUrl}/api/download?token=${token}`;

      await sendDownloadEmail(customerEmail, downloadUrl, customerName);
      console.log(`Download email sent to ${customerEmail}`);
    } catch (error) {
      console.error('Error processing checkout:', error);
      return res.status(200).json({ received: true, warning: 'Email send failed' });
    }
  }

  return res.status(200).json({ received: true });
}
