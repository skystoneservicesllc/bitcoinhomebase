import crypto from 'crypto';
import nodemailer from 'nodemailer';

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
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'skystoneservicesllc@gmail.com',
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });

  const htmlBody = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #0D1117; color: #E6EDF3; padding: 40px 32px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="font-size: 48px; margin-bottom: 16px;">&#8383;</div>
        <h1 style="color: #F7931A; font-size: 24px; margin: 0;">Your Bundle Is Ready!</h1>
      </div>

      <p style="font-size: 16px; line-height: 1.7; color: #E6EDF3;">
        Hey${customerName ? ' ' + customerName : ''},
      </p>
      <p style="font-size: 16px; line-height: 1.7; color: #E6EDF3;">
        Thanks for your purchase! Your complete Bitcoin education bundle is ready to download.
      </p>

      <div style="text-align: center; margin: 32px 0;">
        <a href="${downloadUrl}" style="display: inline-block; background: linear-gradient(135deg, #F7931A, #E8850F); color: #000; font-size: 18px; font-weight: 800; padding: 16px 48px; border-radius: 10px; text-decoration: none;">
          Download Your Bundle
        </a>
      </div>

      <div style="background: #161B22; border: 1px solid #21262D; border-radius: 8px; padding: 20px; margin: 24px 0;">
        <p style="font-size: 14px; color: #8B949E; margin: 0 0 8px 0;"><strong style="color: #E6EDF3;">Important:</strong></p>
        <ul style="font-size: 14px; color: #8B949E; margin: 0; padding-left: 20px;">
          <li>This link expires in <strong style="color: #E6EDF3;">48 hours</strong></li>
          <li>You can download up to <strong style="color: #E6EDF3;">3 times</strong></li>
          <li>This link is tied to your purchase \u2014 please don't share it</li>
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

  await transporter.sendMail({
    from: 'BitcoinHomeBase <skystoneservicesllc@gmail.com>',
    to: email,
    subject: 'Your Bitcoin Ebook Bundle Is Ready to Download',
    html: htmlBody,
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  try {
    if (!sig || !webhookSecret) {
      console.error('Missing signature or webhook secret');
      return res.status(400).json({ error: 'Missing signature' });
    }

    event = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch (err) {
    console.error('Webhook parsing error:', err);
    return res.status(400).json({ error: 'Invalid payload' });
  }

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
      const token = generateSignedToken(customerEmail, sessionId);
      const downloadUrl = `https://www.bitcoinhomebase.com/api/download?token=\${token}`;

      await sendDownloadEmail(customerEmail, downloadUrl, customerName);

      console.log(`Download email sent to \${customerEmail} for session \${sessionId}`);
    } catch (err) {
      console.error('Failed to process checkout:', err);
    }
  }

  return res.status(200).json({ received: true });
}

export const config = {
  api: {
    bodyParser: true,
  },
};
