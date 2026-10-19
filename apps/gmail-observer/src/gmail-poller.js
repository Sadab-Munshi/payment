import { PaymentObserverClient } from '@youpi/observer-sdk';
import { getObserverToken } from '@youpi/common';
import { BankEmailParser } from './parser.js';

function decodeHtmlEntities(str) {
  if (!str) return '';
  return str
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#8377;|&#x20b9;|&inr;/gi, '₹')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_m, code) => String.fromCharCode(Number(code)));
}

/**
 * Recursively extracts text/plain and text/html content from nested Gmail MIME payloads
 * (`multipart/mixed` -> `multipart/related` -> `multipart/alternative` -> `text/plain` / `text/html`).
 */
export function extractBodyFromGmailPayload(payload) {
  if (!payload) return '';

  const plainParts = [];
  const htmlParts = [];
  const otherParts = [];

  function walk(node) {
    if (!node) return;
    const mime = (node.mimeType || '').toLowerCase();

    if (node.body?.data) {
      try {
        const decoded = Buffer.from(node.body.data, 'base64url').toString('utf8');
        if (mime === 'text/plain') {
          plainParts.push(decoded);
        } else if (mime === 'text/html') {
          const stripped = decodeHtmlEntities(
            decoded
              .replace(/<style[\s\S]*?<\/style>/gi, ' ')
              .replace(/<script[\s\S]*?<\/script>/gi, ' ')
              .replace(/<[^>]+>/g, ' ')
              .replace(/\s+/g, ' ')
          ).trim();
          if (stripped) htmlParts.push(stripped);
        } else if (!mime.startsWith('image/') && !mime.startsWith('application/')) {
          otherParts.push(decoded);
        }
      } catch {}
    }

    if (Array.isArray(node.parts)) {
      for (const child of node.parts) {
        walk(child);
      }
    }
  }

  walk(payload);

  if (plainParts.length > 0 && htmlParts.length > 0) {
    // Combine both plain and stripped HTML if plain text is a short stub
    const plainJoined = decodeHtmlEntities(plainParts.join('\n')).trim();
    const htmlJoined = htmlParts.join('\n').trim();
    return plainJoined.length >= htmlJoined.length * 0.5
      ? plainJoined
      : `${plainJoined}\n${htmlJoined}`.trim();
  }
  if (plainParts.length > 0) {
    return decodeHtmlEntities(plainParts.join('\n')).trim();
  }
  if (htmlParts.length > 0) {
    return htmlParts.join('\n').trim();
  }
  if (otherParts.length > 0) {
    return decodeHtmlEntities(otherParts.join('\n')).trim();
  }
  return '';
}

export class GmailPoller {
  /**
   * @param {{
   *   apiBaseUrl?: string,
   *   receivingAccountId?: string,
   *   pollIntervalMs?: number
   * }} options
   */
  constructor(options = {}) {
    this.apiBaseUrl = (options.apiBaseUrl || process.env.BASE_PAYMENT_API_URL || 'http://127.0.0.1:6100').replace(/\/+$/, '');
    this.receivingAccountId = options.receivingAccountId || '00000000-0000-0000-0000-000000000002';
    this.pollIntervalMs = options.pollIntervalMs || Number(process.env.GMAIL_POLL_INTERVAL_MS || 4000);
    this.observerClient = new PaymentObserverClient({
      apiBaseUrl: this.apiBaseUrl,
      sourceName: 'GMAIL'
    });

    this.isRunning = false;
    this.timer = null;
    this.lastPollAt = null;
    this.observedCount = 0;
    this.credentials = null;
    this.cachedAccessToken = null;
    this.tokenExpiresAt = 0;
    this.processedMessageIds = new Set();
  }

  setCredentials(creds) {
    this.credentials = { ...(this.credentials || {}), ...creds };
  }

  async fetchCredentialsFromPaymentApi() {
    try {
      const res = await fetch(`${this.apiBaseUrl}/api/v1/admin/gmail/credentials`, {
        headers: { Authorization: `Bearer ${getObserverToken()}` },
        signal: AbortSignal.timeout(4000)
      });
      if (res.ok) {
        const data = await res.json();
        const conf = data.gmailConfig || data;
        if (conf.refreshToken || conf.clientId) {
          this.setCredentials({
            clientId: conf.clientId,
            clientSecret: conf.clientSecret,
            refreshToken: conf.refreshToken,
            connectedEmail: conf.connectedEmail
          });
        }
      }
    } catch {}
  }

  async getAccessToken() {
    if (this.cachedAccessToken && Date.now() < this.tokenExpiresAt) {
      return this.cachedAccessToken;
    }

    if (!this.credentials?.refreshToken || !this.credentials?.clientId || !this.credentials?.clientSecret) {
      await this.fetchCredentialsFromPaymentApi();
    }

    const { clientId, clientSecret, refreshToken } = this.credentials || {};
    if (!clientId || !clientSecret || !refreshToken) return null;

    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          refresh_token: refreshToken,
          grant_type: 'refresh_token'
        }),
        signal: AbortSignal.timeout(8000)
      });

      if (!tokenRes.ok) {
        const errText = await tokenRes.text().catch(() => '');
        console.warn(`[Gmail Observer] OAuth token refresh failed (${tokenRes.status}): ${errText}`);
        return null;
      }

      const tokenData = await tokenRes.json();
      this.cachedAccessToken = tokenData.access_token;
      this.tokenExpiresAt = Date.now() + ((tokenData.expires_in || 3500) - 120) * 1000;
      return this.cachedAccessToken;
    } catch (err) {
      console.warn('[Gmail Observer] Failed to refresh Google access token:', err.message);
      return null;
    }
  }

  /**
   * Resolves the active receiving account from Payment API's `/api/v1/pollers/active-window`.
   * Passes the observer Bearer token and prefers a session matching `amountPaise` when available.
   */
  async resolveActiveReceivingAccount(amountPaise) {
    try {
      const res = await fetch(`${this.apiBaseUrl}/api/v1/pollers/active-window`, {
        headers: { Authorization: `Bearer ${getObserverToken()}` },
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) {
        const data = await res.json();
        const sessions = Array.isArray(data.sessions) ? data.sessions : [];
        if (sessions.length > 0) {
          if (amountPaise !== undefined && amountPaise !== null) {
            const targetPaise = Number(amountPaise);
            const exact = sessions.find(s => Number(s.amountPaise) === targetPaise && s.receivingAccountId);
            if (exact) return exact.receivingAccountId;
          }
          if (sessions[0].receivingAccountId) {
            return sessions[0].receivingAccountId;
          }
        }
      }
    } catch {}
    return null;
  }

  /**
   * Ingests an email directly (e.g. from Gmail API poll, sweep, or test injection).
   * @param {{ subject: string, body: string, date?: string | Date, from?: string, id?: string, internalDate?: number }} email
   */
  async processEmail(email) {
    let parsed = null;
    try {
      parsed = BankEmailParser.parse(email);
    } catch {}

    let targetAccountId = this.receivingAccountId;
    try {
      const activeAcct = await this.resolveActiveReceivingAccount(parsed?.amountPaise);
      if (activeAcct) targetAccountId = activeAcct;
    } catch {}

    const sender = email.from || email.sender || 'alerts@retail.bank.in';
    const rawContent = `${email.subject || ''}\n${email.body || ''}`.trim();

    try {
      const result = await this.observerClient.submitObservation({
        receivingAccountId: targetAccountId,
        amountPaise: parsed ? parsed.amountPaise : undefined,
        amount: parsed ? parsed.amount : undefined,
        observedAt: email.date ? new Date(email.date) : new Date(),
        bankReferenceNumber: parsed?.bankReferenceNumber,
        senderVpa: parsed?.senderVpa,
        sender,
        rawText: rawContent,
        rawPayload: {
          messageId: email.id || email.messageId || `gmail_${Date.now()}`,
          subject: email.subject || '',
          body: email.body || '',
          snippet: parsed?.rawSnippet || (email.body || '').substring(0, 200),
          from: sender,
          sender,
          source: 'GMAIL',
          internalDate: email.internalDate || (email.date ? new Date(email.date).getTime() : Date.now())
        }
      });

      this.observedCount++;
      if (parsed?.amount) {
        console.log(
          `[Gmail Observer] Processed bank email (amount=₹${parsed.amount}, utr=${parsed.bankReferenceNumber || 'N/A'}, acct=${targetAccountId}, attributed=${Boolean(result?.attribution?.attributed || result?.pipeline?.success)})`
        );
      }
      return result;
    } catch (err) {
      console.error('[Gmail Observer] Submission failed:', err.message);
      throw err;
    }
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    console.log(`[Gmail Observer] Poller started (interval: ${this.pollIntervalMs}ms)`);

    // Run first poll cycle immediately
    this.pollCycle().catch(() => {});

    this.timer = setInterval(() => {
      this.pollCycle().catch(() => {});
    }, this.pollIntervalMs);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.isRunning = false;
    console.log('[Gmail Observer] Poller stopped.');
  }

  async pollCycle() {
    this.lastPollAt = new Date();

    try {
      const accessToken = await this.getAccessToken();
      if (!accessToken) return;

      // Search both subject and body for recent bank/UPI credit alerts (covers Kotak, HDFC, ICICI, SBI, Axis, etc.)
      const query = encodeURIComponent(
        'newer_than:1d (credited OR credit OR received OR upi OR deposit OR alert OR transaction OR kotak OR inr OR rs)'
      );
      const listRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&q=${query}`,
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(8000)
        }
      );

      if (!listRes.ok) {
        if (listRes.status === 401) {
          this.cachedAccessToken = null;
        }
        return;
      }

      const listData = await listRes.json();
      const messages = listData.messages || [];
      const freshnessCutoffMs = Date.now() - 30 * 60 * 1000; // Only ingest emails from last 30 minutes

      // Process oldest-to-newest among recent messages
      for (const m of [...messages].reverse()) {
        if (this.processedMessageIds.has(m.id)) continue;

        try {
          const msgRes = await fetch(
            `https://gmail.googleapis.com/gmail/v1/users/me/messages/${m.id}?format=full`,
            {
              headers: { Authorization: `Bearer ${accessToken}` },
              signal: AbortSignal.timeout(8000)
            }
          );
          if (!msgRes.ok) continue;

          const msgData = await msgRes.json();
          const internalMs = msgData.internalDate ? Number(msgData.internalDate) : Date.now();

          // Skip stale historical emails older than 30 minutes so startup doesn't replay old alerts
          if (internalMs < freshnessCutoffMs) {
            this.processedMessageIds.add(m.id);
            continue;
          }

          const headers = msgData.payload?.headers || [];
          const from = headers.find(h => h.name.toLowerCase() === 'from')?.value || '';
          const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || '';
          const dateStr = headers.find(h => h.name.toLowerCase() === 'date')?.value || '';
          const extractedBody = extractBodyFromGmailPayload(msgData.payload);
          const snippetText = decodeHtmlEntities(msgData.snippet || '');
          const body = extractedBody
            ? `${extractedBody}\n${snippetText}`.trim()
            : snippetText;

          const res = await this.processEmail({
            id: m.id,
            messageId: m.id,
            subject,
            body,
            from,
            date: msgData.internalDate
              ? new Date(Number(msgData.internalDate))
              : dateStr
              ? new Date(dateStr)
              : new Date(),
            internalDate: internalMs
          });

          // Only lock message ID as processed if it was attributed OR if there was no active session for its amount
          const wasAttributed = Boolean(
            res?.attribution?.attributed || res?.pipeline?.success
          );
          const parsedCheck = BankEmailParser.parse({ subject, body, from });
          if (wasAttributed || !parsedCheck) {
            this.processedMessageIds.add(m.id);
          } else {
            // If it's a valid credit email that arrived 2 seconds BEFORE the user clicked 'UPI' / 'I Have Paid',
            // allow re-checking on next sweep if within 2 minutes of arrival
            if (Date.now() - internalMs > 2 * 60 * 1000) {
              this.processedMessageIds.add(m.id);
            }
          }

          if (this.processedMessageIds.size > 500) {
            const firstKey = this.processedMessageIds.values().next().value;
            this.processedMessageIds.delete(firstKey);
          }
        } catch (msgErr) {
          console.warn(`[Gmail Observer] Error fetching message ${m.id}:`, msgErr.message);
        }
      }
    } catch (err) {
      console.warn('[Gmail Observer] pollCycle error:', err.message);
    }
  }
}
