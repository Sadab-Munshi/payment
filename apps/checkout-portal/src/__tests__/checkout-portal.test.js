import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startCheckoutServer } from '../index.js';
import { generateQrMatrix, generateQrSvg } from '../qr.js';
import { readFile } from 'node:fs/promises';

describe('Checkout Portal Integration Tests', () => {
  let serverInstance;
  let baseUrl;

  before(async () => {
    // Start on high test port (7199)
    serverInstance = await startCheckoutServer(7199);
    baseUrl = `http://localhost:${serverInstance.port}`;
  });

  after(async () => {
    await serverInstance.close();
  });

  function get(path) {
    return new Promise((resolve, reject) => {
      http.get(`${baseUrl}${path}`, res => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          resolve({ status: res.statusCode, headers: res.headers, text: data });
        });
      }).on('error', reject);
    });
  }

  describe('QR Generator', () => {
    test('generateQrMatrix creates 29x29 matrix with finder patterns', () => {
      const matrix = generateQrMatrix('upi://pay?pa=store@upi&am=200.00');
      assert.equal(matrix.length, 29);
      assert.equal(matrix[0].length, 29);

      // Verify top-left finder pattern corner
      assert.equal(matrix[0][0], 1);
      assert.equal(matrix[0][6], 1);
      assert.equal(matrix[6][0], 1);
      assert.equal(matrix[6][6], 1);
    });

    test('generateQrSvg creates clean, valid SVG markup', () => {
      const svg = generateQrSvg('upi://pay?pa=merchant@upi&am=500.00', 240);
      assert.ok(svg.startsWith('<svg'));
      assert.ok(svg.includes('xmlns="http://www.w3.org/2000/svg"'));
      assert.ok(svg.includes('viewBox="0 0 240 240"'));
      assert.ok(svg.endsWith('</svg>'));
    });
  });

  describe('HTTP Endpoints', () => {
    test('GET /health returns UP', async () => {
      const res = await get('/health');
      assert.equal(res.status, 200);
      const json = JSON.parse(res.text);
      assert.equal(json.status, 'UP');
      assert.equal(json.service, 'checkout-portal');
    });

    test('GET /checkout/:id renders responsive HTML with injected payment ID', async () => {
      const testPaymentId = 'pay_test_uuid_12345';
      const res = await get(`/checkout/${testPaymentId}`);
      assert.equal(res.status, 200);
      assert.ok(res.headers['content-type'].includes('text/html'));

      assert.ok(res.text.includes('<!DOCTYPE html>'));
      assert.ok(res.text.includes('name="viewport"'));
      assert.ok(res.text.includes('PAYMENT_ID = "pay_test_uuid_12345"'));
      assert.ok(res.text.includes('id="preGatewayAuthView"'));
      assert.ok(res.text.includes('id="paymentGatewayInterface"'));
      assert.ok(res.text.includes('id="authMobileInput"'));
      assert.ok(res.text.includes('id="btnAuthContinue"'));
      assert.ok(res.text.includes('WhatsApp Mobile Number'));
      assert.ok(res.text.includes('id="authStepSignup"'));
      assert.ok(res.text.includes('id="authStepOtp"'));

      // INVARIANT: Zero UPI Offer artifacts
      assert.equal(res.text.includes('6 Offers'), false);
      assert.equal(res.text.includes('View Offers'), false);
      assert.equal(res.text.includes('id="checkoutNoticeText"'), false);
      assert.equal(res.text.includes('available-offers-card'), false);
    });

    test('GET /checkout/:id/qr.svg returns dynamic SVG image', async () => {
      const res = await get('/checkout/pay_test_uuid_12345/qr.svg');
      assert.equal(res.status, 200);
      assert.ok(res.headers['content-type'].includes('image/svg+xml'));
      assert.ok(res.text.includes('<svg'));
      assert.ok(res.text.includes('</svg>'));
    });

    test('GET /icons/:filename returns official Play Store icons with correct MIME type', async () => {
      const res = await get('/icons/gpay.png');
      assert.equal(res.status, 200);
      assert.ok(res.headers['content-type'].includes('image/png'));
      assert.ok(res.text.length > 500);

      const resPhonePe = await get('/icons/phonepe.png');
      assert.equal(resPhonePe.status, 200);
      assert.ok(resPhonePe.headers['content-type'].includes('image/png'));
    });

    test('GET /youpi.js and /sdk/youpi-checkout.js return official integration SDK with CORS', async () => {
      const resYoupi = await get('/youpi.js');
      assert.equal(resYoupi.status, 200);
      assert.ok(resYoupi.headers['content-type'].includes('application/javascript'));
      assert.equal(resYoupi.headers['access-control-allow-origin'], '*');
      assert.ok(resYoupi.text.includes('YoupiCheckout'));
      assert.ok(resYoupi.text.includes('data-youpi-pay'));
      assert.ok(resYoupi.text.includes('youpi:payment:success'));

      const resLegacy = await get('/sdk/youpi-checkout.js');
      assert.equal(resLegacy.status, 200);
      assert.ok(resLegacy.headers['content-type'].includes('application/javascript'));
      assert.equal(resLegacy.headers['access-control-allow-origin'], '*');
      assert.ok(resLegacy.text.includes('YoupiCheckout'));
    });

    test('GET /checkout/:id includes PC 2-column sidebar, UPI Server indicator, and NO visual UPI ID in summary', async () => {
      const res = await get('/checkout/pay_test_uuid_12345');
      assert.equal(res.status, 200);

      // Verify PC Redesign sidebar & header exists
      assert.ok(res.text.includes('ypg-pc-sidebar'));
      assert.ok(res.text.includes('id="pcMerchantName"'));
      assert.ok(res.text.includes('id="pcPriceSummaryAmount"'));
      assert.ok(res.text.includes('ypg-pc-topbar'));

      // Verify UPI Server indicator
      assert.ok(res.text.includes('id="upiServerHealthIndicator"'));
      assert.ok(res.text.includes('id="serverStatusLabel"'));
      assert.ok(res.text.includes('id="serverDowntimeAlert"'));

      // Verify Play Store icons are referenced
      assert.ok(res.text.includes('/icons/gpay.png'));
      assert.ok(res.text.includes('/icons/phonepe.png'));
      assert.ok(res.text.includes('/icons/paytm.png'));

      // INVARIANT: Raw Payee VPA / UPI ID row is REMOVED from Order Summary
      assert.equal(res.text.includes('id="drawerVpa"'), false);
    });
  });

  // Regression guard: the portal serves sdk/youpi.js when it exists and only
  // falls back to sdk/youpi-checkout.js, so a feature added to one file is
  // silently ignored in the browser. Assert both carry the UPI hand-off.
  describe('UPI app hand-off (SDK surface)', () => {
    const sdkFiles = ['youpi.js', 'youpi-checkout.js'];

    for (const file of sdkFiles) {
      test(`${file} can render and launch the UPI hand-off`, async () => {
        const sdkPath = new URL(`../sdk/${file}`, import.meta.url);
        const src = await readFile(sdkPath, 'utf8');

        // The frame reports its URI; the SDK renders the button in the modal
        // chrome, where the tap carries real user activation.
        assert.ok(src.includes("event === 'youpi.upi_ready'"), `${file} missing the youpi.upi_ready branch`);
        assert.ok(src.includes('_renderUpiLaunch'), `${file} missing _renderUpiLaunch`);
        assert.ok(src.includes('_buildUpiIntent'), `${file} missing _buildUpiIntent`);
        assert.ok(src.includes('.youpi-upi-launch-bar'), `${file} missing the footer bar styles`);

        // Android intent, no package pinning (system chooser = "any UPI app").
        assert.ok(src.includes("'scheme=upi'"), `${file} must build a upi-scheme intent`);
        assert.equal(/package=/.test(src), false, `${file} must not pin a UPI app package`);
      });
    }
  });

});
