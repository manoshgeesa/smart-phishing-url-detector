const express = require('express');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('./db/database');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from React build in production
app.use(express.static(path.join(__dirname, 'client', 'build')));

// ─── Phishing Detection Engine ───────────────────────────────────────────────

/**
 * Analyzes a URL for phishing indicators and returns a risk assessment.
 * Each check adds to a weighted risk score.
 */
function analyzeUrl(url) {
  const indicators = [];
  let riskScore = 0;

  // Normalize the URL
  let normalizedUrl = url.trim().toLowerCase();
  if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
    normalizedUrl = 'http://' + normalizedUrl;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(normalizedUrl);
  } catch (e) {
    return {
      status: 'phishing',
      riskScore: 100,
      indicators: [{ type: 'critical', message: 'Invalid URL format — likely malicious or broken' }],
      details: { hostname: url, protocol: 'unknown', path: 'unknown' }
    };
  }

  const hostname = parsedUrl.hostname;
  const fullPath = parsedUrl.pathname + parsedUrl.search;

  // ── Check 1: HTTP vs HTTPS ──────────────────────────────────────────────
  if (parsedUrl.protocol === 'http:') {
    riskScore += 15;
    indicators.push({
      type: 'warning',
      message: 'Uses HTTP instead of HTTPS — connection is not encrypted'
    });
  }

  // ── Check 2: IP address instead of domain ───────────────────────────────
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(hostname)) {
    riskScore += 30;
    indicators.push({
      type: 'danger',
      message: 'Uses an IP address instead of a domain name'
    });
  }

  // ── Check 3: Suspicious TLDs ────────────────────────────────────────────
  const suspiciousTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.buzz', '.club', '.work', '.loan', '.click', '.link', '.info', '.biz', '.stream', '.download', '.racing', '.win', '.review', '.accountant', '.science', '.party', '.date', '.faith', '.cricket'];
  const tldMatch = suspiciousTlds.find(tld => hostname.endsWith(tld));
  if (tldMatch) {
    riskScore += 20;
    indicators.push({
      type: 'warning',
      message: `Uses suspicious top-level domain: ${tldMatch}`
    });
  }

  // ── Check 4: Excessive subdomains ───────────────────────────────────────
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount > 2) {
    riskScore += 15;
    indicators.push({
      type: 'warning',
      message: `Unusually many subdomains (${subdomainCount}) — may be trying to hide the real domain`
    });
  }

  // ── Check 5: Extremely long hostname ────────────────────────────────────
  if (hostname.length > 50) {
    riskScore += 15;
    indicators.push({
      type: 'warning',
      message: 'Unusually long hostname — often used to confuse users'
    });
  }

  // ── Check 6: Contains @ symbol ──────────────────────────────────────────
  if (url.includes('@')) {
    riskScore += 25;
    indicators.push({
      type: 'danger',
      message: 'Contains @ symbol — can redirect to a different site than displayed'
    });
  }

  // ── Check 7: Homograph / look-alike characters ──────────────────────────
  const homographPattern = /[а-яА-ЯёЁ\u0400-\u04FF\u0500-\u052F]/;
  if (homographPattern.test(url)) {
    riskScore += 35;
    indicators.push({
      type: 'danger',
      message: 'Contains Cyrillic or look-alike characters (homograph attack)'
    });
  }

  // ── Check 8: Brand impersonation ────────────────────────────────────────
  const targetBrands = [
    'paypal', 'apple', 'google', 'microsoft', 'facebook', 'amazon',
    'netflix', 'instagram', 'whatsapp', 'linkedin', 'twitter', 'chase',
    'wellsfargo', 'bankofamerica', 'citi', 'dropbox', 'icloud', 'outlook',
    'yahoo', 'ebay', 'usps', 'fedex', 'dhl', 'walmart', 'costco'
  ];
  const legitimateDomains = [
    'paypal.com', 'apple.com', 'google.com', 'microsoft.com', 'facebook.com',
    'amazon.com', 'netflix.com', 'instagram.com', 'whatsapp.com', 'linkedin.com',
    'twitter.com', 'x.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'citi.com', 'dropbox.com', 'icloud.com', 'outlook.com', 'yahoo.com',
    'ebay.com', 'usps.com', 'fedex.com', 'dhl.com', 'walmart.com', 'costco.com'
  ];

  for (const brand of targetBrands) {
    if (hostname.includes(brand)) {
      const isLegit = legitimateDomains.some(ld => hostname === ld || hostname.endsWith('.' + ld));
      if (!isLegit) {
        riskScore += 30;
        indicators.push({
          type: 'danger',
          message: `Impersonates "${brand}" but is not the official domain`
        });
        break;
      }
    }
  }

  // ── Check 9: Suspicious keywords in path ────────────────────────────────
  const suspiciousKeywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password', 'credential', 'suspend', 'locked', 'unusual', 'wallet', 'authenticate'];
  const pathLower = fullPath.toLowerCase();
  const foundKeywords = suspiciousKeywords.filter(kw => pathLower.includes(kw));
  if (foundKeywords.length > 0) {
    riskScore += Math.min(foundKeywords.length * 8, 25);
    indicators.push({
      type: 'warning',
      message: `Suspicious keywords in URL path: ${foundKeywords.join(', ')}`
    });
  }

  // ── Check 10: URL shortener ─────────────────────────────────────────────
  const shortenerDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tiny.cc', 'rb.gy', 'shorturl.at'];
  if (shortenerDomains.some(sd => hostname === sd || hostname.endsWith('.' + sd))) {
    riskScore += 10;
    indicators.push({
      type: 'info',
      message: 'URL shortener detected — the real destination is hidden'
    });
  }

  // ── Check 11: Hyphens in domain ─────────────────────────────────────────
  const domainPart = hostname.split('.').slice(0, -1).join('.');
  const hyphenCount = (domainPart.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    riskScore += 15;
    indicators.push({
      type: 'warning',
      message: `Excessive hyphens in domain name (${hyphenCount}) — common in phishing URLs`
    });
  }

  // ── Check 12: Numbers in domain name ────────────────────────────────────
  const numberPattern = /\d{4,}/;
  if (numberPattern.test(domainPart)) {
    riskScore += 10;
    indicators.push({
      type: 'info',
      message: 'Domain contains long numeric sequences'
    });
  }

  // ── Check 13: Punycode / internationalized domain ───────────────────────
  if (hostname.startsWith('xn--')) {
    riskScore += 20;
    indicators.push({
      type: 'warning',
      message: 'Uses Punycode (internationalized domain) — may be a homograph attack'
    });
  }

  // ── Check 14: Data URI or javascript protocol ───────────────────────────
  if (normalizedUrl.startsWith('data:') || normalizedUrl.startsWith('javascript:')) {
    riskScore += 40;
    indicators.push({
      type: 'danger',
      message: 'Uses data: or javascript: protocol — highly suspicious'
    });
  }

  // ── Check 15: Double dots or unusual characters ─────────────────────────
  if (hostname.includes('..') || /[!$%^*()+=\[\]{}|\\<>]/.test(hostname)) {
    riskScore += 15;
    indicators.push({
      type: 'warning',
      message: 'Contains unusual characters in hostname'
    });
  }

  // If no issues found, mark as safe
  if (indicators.length === 0) {
    indicators.push({
      type: 'safe',
      message: 'No suspicious patterns detected'
    });
  }

  // Cap the score at 100
  riskScore = Math.min(riskScore, 100);

  // Determine status
  let status;
  if (riskScore >= 60) {
    status = 'phishing';
  } else if (riskScore >= 25) {
    status = 'suspicious';
  } else {
    status = 'safe';
  }

  return {
    status,
    riskScore,
    indicators,
    details: {
      hostname,
      protocol: parsedUrl.protocol,
      path: fullPath || '/',
      fullUrl: normalizedUrl
    }
  };
}

// ─── API Routes ──────────────────────────────────────────────────────────────

// POST /api/scan — Analyze a URL
app.post('/api/scan', (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string' || url.trim().length === 0) {
    return res.status(400).json({ error: 'Please provide a valid URL to scan.' });
  }

  const trimmedUrl = url.trim();
  if (trimmedUrl.length > 2048) {
    return res.status(400).json({ error: 'URL is too long (max 2048 characters).' });
  }

  try {
    const result = analyzeUrl(trimmedUrl);

    // Store in database
    const scanId = uuidv4();
    const timestamp = new Date().toISOString();

    db.prepare(`
      INSERT INTO scans (id, url, status, risk_score, indicators, details, scanned_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      scanId,
      trimmedUrl,
      result.status,
      result.riskScore,
      JSON.stringify(result.indicators),
      JSON.stringify(result.details),
      timestamp
    );

    res.json({
      id: scanId,
      url: trimmedUrl,
      ...result,
      scannedAt: timestamp
    });
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: 'An error occurred while scanning the URL.' });
  }
});

// GET /api/history — Get scan history
app.get('/api/history', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const scans = db.prepare(`
      SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ? OFFSET ?
    `).all(limit, offset);

    const total = db.prepare('SELECT COUNT(*) as count FROM scans').get().count;

    const formattedScans = scans.map(scan => ({
      id: scan.id,
      url: scan.url,
      status: scan.status,
      riskScore: scan.risk_score,
      indicators: JSON.parse(scan.indicators),
      details: JSON.parse(scan.details),
      scannedAt: scan.scanned_at
    }));

    res.json({ scans: formattedScans, total });
  } catch (error) {
    console.error('History error:', error);
    res.status(500).json({ error: 'Failed to fetch scan history.' });
  }
});

// DELETE /api/history — Clear all history
app.delete('/api/history', (req, res) => {
  try {
    db.prepare('DELETE FROM scans').run();
    res.json({ message: 'Scan history cleared.' });
  } catch (error) {
    console.error('Clear history error:', error);
    res.status(500).json({ error: 'Failed to clear history.' });
  }
});

// DELETE /api/history/:id — Delete a single scan
app.delete('/api/history/:id', (req, res) => {
  try {
    const result = db.prepare('DELETE FROM scans WHERE id = ?').run(req.params.id);
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    res.json({ message: 'Scan deleted.' });
  } catch (error) {
    console.error('Delete scan error:', error);
    res.status(500).json({ error: 'Failed to delete scan.' });
  }
});

// GET /api/stats — Get scanning statistics
app.get('/api/stats', (req, res) => {
  try {
    const total = db.prepare('SELECT COUNT(*) as count FROM scans').get().count;
    const safe = db.prepare("SELECT COUNT(*) as count FROM scans WHERE status = 'safe'").get().count;
    const suspicious = db.prepare("SELECT COUNT(*) as count FROM scans WHERE status = 'suspicious'").get().count;
    const phishing = db.prepare("SELECT COUNT(*) as count FROM scans WHERE status = 'phishing'").get().count;
    const avgRisk = db.prepare('SELECT AVG(risk_score) as avg FROM scans').get().avg || 0;

    res.json({
      total,
      safe,
      suspicious,
      phishing,
      averageRiskScore: Math.round(avgRisk * 10) / 10
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics.' });
  }
});

// Catch-all: serve React app for any non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'build', 'index.html'));
});

// ─── Start Server ────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🛡️  Phishing Detection Server running on port ${PORT}`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   API:     http://localhost:${PORT}/api/scan\n`);
});
