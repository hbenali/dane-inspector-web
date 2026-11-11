/* DANE / TLSA Inspector: TLSA lookups over DNS-over-HTTPS (dns.google), certificate matching with WebCrypto
   and a TLSA record generator. Certificates never leave the browser. No dependencies, no inline code
   (CSP: script-src 'self'). */
(function () {
  'use strict';

  var DOH = 'https://dns.google/resolve';
  var $ = function (id) { return document.getElementById(id); };

  // ---- Names and validation ----
  function normalizeHost(input) {
    return String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/:\d+$/, '').replace(/\.+$/, '');
  }
  function validHost(d) {
    if (!d || d.length > 253) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d) || d.indexOf(':') !== -1) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(l); });
  }
  function parsePort(v) {
    var s = String(v == null ? '' : v).trim();
    if (!/^\d{1,5}$/.test(s)) return null;
    var n = parseInt(s, 10);
    return n >= 1 && n <= 65535 ? n : null;
  }
  function tlsaName(host, port) { return '_' + port + '._tcp.' + host; }

  async function doh(name, type) {
    var res = await fetch(DOH + '?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type));
    if (!res.ok) throw new Error('DNS query failed (HTTP ' + res.status + ')');
    return res.json();
  }

  // ---- DANE vocabulary ----
  var USAGE = {
    0: { name: 'PKIX-TA', text: 'CA constraint: the chain must validate through the public CA named here (usual PKIX validation, plus this CA).' },
    1: { name: 'PKIX-EE', text: 'Service certificate constraint: the server certificate named here must also validate through a public CA.' },
    2: { name: 'DANE-TA', text: 'Trust anchor assertion: the chain must lead to the CA named here. No public CA is needed; DNSSEC is the trust root.' },
    3: { name: 'DANE-EE', text: 'Domain-issued certificate: the server\'s own certificate or key is pinned. No chain validation and no public CA.' }
  };
  var SELECTOR = {
    0: { name: 'Cert', text: 'matches against the full DER certificate.' },
    1: { name: 'SPKI', text: 'matches against the SubjectPublicKeyInfo only, so the record survives renewals that keep the same key.' }
  };
  var MATCHING = {
    0: { name: 'Full', text: 'the data is the exact selected bytes (no hash).', hexLen: 0 },
    1: { name: 'SHA-256', text: 'the data is a SHA-256 hash of the selected bytes.', hexLen: 64 },
    2: { name: 'SHA-512', text: 'the data is a SHA-512 hash of the selected bytes.', hexLen: 128 }
  };

  // Parse a TLSA answer: "3 1 1 <hex>" or the RFC 3597 form "\# <len> <hex>".
  function parseTlsa(data) {
    var s = String(data).trim(), m;
    if ((m = s.match(/^(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F\s]*)$/))) {
      return { usage: +m[1], selector: +m[2], matching: +m[3], hex: m[4].replace(/\s+/g, '').toLowerCase() };
    }
    if ((m = s.match(/^\\#\s+(\d+)\s+([0-9a-fA-F\s]*)$/))) {
      var hex = m[2].replace(/\s+/g, '').toLowerCase();
      if (hex.length < 6 || hex.length !== +m[1] * 2) return null;
      return { usage: parseInt(hex.slice(0, 2), 16), selector: parseInt(hex.slice(2, 4), 16), matching: parseInt(hex.slice(4, 6), 16), hex: hex.slice(6) };
    }
    return null;
  }

  // ---- Lookups ----
  async function queryTlsa(host, port) {
    var name = tlsaName(host, port);
    var out = { host: host, port: port, name: name, status: 0, ad: false, records: [], unparsed: 0, error: null };
    try {
      var d = await doh(name, 'TLSA');
      out.status = d.Status;
      out.ad = d.AD === true;
      var answers = (d.Answer || []).filter(function (x) { return x.type === 52; });
      answers.forEach(function (x) {
        var r = parseTlsa(x.data);
        if (r) { r.ttl = x.TTL; out.records.push(r); } else out.unparsed++;
      });
      if (d.Status !== 0 && d.Status !== 3) out.error = d.Status === 2 ? 'SERVFAIL (this can also mean the zone is DNSSEC-bogus)' : 'DNS error code ' + d.Status;
    } catch (e) { out.error = e.message; }
    return out;
  }

  function parseMX(data) {
    var m = String(data).trim().match(/^(\d+)\s+(\S+)$/);
    if (!m) return null;
    return { pref: parseInt(m[1], 10), host: m[2].replace(/\.$/, '').toLowerCase() || '.' };
  }
  async function queryMX(domain) {
    var d = await doh(domain, 'MX');
    if (d.Status === 3) throw new Error('Domain "' + domain + '" does not exist (NXDOMAIN)');
    if (d.Status !== 0) throw new Error('DNS lookup error: ' + (d.Comment || 'code ' + d.Status));
    var recs = (d.Answer || []).filter(function (r) { return r.type === 15; }).map(function (r) { return parseMX(r.data); }).filter(Boolean);
    recs.sort(function (x, y) { return x.pref - y.pref || x.host.localeCompare(y.host); });
    return { domain: domain, records: recs, ad: d.AD === true };
  }

  // ---- Rendering helpers ----
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function checkList(items) {
    var ul = el('ul', 'checks');
    var labels = { pass: 'ok', warn: 'warn', fail: 'fail', info: 'note' };
    var order = { fail: 0, warn: 1, info: 2, pass: 3 };
    items.slice().sort(function (a, b) { return order[a.level] - order[b.level]; }).forEach(function (c) {
      var li = el('li');
      li.append(el('span', 'chk ' + c.level, labels[c.level]));
      li.append(el('span', null, c.text));
      ul.append(li);
    });
    return ul;
  }
  function link(text, href) {
    var a = el('a', 'link', text);
    a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
    return a;
  }
  var views = { placeholder: $('placeholderState'), records: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }

  function renderError(title, msg) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', title));
    s.append(el('p', null, msg));
    box.append(s);
  }

  // ---- Analysis of one target ----
  function analyse(t, mailContext) {
    var items = [];
    var add = function (level, text) { items.push({ level: level, text: text }); };
    if (t.error) { add('fail', 'Lookup of ' + t.name + ' failed: ' + t.error + '.'); return items; }
    if (!t.records.length) {
      add('info', 'No TLSA record at ' + t.name + (t.status === 3 ? ' (NXDOMAIN)' : '') + ': DANE is not published for this host and port.');
      if (t.unparsed) add('warn', t.unparsed + ' TLSA record(s) could not be parsed.');
      return items;
    }
    if (t.ad) add('pass', 'The resolver validated this answer with DNSSEC (AD flag set).');
    else add('fail', 'NOT DNSSEC-validated (AD flag not set). DANE is only meaningful with DNSSEC: without it anybody on the path can forge or strip TLSA records, and DANE-aware clients ignore unauthenticated TLSA data (RFC 6698 section 4.1, RFC 7672 section 2.2). Treat this host as NOT protected by DANE.');
    var usable = 0, wrongUsage = 0;
    t.records.forEach(function (r) {
      var bad = !USAGE[r.usage] || !SELECTOR[r.selector] || !MATCHING[r.matching];
      var label = 'Record "' + r.usage + ' ' + r.selector + ' ' + r.matching + '"';
      if (bad) { add('fail', label + ' uses an unassigned value (usage 0-3, selector 0-1, matching 0-2).'); return; }
      var hl = MATCHING[r.matching].hexLen;
      if (hl && r.hex.length !== hl) add('fail', label + ': ' + MATCHING[r.matching].name + ' data must be ' + hl + ' hex characters, found ' + r.hex.length + '.');
      else if (!hl && !r.hex.length) add('fail', label + ' has empty certificate data.');
      else if (r.hex.length % 2) add('fail', label + ' has an odd number of hex digits.');
      if (r.usage <= 1) {
        wrongUsage++;
        if (mailContext) add('warn', label + ': usage ' + r.usage + ' (' + USAGE[r.usage].name + ') is discouraged for SMTP. RFC 7672 section 3.1 says clients ignore usage 0 and 1 and publishers should use 2 or 3. Use "3 1 1" or "2 1 1".');
      } else usable++;
    });
    if (mailContext) {
      if (!usable) add('fail', 'No usable record for SMTP: only usage 0/1 records are published, so sending servers treat DANE as not configured here (RFC 7672 section 3.1).');
      else add('pass', usable + ' usable DANE-EE/DANE-TA record(s) for SMTP (RFC 7672 wants usage 2 or 3).');
    } else if (wrongUsage) {
      add('info', 'Usage 0/1 records also require a valid public-CA chain. If this port carries SMTP, RFC 7672 wants usage 2 or 3.');
    }
    if (t.records.some(function (r) { return r.usage === 3 && r.selector === 1 && r.matching === 1; })) add('pass', 'A "3 1 1" record is present (the recommended form, RFC 7671: survives renewals that keep the key).');
    else if (usable) add('info', 'No "3 1 1" record. It is the commonly recommended form; "2 1 1" is also fine for SMTP.');
    if (t.records.length === 1 && t.records.some(function (r) { return r.usage === 3; })) add('info', 'Only one DANE-EE record: when you rotate the key, publish the new record first and wait out the TTL (key rollover).');
    if (t.unparsed) add('warn', t.unparsed + ' TLSA record(s) could not be parsed.');
    return items;
  }

  function renderRecord(r) {
    var li = el('li', 'mx-item');
    var head = el('div', 'mx-head');
    [['usage', r.usage], ['selector', r.selector], ['matching', r.matching]].forEach(function (p) {
      var tag = el('span', 'flag-tag');
      tag.append(el('span', 'k', p[0]));
      tag.append(String(p[1]));
      head.append(tag);
    });
    if (r.ttl != null) head.append(el('span', 'mx-role', 'TTL ' + r.ttl));
    li.append(head);
    var u = USAGE[r.usage], s = SELECTOR[r.selector], m = MATCHING[r.matching];
    var expl = el('div', 'tlsa-expl');
    expl.append(el('p', null, u ? 'Usage ' + r.usage + ', ' + u.name + ': ' + u.text : 'Usage ' + r.usage + ': unassigned value.'));
    expl.append(el('p', null, s ? 'Selector ' + r.selector + ', ' + s.name + ': ' + s.text : 'Selector ' + r.selector + ': unassigned value.'));
    expl.append(el('p', null, m ? 'Matching type ' + r.matching + ', ' + m.name + ': ' + m.text : 'Matching type ' + r.matching + ': unassigned value.'));
    li.append(expl);
    li.append(el('div', 'mx-addrs', r.hex || '(empty)'));
    return li;
  }

  function renderTarget(t, mailContext) {
    var card = el('div', 'target');
    var head = el('div', 'target-head');
    head.append(el('span', 'mx-host', t.name));
    head.append(el('span', 'chk ' + (t.records.length ? (t.ad ? 'pass' : 'fail') : 'info'),
      t.records.length ? (t.ad ? 'DNSSEC validated (AD)' : 'NOT DNSSEC-validated') : 'no TLSA'));
    card.append(head);
    if (t.records.length) {
      var ul = el('ul', 'record-list');
      t.records.forEach(function (r) { ul.append(renderRecord(r)); });
      card.append(ul);
    }
    card.append(checkList(analyse(t, mailContext)));
    return card;
  }

  function summaryState(targets, mailContext) {
    var withRecords = targets.filter(function (t) { return t.records.length; });
    var level, title, text;
    if (!withRecords.length) {
      level = 'warn'; title = 'No DANE found';
      text = 'No TLSA record was found for ' + (targets.length > 1 ? 'any of these hosts.' : 'this host and port.');
    } else if (withRecords.some(function (t) { return !t.ad; })) {
      level = 'fail'; title = 'TLSA present, DNSSEC missing';
      text = 'TLSA records exist but the answer is not DNSSEC-validated. DANE gives no protection without DNSSEC.';
    } else if (mailContext && withRecords.every(function (t) { return !t.records.some(function (r) { return r.usage >= 2; }); })) {
      level = 'warn'; title = 'TLSA present, not usable for SMTP';
      text = 'Only usage 0/1 records are published; SMTP clients ignore them.';
    } else if (withRecords.length < targets.length) {
      level = 'warn'; title = 'DANE only on some hosts';
      text = withRecords.length + ' of ' + targets.length + ' hosts publish TLSA records. Add TLSA records to every MX host so that no delivery path is left unprotected.';
    } else {
      level = 'ok'; title = 'DANE published, DNSSEC validated';
      text = 'Every host publishes TLSA records and the resolver validated them with DNSSEC.';
    }
    var state = el('div', 'state ' + level);
    state.append(el('h2', 'state-title', title));
    state.append(el('p', null, text));
    return state;
  }

  // ---- Lookup flow ----
  var lookupForm = $('lookupForm'), modeSelect = $('modeSelect');
  var domainInput = $('domainInput'), hostInput = $('hostInput'), portInput = $('portInput');
  var checkBtn = $('checkBtn'), btnText = $('btnText'), btnLoader = $('btnLoader');
  var lastTargets = null;

  function setMode() {
    var mail = modeSelect.value === 'mail';
    $('rowDomain').hidden = !mail;
    $('rowHost').hidden = mail;
    $('rowPort').hidden = mail;
  }
  modeSelect.addEventListener('change', setMode);

  function setLoading(on) {
    checkBtn.disabled = on;
    btnText.textContent = on ? 'Looking up' : 'Look up TLSA';
    btnLoader.hidden = !on;
    btnLoader.className = on ? 'loader' : '';
  }

  function siblingLinks(domain) {
    var p = el('p', 'provider');
    p.append('Also check ' + domain + ': ');
    [['dnssec', 'DNSSEC'], ['mx', 'MX'], ['ssl', 'SSL/TLS'], ['caa', 'CAA']].forEach(function (t, i) {
      if (i) p.append(' · ');
      p.append(link(t[1], 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(domain)));
    });
    return p;
  }

  function syncGenerator(host, port) {
    $('genHost').value = host;
    $('genPort').value = String(port);
  }

  async function lookupMail(domain) {
    var mx = await queryMX(domain);
    var real = mx.records.filter(function (r) { return r.host !== '.'; });
    var box = views.records;
    box.replaceChildren();
    if (mx.records.length === 1 && mx.records[0].host === '.') {
      lastTargets = null;
      var n = el('div', 'state warn');
      n.append(el('h2', 'state-title', 'Null MX'));
      n.append(el('p', null, domain + ' publishes a null MX (RFC 7505): it does not receive email, so there is nothing for DANE to protect.'));
      box.append(n);
      return;
    }
    if (!real.length) {
      lastTargets = null;
      var e = el('div', 'state warn');
      e.append(el('h2', 'state-title', 'No MX records'));
      e.append(el('p', null, domain + ' has no MX record, so there is no mail host to check. Use the "custom host and port" mode on a host you know.'));
      box.append(e);
      return;
    }
    var hosts = real.map(function (r) { return r.host; }).filter(function (h, i, a) { return a.indexOf(h) === i && validHost(h); });
    var targets = await Promise.all(hosts.map(function (h) { return queryTlsa(h, 25); }));
    lastTargets = targets;
    var sum = summaryState(targets, true);
    sum.append(el('span', 'badge-domain', domain));
    box.append(sum);
    box.append(checkList([mx.ad
      ? { level: 'pass', text: 'The MX answer for ' + domain + ' is DNSSEC-validated (AD flag set), as RFC 7672 section 2.2.1 requires before TLSA lookups count.' }
      : { level: 'warn', text: 'The MX answer for ' + domain + ' is NOT DNSSEC-validated. RFC 7672 requires a secure MX lookup: a sender will not apply DANE to hosts learned from an unsigned MX answer.' }]));
    targets.forEach(function (t) { box.append(renderTarget(t, true)); });
    box.append(siblingLinks(domain));
    syncGenerator(hosts[0], 25);
  }

  async function lookupHost(host, port) {
    var t = await queryTlsa(host, port);
    lastTargets = [t];
    var box = views.records;
    box.replaceChildren();
    var sum = summaryState([t], port === 25);
    sum.append(el('span', 'badge-domain', t.name));
    box.append(sum);
    box.append(renderTarget(t, port === 25));
    box.append(siblingLinks(host));
    syncGenerator(host, port);
  }

  async function performLookup() {
    if (modeSelect.value === 'mail') {
      var domain = normalizeHost(domainInput.value);
      if (!domain) { setView('error'); renderError('Error', 'Please enter a domain name.'); return; }
      if (!validHost(domain)) { lastTargets = null; setView('error'); renderError('Error checking ' + domain, 'That is not a valid domain name.'); return; }
      domainInput.value = domain;
      setLoading(true);
      try { await lookupMail(domain); setView('records'); }
      catch (err) { lastTargets = null; renderError('Error checking ' + domain, err.message || 'Unknown error'); setView('error'); }
      finally { setLoading(false); }
    } else {
      var host = normalizeHost(hostInput.value), port = parsePort(portInput.value);
      if (!host) { setView('error'); renderError('Error', 'Please enter a host name.'); return; }
      if (!validHost(host)) { lastTargets = null; setView('error'); renderError('Error checking ' + host, 'That is not a valid host name (IP addresses cannot carry a TLSA name).'); return; }
      if (port === null) { setView('error'); renderError('Error checking ' + host, 'The port must be a number from 1 to 65535.'); return; }
      hostInput.value = host;
      portInput.value = String(port);
      setLoading(true);
      try { await lookupHost(host, port); setView('records'); }
      catch (err) { lastTargets = null; renderError('Error checking ' + host, err.message || 'Unknown error'); setView('error'); }
      finally { setLoading(false); }
    }
  }
  lookupForm.addEventListener('submit', function (e) { e.preventDefault(); performLookup(); });

  // ---- Minimal DER parser: extract the SubjectPublicKeyInfo of an X.509 certificate ----
  function readTLV(buf, pos) {
    if (pos + 2 > buf.length) throw new Error('truncated DER');
    var tag = buf[pos], b = buf[pos + 1], len, hdr = 2;
    if (b < 0x80) len = b;
    else {
      var n = b & 0x7f;
      if (n === 0 || n > 4) throw new Error('unsupported DER length');
      if (pos + 2 + n > buf.length) throw new Error('truncated DER');
      len = 0;
      for (var i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
      hdr = 2 + n;
    }
    var start = pos + hdr, end = start + len;
    if (end > buf.length) throw new Error('DER element overruns the data');
    return { tag: tag, pos: pos, start: start, end: end };
  }
  function children(buf, node) {
    var out = [], p = node.start;
    while (p < node.end) { var c = readTLV(buf, p); out.push(c); p = c.end; }
    return out;
  }
  var OID_CN = [0x55, 0x04, 0x03];
  function commonName(buf, name) {
    try {
      var rdns = children(buf, name);
      for (var i = 0; i < rdns.length; i++) {
        var atvs = children(buf, rdns[i]);
        for (var j = 0; j < atvs.length; j++) {
          var kv = children(buf, atvs[j]);
          if (kv.length === 2 && kv[0].tag === 0x06 && kv[0].end - kv[0].start === 3 && OID_CN.every(function (x, k) { return buf[kv[0].start + k] === x; })) {
            return new TextDecoder(kv[1].tag === 0x1e ? 'utf-16be' : 'utf-8').decode(buf.subarray(kv[1].start, kv[1].end));
          }
        }
      }
    } catch (e) { /* no readable CN */ }
    return null;
  }
  // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version?, serial, signature, issuer, validity, subject, spki, ... }, ... }
  function parseCertificate(der) {
    var cert = readTLV(der, 0);
    if (cert.tag !== 0x30) throw new Error('not a DER SEQUENCE');
    var tbs = readTLV(der, cert.start);
    if (tbs.tag !== 0x30) throw new Error('missing TBSCertificate');
    var f = children(der, tbs), i = 0;
    if (f[0] && f[0].tag === 0xa0) i = 1;
    var serial = f[i], issuer = f[i + 2], subject = f[i + 4], spki = f[i + 5];
    if (!serial || serial.tag !== 0x02 || !issuer || !subject || !spki || spki.tag !== 0x30) throw new Error('unexpected certificate structure');
    var kids = children(der, spki);
    if (kids.length !== 2 || kids[0].tag !== 0x30 || kids[1].tag !== 0x03) throw new Error('malformed SubjectPublicKeyInfo');
    return { spki: der.slice(spki.pos, spki.end), subject: commonName(der, subject), issuer: commonName(der, issuer) };
  }

  // ---- PEM and hashing ----
  function parsePem(text) {
    var re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g, m, out = [];
    while ((m = re.exec(text)) !== null) {
      var b64 = m[1].replace(/\s+/g, '');
      if (!b64 || !/^[A-Za-z0-9+\/]+={0,2}$/.test(b64) || b64.length % 4) throw new Error('Certificate #' + (out.length + 1) + ' is not valid base64.');
      var bin = atob(b64), der = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
      out.push(der);
    }
    return out;
  }
  function toHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  async function digest(alg, bytes) { return toHex(await crypto.subtle.digest(alg, bytes)); }

  async function describeCert(der) {
    var info = parseCertificate(der);
    return {
      subject: info.subject, issuer: info.issuer, derLen: der.length, spkiLen: info.spki.length,
      hex: {
        '0-0': toHex(der), '1-0': toHex(info.spki),
        '0-1': await digest('SHA-256', der), '0-2': await digest('SHA-512', der),
        '1-1': await digest('SHA-256', info.spki), '1-2': await digest('SHA-512', info.spki)
      }
    };
  }

  var pemInput = $('pemInput'), pemError = $('pemError'), matchOutput = $('matchOutput');

  function showMsg(node, msg) { node.textContent = msg; node.classList.toggle('visible', !!msg); }

  async function loadCerts() {
    if (!(window.crypto && crypto.subtle)) throw new Error('WebCrypto is not available (it needs a secure context: https or localhost).');
    var ders = parsePem(pemInput.value);
    if (!ders.length) throw new Error('No PEM certificate found. Paste text between -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----.');
    var certs = [];
    for (var i = 0; i < ders.length; i++) {
      try { certs.push(await describeCert(ders[i])); }
      catch (e) { throw new Error('Certificate #' + (i + 1) + ': ' + e.message + '.'); }
    }
    return certs;
  }

  function certLabel(c, i) { return 'Certificate #' + (i + 1) + (c.subject ? ' (' + c.subject + ')' : ''); }
  var SEL_WORD = { 0: 'full certificate', 1: 'public key (SPKI)' };
  var MAT_WORD = { 0: 'exact data', 1: 'SHA-256', 2: 'SHA-512' };

  function renderMatch(certs) {
    var box = matchOutput;
    box.replaceChildren();
    certs.forEach(function (c, i) {
      var item = el('div', 'target');
      var head = el('div', 'target-head');
      head.append(el('span', 'mx-host', certLabel(c, i)));
      item.append(head);
      var meta = [];
      if (c.issuer) meta.push('issuer ' + c.issuer);
      meta.push('DER ' + c.derLen + ' bytes', 'SPKI ' + c.spkiLen + ' bytes');
      item.append(el('p', 'provider', meta.join(' · ')));
      var ul = el('ul', 'record-list');
      ['0-1', '0-2', '1-1', '1-2'].forEach(function (k) {
        var li = el('li', 'mx-item');
        var h = el('div', 'mx-head');
        var tag = el('span', 'flag-tag');
        tag.append(el('span', 'k', 'selector'));
        tag.append(k.charAt(0));
        h.append(tag);
        h.append(el('span', 'mx-role', SEL_WORD[k.charAt(0)] + ', ' + MAT_WORD[k.charAt(2)]));
        li.append(h);
        li.append(el('div', 'mx-addrs', c.hex[k]));
        ul.append(li);
      });
      item.append(ul);
      box.append(item);
    });

    var items = [];
    if (!lastTargets) {
      items.push({ level: 'info', text: 'Run a lookup above to compare these hashes with published TLSA records.' });
    } else {
      var anyRecord = false, anyMatch = false;
      lastTargets.forEach(function (t) {
        t.records.forEach(function (r) {
          if (!SELECTOR[r.selector] || !MATCHING[r.matching]) return;
          anyRecord = true;
          certs.forEach(function (c, i) {
            if (c.hex[r.selector + '-' + r.matching] !== r.hex) return;
            anyMatch = true;
            var role = r.usage === 3 || r.usage === 1 ? 'the end-entity (server) certificate' : 'a CA certificate (trust anchor)';
            var txt = t.name + ': record "' + r.usage + ' ' + r.selector + ' ' + r.matching + '" MATCHES ' + certLabel(c, i) + ' (' + SEL_WORD[r.selector] + ', ' + MAT_WORD[r.matching] + '). Usage ' + r.usage + ' means the record names ' + role + '.';
            if (!t.ad) txt += ' But the answer was NOT DNSSEC-validated, so DANE clients will not trust it.';
            items.push({ level: t.ad ? 'pass' : 'warn', text: txt });
          });
        });
      });
      if (!anyRecord) items.push({ level: 'info', text: 'The last lookup returned no TLSA record to compare with.' });
      else if (!anyMatch) items.push({ level: 'fail', text: 'No TLSA record from the last lookup matches any pasted certificate. If the server presents a different certificate or key, DANE-validating senders will refuse to deliver. If you renewed with a new key, publish the new record.' });
    }
    box.append(checkList(items));
  }

  $('matchBtn').addEventListener('click', async function () {
    showMsg(pemError, '');
    matchOutput.replaceChildren();
    try { renderMatch(await loadCerts()); }
    catch (e) { showMsg(pemError, e.message); }
  });
  $('pemClearBtn').addEventListener('click', function () {
    pemInput.value = '';
    showMsg(pemError, ''); matchOutput.replaceChildren(); $('genOutput').replaceChildren(); showMsg($('genError'), '');
  });

  // ---- Generator ----
  var genHost = $('genHost'), genPort = $('genPort'), genError = $('genError'), genOutput = $('genOutput');
  $('genBtn').addEventListener('click', async function () {
    showMsg(genError, ''); genOutput.replaceChildren();
    var host = normalizeHost(genHost.value), port = parsePort(genPort.value);
    if (!validHost(host)) { showMsg(genError, 'Enter a valid host name (not an IP address), e.g. mail.example.com.'); genHost.focus(); return; }
    if (port === null) { showMsg(genError, 'The port must be a number from 1 to 65535.'); genPort.focus(); return; }
    var usage = parseInt($('genUsage').value, 10), sel = parseInt($('genSelector').value, 10), mt = parseInt($('genMatching').value, 10);
    var certs;
    try { certs = await loadCerts(); } catch (e) { showMsg(genError, e.message); return; }
    var lines = certs.map(function (c) { return tlsaName(host, port) + '. IN TLSA ' + usage + ' ' + sel + ' ' + mt + ' ' + c.hex[sel + '-' + mt]; });
    var pre = el('div', 'preview gen-pre');
    pre.textContent = lines.join('\n');
    genOutput.append(pre);
    var notes = [];
    if (certs.length > 1) notes.push({ level: 'info', text: certs.length + ' certificates were pasted, so one line is produced for each, in order. Publish only the line you want: usually #1 (the server certificate) for usage 3, or the CA certificate for usage 2.' });
    if (usage <= 1 && port === 25) notes.push({ level: 'warn', text: 'Usage ' + usage + ' is discouraged for SMTP: RFC 7672 wants usage 2 or 3, and sending servers ignore 0 and 1.' });
    else if (usage <= 1) notes.push({ level: 'info', text: 'Usage ' + usage + ' also needs a valid public-CA chain at connection time.' });
    if (usage === 3 && sel === 1 && mt === 1) notes.push({ level: 'pass', text: '3 1 1 is the recommended form: it keeps working across renewals as long as the key pair is reused.' });
    if (usage >= 2 && port === 25) notes.push({ level: 'info', text: 'For SMTP, the server should send the full chain, and for usage 2 the named CA certificate should be part of it (RFC 7672 section 3.1.2).' });
    notes.push({ level: 'warn', text: 'These records only work if the zone is DNSSEC-signed and the DS record is published at the parent. Publish the new record before switching certificates, and keep the old one until its TTL has expired.' });
    genOutput.append(checkList(notes));
  });

  // ---- Start ----
  setMode();
  setView('placeholder');
  var params = new URLSearchParams(location.search);
  var pDomain = params.get('domain'), pHost = params.get('host'), pPort = params.get('port');
  if (pHost) {
    modeSelect.value = 'host'; setMode();
    hostInput.value = pHost;
    if (pPort) portInput.value = pPort;
    performLookup();
  } else if (pDomain) {
    domainInput.value = pDomain;
    performLookup();
  }
})();
