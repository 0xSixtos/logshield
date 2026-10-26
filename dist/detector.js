/** Pure detection and redaction. No network, persistence, or side effects. */
export const MAX_BYTES = 2_000_000;
export const MAX_FINDINGS = 2000;
export const TYPES = ['PASSWORD', 'API_KEY', 'TOKEN', 'AUTH', 'COOKIE', 'PRIVATE_KEY', 'CREDENTIALS', 'EMAIL', 'IP_ADDRESS'];

function fieldType(key) {
  const k = key.toLowerCase().replace(/[-_\s]/g, '');
  if (/^(password|passwd|pwd|passphrase|dbpassword)$/.test(k)) return 'PASSWORD';
  if (/^(apikey|xapikey|secret|clientsecret|secretkey|apisecret|awssecretaccesskey)$/.test(k)) return 'API_KEY';
  if (/^(token|accesstoken|refreshtoken|idtoken|sessiontoken|sessionid|authToken)$/i.test(k)) return 'TOKEN';
  if (/^(authorization|proxyauthorization)$/.test(k)) return 'AUTH';
  if (/^(cookie|setcookie)$/.test(k)) return 'COOKIE';
  if (k === 'privatekey') return 'PRIVATE_KEY';
  return null;
}

function jsonFields(text, add) {
  // Token positions refer to the ORIGINAL input: formatting is never reconstructed.
  const re = /"(?:\\.|[^"\\])*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]:,]/g;
  const tokens = Array.from(text.matchAll(re), m => ({ raw: m[0], start: m.index, end: m.index + m[0].length }));
  let i = 0;
  function value() {
    const first = tokens[i];
    if (first.raw === '{') {
      i++;
      while (tokens[i]?.raw !== '}') {
        const key = JSON.parse(tokens[i++].raw);
        i++; // colon
        const start = tokens[i];
        value();
        const end = tokens[i - 1];
        const type = fieldType(key);
        if (type && start.raw !== 'null' && start.raw !== 'false' && start.raw !== 'true' && start.raw !== '""') {
          const quoted = start === end && start.raw.startsWith('"');
          add(start.start + (quoted ? 1 : 0), end.end - (quoted ? 1 : 0), type, 100,
            quoted ? undefined : JSON.stringify(`[REDACTED:${type}]`));
        }
        if (tokens[i]?.raw === ',') i++;
      }
      i++;
    } else if (first.raw === '[') {
      i++;
      while (tokens[i]?.raw !== ']') {
        value();
        if (tokens[i]?.raw === ',') i++;
      }
      i++;
    } else { i++; }
  }
  value();
}

export function analyze(text, options = {}) {
  if (typeof text !== 'string') throw new TypeError('Expected text');
  if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new RangeError('FILE_TOO_LARGE');
  const enabled = new Set(TYPES.filter(t => options[t] !== false));
  if (options.IP_ADDRESS !== true) enabled.delete('IP_ADDRESS');
  const candidates = [];
  let candidateOverflow = false;
  function add(start, end, type, priority, replacement) {
    if (!enabled.has(type) || end <= start) return;
    if (candidates.length >= MAX_FINDINGS * 4) { candidateOverflow = true; return; }
    candidates.push({ start, end, type, priority, replacement: replacement ?? `[REDACTED:${type}]` });
  }
  const trimmed = text.trim();
  let format = 'text';
  let invalidJson = false;
  if (/^[{\[]/.test(trimmed)) {
    try { JSON.parse(text); format = 'json'; } catch { invalidJson = true; }
  }
  if (format === 'json') {
    try { jsonFields(text, add); } catch (error) {
      // Excessive nesting or an unsupported parse must never produce a partial "safe" result.
      throw new RangeError('JSON_TOO_DEEP');
    }
  } else {
    const pairs = /\b([A-Za-z][A-Za-z0-9_-]{1,40})["']?[ \t]*[:=][ \t]*(?:"((?:\\.|[^"\\\r\n])*)"|'((?:\\.|[^'\\\r\n])*)'|([^\s,;\r\n]+))/g;
    for (const m of text.matchAll(pairs)) {
      const type = fieldType(m[1]);
      if (!type) continue;
      // Header values may contain a scheme or many cookie pairs, so cover the line.
      if (type === 'AUTH' || type === 'COOKIE') {
        const separator = m[0].search(/[:=]/);
        const prefix = m[0].slice(0, separator + 1);
        const start = m.index + prefix.length + (text.slice(m.index + prefix.length).match(/^[ \t]*/)?.[0].length ?? 0);
        const lineEnd = text.indexOf('\n', start);
        const end = lineEnd < 0 ? text.length : lineEnd;
        add(start, end - (text[end - 1] === '\r' ? 1 : 0), type, 95);
      } else {
        const val = m[2] ?? m[3] ?? m[4];
        const offset = m[0].indexOf(val, m[0].search(/[:=]/) + 1);
        add(m.index + offset, m.index + offset + val.length, type, 90);
      }
    }
  }
  function scan(re, type, priority, group = 0) {
    for (const m of text.matchAll(re)) {
      const token = m[group];
      const offset = group === 0 ? 0 : m[0].lastIndexOf(token);
      add(m.index + offset, m.index + offset + token.length, type, priority);
    }
  }
  scan(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g, 'PRIVATE_KEY', 110);
  scan(/\b(?:Bearer|Basic)[ \t]+([A-Za-z0-9_~+/.=:-]{8,})/gi, 'AUTH', 85, 1);
  scan(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, 'TOKEN', 80);
  scan(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/g, 'API_KEY', 80);
  scan(/https?:\/\/([^\s/@:]+:[^\s/@]+)@/gi, 'CREDENTIALS', 85, 1);
  const query = /[?&]([A-Za-z][A-Za-z0-9_-]*)=([^&#\s"'<>]+)/g;
  for (const m of text.matchAll(query)) {
    const type = fieldType(m[1]);
    if (type) add(m.index + m[0].length - m[2].length, m.index + m[0].length, type, 95);
  }
  scan(/\b[A-Z0-9.!#$%&'*+^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+\b/gi, 'EMAIL', 50);
  const ips = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  for (const m of text.matchAll(ips)) {
    if (m[0].split('.').every(v => Number(v) <= 255)) add(m.index, m.index + m[0].length, 'IP_ADDRESS', 40);
  }
  // Prefer named fields and full private keys to nested partial matches.
  candidates.sort((a, b) => b.priority - a.priority || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const accepted = [];
  let truncated = candidateOverflow;
  for (const candidate of candidates) {
    if (accepted.some(f => candidate.start < f.end && candidate.end > f.start)) continue;
    if (accepted.length >= MAX_FINDINGS) { truncated = true; break; }
    accepted.push(candidate);
  }
  accepted.sort((a, b) => a.start - b.start);
  const lineStarts = [0];
  for (let j = 0; j < text.length; j++) if (text[j] === '\n') lineStarts.push(j + 1);
  const findings = accepted.map((f, index) => {
    let lo = 0, hi = lineStarts.length;
    while (lo + 1 < hi) { const mid = (lo + hi) >> 1; if (lineStarts[mid] <= f.start) lo = mid; else hi = mid; }
    return { id: `f-${index}`, ...f, line: lo + 1, column: f.start - lineStarts[lo] + 1 };
  });
  return { format, invalidJson, truncated, findings, lines: lineStarts.length };
}

export function redact(text, findings, selected = new Set(findings.map(f => f.id))) {
  let cursor = 0;
  const parts = [];
  for (const f of findings) {
    if (!selected.has(f.id)) continue;
    if (f.start < cursor || f.start < 0 || f.end > text.length) throw new RangeError('Invalid finding ranges');
    parts.push(text.slice(cursor, f.start), f.replacement);
    cursor = f.end;
  }
  parts.push(text.slice(cursor));
  return parts.join('');
}
