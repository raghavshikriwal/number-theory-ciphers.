/* ============================================================
   MATH HELPERS
   ============================================================ */
const MOD = 26;
function mod(n, m = MOD){ return ((n % m) + m) % m; }
function gcd(a, b){ a = Math.abs(a); b = Math.abs(b); return b === 0 ? a : gcd(b, a % b); }
function modInverse(a, m = MOD){
  a = mod(a, m);
  for (let x = 1; x < m; x++) if (mod(a * x, m) === 1) return x;
  return null;
}
function cleanText(s){ return (s || '').toUpperCase().replace(/[^A-Z]/g, ''); }
function letterToNum(c){ return c.charCodeAt(0) - 65; }
function numToLetter(n){ return String.fromCharCode(mod(n) + 65); }
const COPRIME_WITH_26 = [1,3,5,7,9,11,15,17,19,21,23,25];

/* ============================================================
   CIPHER ALGORITHMS
   ============================================================ */

/* ---- Shift Cipher ---- */
function shiftEncrypt(text, k){
  return cleanText(text).split('').map(c => numToLetter(letterToNum(c) + Number(k))).join('');
}
function shiftDecrypt(text, k){
  return cleanText(text).split('').map(c => numToLetter(letterToNum(c) - Number(k))).join('');
}

/* ---- Multiplicative Cipher ---- */
function multEncrypt(text, a){
  a = Number(a);
  return cleanText(text).split('').map(c => numToLetter(letterToNum(c) * a)).join('');
}
function multDecrypt(text, a){
  const aInv = modInverse(Number(a));
  return cleanText(text).split('').map(c => numToLetter(letterToNum(c) * aInv)).join('');
}

/* ---- Affine Cipher: E(p) = a*p + b, D(c) = a^-1 * (c - b) ---- */
function affineEncrypt(text, a, b){
  a = Number(a); b = Number(b);
  return cleanText(text).split('').map(c => numToLetter(a * letterToNum(c) + b)).join('');
}
function affineDecrypt(text, a, b){
  a = Number(a); b = Number(b);
  const aInv = modInverse(a);
  return cleanText(text).split('').map(c => numToLetter(aInv * (letterToNum(c) - b))).join('');
}

/* ---- Playfair Cipher ---- */
function buildPlayfairGrid(keyword){
  const key = cleanText(keyword).replace(/J/g, 'I');
  const seen = new Set();
  const letters = [];
  for (const ch of key) if (!seen.has(ch)) { seen.add(ch); letters.push(ch); }
  for (let i = 0; i < 26; i++) {
    const ch = String.fromCharCode(65 + i);
    if (ch === 'J') continue;
    if (!seen.has(ch)) { seen.add(ch); letters.push(ch); }
  }
  const grid = [];
  for (let r = 0; r < 5; r++) grid.push(letters.slice(r * 5, r * 5 + 5));
  return grid;
}
function findPos(grid, ch){
  for (let r = 0; r < 5; r++) { const c = grid[r].indexOf(ch); if (c !== -1) return { r, c }; }
  return null;
}
function playfairDigraphs(text){
  const t = cleanText(text).replace(/J/g, 'I');
  const pairs = [];
  let i = 0;
  while (i < t.length) {
    const a = t[i];
    const b = (i + 1 < t.length) ? t[i + 1] : 'X';
    if (a === b) { pairs.push([a, 'X']); i += 1; }
    else { pairs.push([a, b]); i += 2; }
  }
  return pairs;
}
function playfairEncrypt(text, keyword){
  const grid = buildPlayfairGrid(keyword);
  return playfairDigraphs(text).map(([a, b]) => {
    const pa = findPos(grid, a), pb = findPos(grid, b);
    if (pa.r === pb.r) return grid[pa.r][mod(pa.c + 1, 5)] + grid[pb.r][mod(pb.c + 1, 5)];
    if (pa.c === pb.c) return grid[mod(pa.r + 1, 5)][pa.c] + grid[mod(pb.r + 1, 5)][pb.c];
    return grid[pa.r][pb.c] + grid[pb.r][pa.c];
  }).join('');
}
function playfairDecrypt(text, keyword){
  const grid = buildPlayfairGrid(keyword);
  const t = cleanText(text);
  const pairs = [];
  for (let i = 0; i < t.length; i += 2) pairs.push([t[i], t[i + 1]]);
  return pairs.map(([a, b]) => {
    const pa = findPos(grid, a), pb = findPos(grid, b);
    if (pa.r === pb.r) return grid[pa.r][mod(pa.c - 1, 5)] + grid[pb.r][mod(pb.c - 1, 5)];
    if (pa.c === pb.c) return grid[mod(pa.r - 1, 5)][pa.c] + grid[mod(pb.r - 1, 5)][pb.c];
    return grid[pa.r][pb.c] + grid[pb.r][pa.c];
  }).join('');
}

/* ---- Hill Cipher (2x2) ---- */
function hillMatrixFromKey(keyStr){
  const nums = (keyStr || '').split(/[,\s]+/).filter(Boolean).map(Number);
  if (nums.length !== 4 || nums.some(isNaN)) return null;
  return [[nums[0], nums[1]], [nums[2], nums[3]]];
}
function matDet2(m){ return mod(m[0][0] * m[1][1] - m[0][1] * m[1][0]); }
function matInverse2(m){
  const det = matDet2(m);
  const detInv = modInverse(det);
  if (detInv === null) return null;
  return [
    [mod(m[1][1] * detInv), mod(-m[0][1] * detInv)],
    [mod(-m[1][0] * detInv), mod(m[0][0] * detInv)]
  ];
}
function hillTransform(text, matrix){
  let t = cleanText(text);
  if (t.length % 2 !== 0) t += 'X';
  let out = '';
  for (let i = 0; i < t.length; i += 2) {
    const p1 = letterToNum(t[i]), p2 = letterToNum(t[i + 1]);
    out += numToLetter(matrix[0][0] * p1 + matrix[0][1] * p2);
    out += numToLetter(matrix[1][0] * p1 + matrix[1][1] * p2);
  }
  return out;
}
function hillEncrypt(text, keyStr){
  const m = hillMatrixFromKey(keyStr);
  if (!m) throw new Error('Key must be 4 numbers, e.g. "3 3 2 5" (a 2×2 matrix).');
  return hillTransform(text, m);
}
function hillDecrypt(text, keyStr){
  const m = hillMatrixFromKey(keyStr);
  if (!m) throw new Error('Key must be 4 numbers, e.g. "3 3 2 5" (a 2×2 matrix).');
  const inv = matInverse2(m);
  if (!inv) throw new Error('This matrix has no inverse mod 26 (determinant must be coprime with 26).');
  return hillTransform(text, inv);
}

/* ---- Vigenère Cipher ---- */
function vigenereEncrypt(text, key){
  const t = cleanText(text), k = cleanText(key);
  if (!k) throw new Error('Enter a keyword.');
  return t.split('').map((c, i) => numToLetter(letterToNum(c) + letterToNum(k[i % k.length]))).join('');
}
function vigenereDecrypt(text, key){
  const t = cleanText(text), k = cleanText(key);
  if (!k) throw new Error('Enter a keyword.');
  return t.split('').map((c, i) => numToLetter(letterToNum(c) - letterToNum(k[i % k.length]))).join('');
}

/* ---- Rail Fence Cipher ---- */
function railPattern(len, rails){
  const pattern = [];
  let r = 0, dir = 1;
  for (let i = 0; i < len; i++) {
    pattern.push(r);
    if (r === 0) dir = 1; else if (r === rails - 1) dir = -1;
    r += dir;
  }
  return pattern;
}
function railFenceEncrypt(text, rails){
  rails = Number(rails);
  const t = cleanText(text);
  if (rails < 2) throw new Error('Number of rails must be 2 or more.');
  const pattern = railPattern(t.length, rails);
  const fence = Array.from({ length: rails }, () => []);
  t.split('').forEach((ch, i) => fence[pattern[i]].push(ch));
  return fence.flat().join('');
}
function railFenceDecrypt(text, rails){
  rails = Number(rails);
  const t = cleanText(text);
  if (rails < 2) throw new Error('Number of rails must be 2 or more.');
  const pattern = railPattern(t.length, rails);
  const counts = Array(rails).fill(0);
  pattern.forEach(r => counts[r]++);
  const rows = [];
  let idx = 0;
  for (let i = 0; i < rails; i++) { rows.push(t.slice(idx, idx + counts[i]).split('')); idx += counts[i]; }
  const ptr = Array(rails).fill(0);
  return pattern.map(r => rows[r][ptr[r]++]).join('');
}

/* ============================================================
   VISUALIZATIONS
   ============================================================ */
function renderSubstitutionVisual(el, mapFn){
  const plain = Array.from({ length: 26 }, (_, i) => String.fromCharCode(65 + i));
  let cipher;
  try { cipher = plain.map(mapFn); } catch (e) { el.innerHTML = ''; return; }
  el.innerHTML = `<div class="map-table">
    <div class="map-row plain">${plain.map(c => `<span>${c}</span>`).join('')}</div>
    <div class="map-row cipher">${cipher.map(c => `<span>${c}</span>`).join('')}</div>
  </div>`;
}
function renderPlayfairVisual(el, text, v){
  const grid = buildPlayfairGrid(v.keyword || '');
  const digraphs = playfairDigraphs(text || 'EXAMPLE');
  const gridHtml = `<div class="pf-grid">${grid.map(row => row.map(ch => `<div class="pf-cell">${ch}</div>`).join('')).join('')}</div>`;
  const listHtml = `<div class="pf-pairs">${digraphs.map(([a, b]) => {
    const pa = findPos(grid, a), pb = findPos(grid, b);
    const rule = pa.r === pb.r ? 'row' : pa.c === pb.c ? 'column' : 'rectangle';
    return `<div class="pf-pair"><span class="pf-letters">${a}${b}</span><span class="pf-rule pf-rule-${rule}">${rule}</span></div>`;
  }).join('')}</div>`;
  el.innerHTML = `<p class="visual-note">5×5 key square (I/J share a cell):</p>${gridHtml}<p class="visual-note">Rule applied to each letter pair:</p>${listHtml}`;
}
function renderHillVisual(el, text, v){
  const m = hillMatrixFromKey(v.matrix);
  if (!m) { el.innerHTML = '<p class="visual-note">Enter 4 numbers for a 2×2 key matrix, e.g. "3 3 2 5".</p>'; return; }
  let t = cleanText(text || 'HI');
  if (t.length % 2 !== 0) t += 'X';
  const p1 = letterToNum(t[0] || 'A'), p2 = letterToNum(t[1] || 'A');
  const c1 = mod(m[0][0] * p1 + m[0][1] * p2), c2 = mod(m[1][0] * p1 + m[1][1] * p2);
  el.innerHTML = `
    <p class="visual-note">Key matrix:</p>
    <div class="hill-matrix"><div class="hill-row">${m[0][0]}&nbsp;&nbsp;${m[0][1]}</div><div class="hill-row">${m[1][0]}&nbsp;&nbsp;${m[1][1]}</div></div>
    <p class="visual-note">First block "${t[0]}${t[1]}" → plaintext vector (${p1}, ${p2})</p>
    <p class="visual-note">c₁ = (${m[0][0]}×${p1} + ${m[0][1]}×${p2}) mod 26 = ${c1} → ${numToLetter(c1)}</p>
    <p class="visual-note">c₂ = (${m[1][0]}×${p1} + ${m[1][1]}×${p2}) mod 26 = ${c2} → ${numToLetter(c2)}</p>
  `;
}
function renderVigenereVisual(el, text, v){
  const t = cleanText(text), k = cleanText(v.keyword || '');
  if (!t || !k) { el.innerHTML = '<p class="visual-note">Enter text and a keyword to see the tableau alignment.</p>'; return; }
  const keyRow = Array.from({ length: t.length }, (_, i) => k[i % k.length]);
  el.innerHTML = `<p class="visual-note">Keyword repeated under the plaintext:</p>
    <div class="vig-table">
      <div class="vig-row">${t.split('').map(c => `<span>${c}</span>`).join('')}</div>
      <div class="vig-row key">${keyRow.map(c => `<span>${c}</span>`).join('')}</div>
    </div>`;
}
function renderRailFenceVisual(el, text, v){
  const t = cleanText(text);
  const rails = Number(v.rails) || 3;
  if (!t || rails < 2) { el.innerHTML = '<p class="visual-note">Enter text and 2+ rails to see the zigzag.</p>'; return; }
  const pattern = railPattern(t.length, rails);
  let html = `<p class="visual-note">Zigzag placement across ${rails} rails:</p><div class="rf-grid" style="grid-template-columns:repeat(${t.length},22px)">`;
  for (let r = 0; r < rails; r++) {
    for (let i = 0; i < t.length; i++) html += `<div class="rf-cell">${pattern[i] === r ? t[i] : ''}</div>`;
  }
  html += '</div>';
  el.innerHTML = html;
}

/* ============================================================
   MODULE DEFINITIONS (data-driven UI)
   ============================================================ */
const MODULES = [
  {
    id: 'shift', glyph: '⇌', name: 'Shift Cipher', desc: 'Caesar shift — additive substitution',
    fields: [{ id: 'shift', label: 'Shift (k)', type: 'number', value: 3 }],
    encrypt: (t, v) => shiftEncrypt(t, v.shift), decrypt: (t, v) => shiftDecrypt(t, v.shift),
    validate: () => null,
    visualize: (el, t, v) => renderSubstitutionVisual(el, c => numToLetter(letterToNum(c) + Number(v.shift))),
    code: `function shiftEncrypt(text, k) {
  return clean(text).split('').map(c =>
    numToLetter(letterToNum(c) + k)
  ).join('');
}
function shiftDecrypt(text, k) {
  return shiftEncrypt(text, -k);
}`
  },
  {
    id: 'mult', glyph: '×', name: 'Multiplicative Cipher', desc: 'c = a·p mod 26, a coprime with 26',
    fields: [{ id: 'a', label: 'Multiplier (a)', type: 'number', value: 7 }],
    encrypt: (t, v) => multEncrypt(t, v.a), decrypt: (t, v) => multDecrypt(t, v.a),
    validate: (v) => gcd(Number(v.a), 26) !== 1 ? `a=${v.a} is not coprime with 26. Try one of: ${COPRIME_WITH_26.join(', ')}` : null,
    visualize: (el, t, v) => renderSubstitutionVisual(el, c => numToLetter(letterToNum(c) * Number(v.a))),
    code: `function multEncrypt(text, a) {
  return clean(text).split('').map(c =>
    numToLetter(letterToNum(c) * a)
  ).join('');
}
function multDecrypt(text, a) {
  const aInv = modInverse(a, 26);
  return clean(text).split('').map(c =>
    numToLetter(letterToNum(c) * aInv)
  ).join('');
}`
  },
  {
    id: 'affine', glyph: 'ax+b', name: 'Affine Cipher', desc: 'c = a·p + b mod 26',
    fields: [{ id: 'a', label: 'a', type: 'number', value: 5 }, { id: 'b', label: 'b', type: 'number', value: 8 }],
    encrypt: (t, v) => affineEncrypt(t, v.a, v.b), decrypt: (t, v) => affineDecrypt(t, v.a, v.b),
    validate: (v) => gcd(Number(v.a), 26) !== 1 ? `a=${v.a} is not coprime with 26. Try one of: ${COPRIME_WITH_26.join(', ')}` : null,
    visualize: (el, t, v) => renderSubstitutionVisual(el, c => numToLetter(Number(v.a) * letterToNum(c) + Number(v.b))),
    code: `function affineEncrypt(text, a, b) {
  return clean(text).split('').map(c =>
    numToLetter(a * letterToNum(c) + b)
  ).join('');
}
function affineDecrypt(text, a, b) {
  const aInv = modInverse(a, 26);
  return clean(text).split('').map(c =>
    numToLetter(aInv * (letterToNum(c) - b))
  ).join('');
}`
  },
  {
    id: 'playfair', glyph: '▦', name: 'Playfair Cipher', desc: '5×5 key square, digraph substitution',
    fields: [{ id: 'keyword', label: 'Keyword', type: 'text', value: 'MONARCHY' }],
    encrypt: (t, v) => playfairEncrypt(t, v.keyword), decrypt: (t, v) => playfairDecrypt(t, v.keyword),
    validate: (v) => !cleanText(v.keyword) ? 'Enter a keyword.' : null,
    visualize: (el, t, v) => renderPlayfairVisual(el, t, v),
    code: `// Rules per letter pair, based on position in the 5x5 grid:
// same row      -> shift each letter one cell right
// same column   -> shift each letter one cell down
// rectangle     -> swap to the opposite corner's column
function playfairEncryptPair(grid, [a, b]) {
  const pa = findPos(grid, a), pb = findPos(grid, b);
  if (pa.r === pb.r)
    return grid[pa.r][(pa.c+1)%5] + grid[pb.r][(pb.c+1)%5];
  if (pa.c === pb.c)
    return grid[(pa.r+1)%5][pa.c] + grid[(pb.r+1)%5][pb.c];
  return grid[pa.r][pb.c] + grid[pb.r][pa.c];
}`
  },
  {
    id: 'hill', glyph: '⊞', name: 'Hill Cipher', desc: '2×2 matrix, linear algebra mod 26',
    fields: [{ id: 'matrix', label: 'Key matrix: a b c d', type: 'text', value: '3 3 2 5' }],
    encrypt: (t, v) => hillEncrypt(t, v.matrix), decrypt: (t, v) => hillDecrypt(t, v.matrix),
    validate: (v) => {
      const m = hillMatrixFromKey(v.matrix);
      if (!m) return 'Enter exactly 4 numbers, e.g. "3 3 2 5".';
      if (gcd(matDet2(m), 26) !== 1) return `Determinant (${matDet2(m)}) is not coprime with 26 — matrix is not invertible.`;
      return null;
    },
    visualize: (el, t, v) => renderHillVisual(el, t, v),
    code: `function hillTransform(text, matrix) {
  let t = clean(text);
  if (t.length % 2) t += 'X';
  let out = '';
  for (let i = 0; i < t.length; i += 2) {
    const p1 = letterToNum(t[i]), p2 = letterToNum(t[i+1]);
    out += numToLetter(matrix[0][0]*p1 + matrix[0][1]*p2);
    out += numToLetter(matrix[1][0]*p1 + matrix[1][1]*p2);
  }
  return out;
}
// Decrypt uses the modular inverse of the matrix instead.`
  },
  {
    id: 'vigenere', glyph: '⟳', name: 'Vigenère Cipher', desc: 'Repeating-keyword polyalphabetic shift',
    fields: [{ id: 'keyword', label: 'Keyword', type: 'text', value: 'KEY' }],
    encrypt: (t, v) => vigenereEncrypt(t, v.keyword), decrypt: (t, v) => vigenereDecrypt(t, v.keyword),
    validate: (v) => !cleanText(v.keyword) ? 'Enter a keyword.' : null,
    visualize: (el, t, v) => renderVigenereVisual(el, t, v),
    code: `function vigenereEncrypt(text, key) {
  const t = clean(text), k = clean(key);
  return t.split('').map((c, i) =>
    numToLetter(letterToNum(c) + letterToNum(k[i % k.length]))
  ).join('');
}`
  },
  {
    id: 'railfence', glyph: '⩙', name: 'Rail Fence Cipher', desc: 'Zigzag transposition across rails',
    fields: [{ id: 'rails', label: 'Number of rails', type: 'number', value: 3 }],
    encrypt: (t, v) => railFenceEncrypt(t, v.rails), decrypt: (t, v) => railFenceDecrypt(t, v.rails),
    validate: (v) => Number(v.rails) < 2 ? 'Rails must be 2 or more.' : null,
    visualize: (el, t, v) => renderRailFenceVisual(el, t, v),
    code: `function railFenceEncrypt(text, rails) {
  const t = clean(text);
  const fence = Array.from({ length: rails }, () => []);
  let r = 0, dir = 1;
  for (const ch of t) {
    fence[r].push(ch);
    if (r === 0) dir = 1;
    else if (r === rails - 1) dir = -1;
    r += dir;
  }
  return fence.flat().join('');
}`
  }
];

/* ============================================================
   APP STATE + RENDERING
   ============================================================ */
let currentModuleId = null;
const app = document.getElementById('app');

function goHome(){ currentModuleId = null; render(); }
function openModule(id){ currentModuleId = id; render(); }

function render(){
  app.innerHTML = '';
  if (!currentModuleId) renderHome(); else renderModule(MODULES.find(m => m.id === currentModuleId));
}

function renderHome(){
  const header = document.createElement('div');
  header.className = 'topbar';
  header.innerHTML = `<span class="wordmark">Cipher<span>Lab</span></span>`;
  app.appendChild(header);

  const tagline = document.createElement('p');
  tagline.className = 'home-tagline';
  tagline.textContent = 'Seven classical ciphers from number theory — pick one to encrypt, decrypt, and see how it works step by step.';
  app.appendChild(tagline);

  const grid = document.createElement('div');
  grid.className = 'home-grid';
  MODULES.forEach(m => {
    const card = document.createElement('button');
    card.className = 'cipher-card';
    card.innerHTML = `<span class="cipher-glyph">${m.glyph}</span><span class="cipher-card-name">${m.name}</span><span class="cipher-card-desc">${m.desc}</span>`;
    card.onclick = () => openModule(m.id);
    grid.appendChild(card);
  });
  app.appendChild(grid);

  const footer = document.createElement('footer');
  footer.className = 'note';
  footer.textContent = 'Everything runs locally in your browser — nothing is uploaded anywhere.';
  app.appendChild(footer);
}

function renderModule(m){
  const header = document.createElement('div');
  header.className = 'topbar';
  header.innerHTML = `<button class="back-btn" aria-label="Back">‹</button>
    <div><div class="module-title">${m.name}</div><div class="module-sub">${m.desc}</div></div>`;
  header.querySelector('.back-btn').onclick = goHome;
  app.appendChild(header);

  const panel = document.createElement('div');
  panel.className = 'panel';

  const fieldsHtml = m.fields.map(f =>
    `<div><label class="field-label">${f.label}</label>
     <input type="${f.type}" id="field-${f.id}" value="${f.value}" />
     </div>`
  ).join('');

  panel.innerHTML = `
    <div class="panel-label">input</div>
    <label class="field-label">Text</label>
    <textarea id="input-text" placeholder="Type a message...">HELLO WORLD</textarea>
    ${m.fields.length > 1 ? `<div class="field-row">${fieldsHtml}</div>` : fieldsHtml}
    <div class="btn-row">
      <button class="action" id="btn-encrypt">Encrypt</button>
      <button class="action secondary" id="btn-decrypt">Decrypt</button>
    </div>
    <div id="error-slot"></div>
    <div id="output-slot"></div>
  `;
  app.appendChild(panel);

  const visualPanel = document.createElement('div');
  visualPanel.className = 'panel';
  visualPanel.innerHTML = `<div class="panel-label">how it works</div><div id="visual-slot"></div>`;
  app.appendChild(visualPanel);

  const codeToggle = document.createElement('button');
  codeToggle.className = 'code-toggle';
  codeToggle.textContent = '</> view code';
  const codeBlock = document.createElement('pre');
  codeBlock.className = 'code-block';
  codeBlock.style.display = 'none';
  codeBlock.textContent = m.code;
  codeToggle.onclick = () => {
    const visible = codeBlock.style.display !== 'none';
    codeBlock.style.display