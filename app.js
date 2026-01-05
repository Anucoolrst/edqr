/* Minimal client-side encoder/decoder with hash and optional AES-GCM.
   Now supports: auto-shortest, Base64, Base64url, Base91, Base85 (Ascii85), Hex, and optional gzip-before-encode.
*/

// Optional: set this to a proxy base to bypass CORS when the extension isn't available.
// Example for cors-anywhere: 'https://cors-anywhere.herokuapp.com/'
// Example for your own reverse proxy: 'https://your-proxy.example.com/'

// Removed ad-hoc test fetch; network calls now use proxy-aware helpers.

const CTXT_BASE = 'https://ctxt.io';

// Add proxy list and proxy-aware fetch helper (direct first, then fallbacks)
const CTXT_PROXIES = [
  { base: 'https://corsproxy.io/?', methods: ['GET','POST'] },
  { base: 'https://cors.isomorphic-git.org/', methods: ['GET','POST'] },
  { base: 'https://thingproxy.freeboard.io/fetch/', methods: ['GET','POST'] },
  { base: 'https://api.allorigins.win/raw?url=', methods: ['GET'] },
  { base: 'https://cors-anywhere.herokuapp.com/', methods: ['GET','POST'] },
];
// LZMA worker URL for browser instance creation (for stronger compression)
const LZMA_WORKER_URL = 'https://cdn.jsdelivr.net/gh/LZMA-JS/LZMA-JS/src/lzma_worker-min.js';
function makeProxyUrl(base, absUrl){
  try{
    const queryStyle = base.endsWith('?') || /[?&]url=/.test(base);
    if(queryStyle) return base + encodeURIComponent(absUrl);
    const b = base.endsWith('/') ? base : base + '/';
    return b + absUrl;
  }catch{ return absUrl; }
}
async function fetchWithCors(url, options={}){
  const method = (options.method || 'GET').toUpperCase();
  let lastErr;
  try{
    const res = await fetch(url, options);
    if(res.ok) return res;
    lastErr = new Error(`HTTP ${res.status}`);
  }catch(e){ lastErr = e; }
  for(const p of CTXT_PROXIES){
    if(p.methods && !p.methods.includes(method)) continue;
    try{
      const res = await fetch(makeProxyUrl(p.base, url), options);
      if(res.ok) return res;
      lastErr = new Error(`Proxy ${p.base} -> HTTP ${res.status}`);
    }catch(e){ lastErr = e; }
  }
  throw lastErr || new Error('Fetch failed');
}

// Helper to extract the short code from ctxt URLs or paths
function toKoolCode(input){
  try{
    if(!input) return '';
    let s = String(input).trim();
    // remove scheme+host if present
    s = s.replace(/^https?:\/\/[^/]+/i,'');
    // strip query/hash
    s = s.split('?')[0].split('#')[0];
    const parts = s.split('/').filter(Boolean);
    if(!parts.length) return '';
    const id = parts.pop();
    return /^[A-Za-z0-9]+$/.test(id) ? id : '';
  }catch{ return ''; }
}

// Extract code from any input (full URL, path, or code)
function extractCtxtCode(input){
  try{
    if(!input) return '';
    const s = String(input).trim();
    // if it's already a bare code
    if(/^[A-Za-z0-9]{4,}$/.test(s)) return s; // was 6+, allow 4+
    // otherwise strip scheme+host and split
    let p = s.replace(/^https?:\/\/[^/]+/i,'').split('?')[0].split('#')[0];
    const parts = p.split('/').filter(Boolean);
    if(!parts.length) return '';
    const id = parts.pop();
    return /^[A-Za-z0-9]{4,}$/.test(id) ? id : '';
  }catch{ return ''; }
}

// Helper: build a proxied URL for proxies that expect either the full absolute URL appended as a path (e.g., cors-anywhere)
// or passed as a query value (e.g., corsproxy.io)
// viaProxy no longer used (replaced by fetchWithCors). Kept as a passthrough for backward compatibility.
function viaProxy(absUrl){
  return absUrl;
}

const $ = (sel) => document.querySelector(sel);
const enc = {
  file: $('#enc-file'),
  encoding: $('#enc-encoding'),
  pkg: $('#enc-package'),
  tryGzip: $('#enc-try-gzip'),
  encrypt: $('#enc-encrypt'),
  passWrap: $('#enc-pass-wrap'),
  password: $('#enc-password'),
  run: $('#enc-run'),
  copy: $('#enc-copy'),
  download: $('#enc-download'),
  clear: $('#enc-clear'),
  out: $('#enc-output'),
  fileName: $('#enc-file-name'),
  fileSize: $('#enc-file-size'),
  hash: $('#enc-hash'),
  method: $('#enc-method'),
  outLen: $('#enc-out-len'),
  warn: $('#enc-warning'),
  // New: button to send text to ctxt.io
  getText: document.querySelector('#enc-get-text'),
  // New: UI to show the result Kool Code for copy
  resultBox: document.querySelector('#enc-result'),
  resultLink: document.querySelector('#enc-result-link'),
  resultCopy: document.querySelector('#enc-copy-link'),
  // New: compression controls
  compMethod: document.querySelector('#enc-compress-method'),
  compLevel: document.querySelector('#enc-compress-level'),
  // QR UI
  showQrBtn: document.querySelector('#enc-show-qr'),
  qrModal: document.querySelector('#enc-qr-modal'),
  qrClose: document.querySelector('#enc-qr-close'),
  qrBox: document.querySelector('#enc-qr-code')
};

const dec = {
  input: $('#dec-input'),
  textFile: $('#dec-text-file'),
  encoding: $('#dec-encoding'),
  passWrap: $('#dec-pass-wrap'),
  password: $('#dec-password'),
  run: $('#dec-run'),
  clear: $('#dec-clear'),
  detected: $('#dec-detected'),
  name: $('#dec-name'),
  expected: $('#dec-expected'),
  actual: $('#dec-actual'),
  status: $('#dec-status'),
  inLen: document.querySelector('#dec-in-len'),
  // New: paste link input and fetch button
  link: document.querySelector('#dec-link'),
  fetch: document.querySelector('#dec-fetch'),
  // QR scan
  scanBtn: document.querySelector('#dec-scan-qr'),
  scanOverlay: document.querySelector('#qr-scan-overlay'),
  scanVideo: document.querySelector('#qr-video'),
  scanCanvas: document.querySelector('#qr-canvas'),
  scanStatus: document.querySelector('#qr-scan-status'),
  scanClose: document.querySelector('#qr-scan-close'),
};

function humanSize(n){
  if(n===0) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(n)/Math.log(1024));
  return `${(n/Math.pow(1024,i)).toFixed(2)} ${u[i]}`;
}

async function sha256(buf){
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,'0')).join('');
}

function bufToBase64(buf){
  const bytes = new Uint8Array(buf);
  let bin='';
  const chunk=0x8000;
  for(let i=0;i<bytes.length;i+=chunk){ bin += String.fromCharCode.apply(null, bytes.subarray(i,i+chunk)); }
  return btoa(bin);
}
function base64ToBuf(b64){
  const bin = atob(b64.replace(/\s+/g,''));
  const buf = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToBase64Url(buf){
  return bufToBase64(buf).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
}
function base64UrlToBuf(s){
  let b64 = s.replaceAll('-','+').replaceAll('_','/');
  while(b64.length % 4) b64 += '=';
  return base64ToBuf(b64);
}

function bufToHex(buf){ return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function hexToBuf(hex){
  hex = hex.replace(/\s+/g,'');
  if(hex.length % 2) throw new Error('Hex length must be even');
  const len=hex.length/2, out=new Uint8Array(len);
  for(let i=0;i<len;i++) out[i]=parseInt(hex.substr(i*2,2),16);
  return out.buffer;
}

// Minimal Ascii85 (Base85) codec (Adobe Ascii85)
function bufToAscii85(buf){
  const data=new Uint8Array(buf);
  let out='';
  for(let i=0;i<data.length;i+=4){
    const remain=Math.min(4, data.length-i);
    let chunk = 0;
    for(let j=0;j<4;j++) chunk = (chunk<<8) + (j<remain ? data[i+j] : 0);
    if(remain===4 && chunk===0){ out+='z'; continue; }
    const chars = new Array(5);
    for(let k=4;k>=0;k--){ chars[k] = (chunk % 85) + 33; chunk = Math.floor(chunk/85); }
    out += String.fromCharCode(...chars).slice(0, remain+1);
  }
  return out;
}
function ascii85ToBuf(str){
  const input = str.replace(/\s+/g,'');
  const out = [];
  let i=0;
  while(i<input.length){
    if(input[i]==='z'){ out.push(0,0,0,0); i++; continue; }
    const block = input.slice(i, i+5);
    const remain = Math.min(5, block.length);
    let v=0;
    for(let k=0;k<remain;k++) v = v*85 + (block.charCodeAt(k)-33);
    const bytes = [ (v>>>24)&255, (v>>>16)&255, (v>>>8)&255, v&255 ];
    for(let b=0;b<remain-1;b++) out.push(bytes[b]);
    i += remain;
  }
  return new Uint8Array(out).buffer;
}

// Base91 codec (BasE91 by Joachim Henke). Compact, ASCII-safe.
const B91_ENC_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""; // 91 chars
const B91_DEC_TABLE = (()=>{
  const dec = new Int16Array(256).fill(-1);
  for(let i=0;i<B91_ENC_TABLE.length;i++) dec[B91_ENC_TABLE.charCodeAt(i)] = i;
  return dec;
})();
function bufToBase91(buf){
  const data = new Uint8Array(buf);
  let b=0, n=0, out='';
  for(let i=0;i<data.length;i++){
    b |= data[i] << n; n += 8;
    if(n > 13){
      let v = b & 8191; // 2^13-1
      if(v > 88){ b >>= 13; n -= 13; }
      else { v = b & 16383; b >>= 14; n -= 14; }
      out += B91_ENC_TABLE[v % 91] + B91_ENC_TABLE[Math.floor(v / 91)];
    }
  }
  if(n){
    out += B91_ENC_TABLE[b % 91];
    if(n > 7 || b > 90) out += B91_ENC_TABLE[Math.floor(b / 91)];
  }
  return out;
}
function base91ToBuf(str){
  const dec = B91_DEC_TABLE;
  let v=-1, b=0, n=0; const out=[];
  for(let i=0;i<str.length;i++){
    const c = dec[str.charCodeAt(i) & 255];
    if(c === -1) continue; // skip whitespace/invalid
    if(v < 0) v = c; else {
      v += c * 91; b |= v << n; n += (v & 8191) > 88 ? 13 : 14;
      do{ out.push(b & 255); b >>= 8; n -= 8; } while(n > 7);
      v = -1;
    }
  }
  if(v !== -1){ out.push((b | (v << n)) & 255); }
  return new Uint8Array(out).buffer;
}

// Stronger compression (LZMA) helper if library available
let __lzmaInstance = null;
function getLzma(){
  // Try existing instance
  if(__lzmaInstance) return __lzmaInstance;
  // If a ready object with methods exists, use it
  const cand = (window.LZMA || window.lzma);
  if(cand && typeof cand.compress === 'function' && typeof cand.decompress === 'function'){
    __lzmaInstance = cand; return __lzmaInstance;
  }
  // If constructor is provided, instantiate with a worker URL
  if(typeof window.LZMA === 'function'){
    try{ __lzmaInstance = new window.LZMA(LZMA_WORKER_URL); return __lzmaInstance; }catch{}
  }
  throw new Error('LZMA not available');
}
async function lzmaCompress(buf, level){
  const api = getLzma();
  const u8 = new Uint8Array(buf);
  return await new Promise((resolve, reject)=>{
    try{
      api.compress(u8, Number(level)||6, (res)=>{
        try{
          let outU8;
          if(res instanceof Uint8Array) outU8 = res;
          else if(Array.isArray(res)) outU8 = new Uint8Array(res);
          else if(typeof res === 'string') outU8 = new TextEncoder().encode(res);
          else outU8 = new Uint8Array(res);
          resolve(outU8.buffer);
        }catch(e){ reject(e); }
      }, ()=>{});
    }catch(e){ reject(e); }
  });
}
async function lzmaDecompress(buf){
  const api = getLzma();
  const u8 = new Uint8Array(buf);
  return await new Promise((resolve, reject)=>{
    try{
      api.decompress(u8, (res)=>{
        try{
          let outU8;
          if(res instanceof Uint8Array) outU8 = res;
          else if(Array.isArray(res)) outU8 = new Uint8Array(res);
          else if(typeof res === 'string') outU8 = new TextEncoder().encode(res);
          else outU8 = new Uint8Array(res);
          resolve(outU8.buffer);
        }catch(e){ reject(e); }
      });
    }catch(e){ reject(e); }
  });
}

// Replace gzipIfHelpful with a more general compression step
async function compressIfHelpful(buf){
  const methodSel = enc.compMethod?.value || 'auto';
  const levelSel = Number(enc.compLevel?.value || 6);

  // If encryption is enabled, we compress before encrypting (already handled in flow)
  const tryGzip = async()=>{
    try{
      if('CompressionStream' in window){
        const cs = new CompressionStream('gzip');
        const compressed = await new Response(new Blob([buf]).stream().pipeThrough(cs)).arrayBuffer();
        return compressed.byteLength < buf.byteLength ? { buf: compressed, used: true, name: 'gzip' } : { buf, used:false };
      }
    }catch{}
    try{
      if(window.fflate?.gzipSync){
        const gz = window.fflate.gzipSync(new Uint8Array(buf), { level: Math.min(9, Math.max(0, levelSel)) });
        return gz.byteLength < (new Uint8Array(buf)).byteLength ? { buf: gz.buffer, used:true, name:'gzip' } : { buf, used:false };
      }
    }catch{}
    return { buf, used:false };
  };

  const tryLzma = async()=>{
    try{
      const out = await lzmaCompress(buf, Math.min(9, Math.max(1, levelSel)));
      return out.byteLength < buf.byteLength ? { buf: out, used:true, name:'lzma' } : { buf, used:false };
    }catch{ return { buf, used:false }; }
  };

  if(methodSel === 'none') return { buf, used:false, name: null };
  if(methodSel === 'gzip') return await tryGzip();
  if(methodSel === 'lzma') return await tryLzma();

  // auto: pick best size among available
  const results = await Promise.all([tryGzip(), tryLzma()]);
  let best = { buf, used:false, name:null };
  for(const r of results){ if(r.used && r.buf.byteLength < best.buf.byteLength) best = r; }
  return best;
}

// Gzip via CompressionStream if available; else fallback to fflate if present
async function gzipIfHelpful(buf){
  if(!enc.tryGzip?.checked) return {buf, used:false};
  try{
    if('CompressionStream' in window){
      const cs = new CompressionStream('gzip');
      const compressed = await new Response(new Blob([buf]).stream().pipeThrough(cs)).arrayBuffer();
      return compressed.byteLength < buf.byteLength ? {buf:compressed, used:true} : {buf, used:false};
    }
  }catch{}
  // fallback to fflate if available
  try{
    if(window.fflate && window.fflate.gzipSync){
      const u8 = new Uint8Array(buf);
      const gz = window.fflate.gzipSync(u8, { level: 6 });
      return gz.byteLength < u8.byteLength ? { buf: gz.buffer, used:true } : { buf, used:false };
    }
  }catch{}
  return {buf, used:false};
}

async function aesGcmEncrypt(plaintext, password){
  const te=new TextEncoder();
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const km=await crypto.subtle.importKey('raw', te.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:150000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['encrypt']);
  const ct=await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, plaintext);
  const out=new Uint8Array(28+ct.byteLength); out.set(salt,0); out.set(iv,16); out.set(new Uint8Array(ct),28); return out.buffer;
}
async function aesGcmDecrypt(data, password){
  const te=new TextEncoder();
  const u8=new Uint8Array(data); if(u8.length<28) throw new Error('Invalid ciphertext');
  const salt=u8.slice(0,16), iv=u8.slice(16,28), ct=u8.slice(28);
  const km=await crypto.subtle.importKey('raw', te.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:150000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['decrypt']);
  return crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
}

async function fileToArrayBuffer(file){
  return new Promise((res, rej)=>{ const fr=new FileReader(); fr.onerror=()=>rej(fr.error); fr.onload=()=>res(fr.result); fr.readAsArrayBuffer(file); });
}
function downloadBlob(blob, name){ const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name; document.body.appendChild(a); a.click(); setTimeout(()=>{URL.revokeObjectURL(a.href); a.remove();},0); }
function setText(el,t){ if(el) el.textContent=t; }
function resetEncMeta(){ setText(enc.fileName,'—'); setText(enc.fileSize,'—'); setText(enc.hash,'—'); setText(enc.method,'—'); setText(enc.outLen,'—'); enc.warn.textContent=''; }
function resetDecMeta(){ setText(dec.detected,'—'); setText(dec.name,'—'); setText(dec.expected,'—'); setText(dec.actual,'—'); dec.status.textContent=''; }

enc.encrypt.addEventListener('change', ()=>{ enc.passWrap.classList.toggle('hidden', !enc.encrypt.checked); });
enc.clear.addEventListener('click', ()=>{ 
  enc.out.value=''; 
  enc.copy.disabled=true; 
  enc.download.disabled=true; 
  if(enc.getText) enc.getText.disabled=true; 
  if(enc.showQrBtn) enc.showQrBtn.disabled=true;
  if(enc.resultBox){ 
    enc.resultBox.classList.add('hidden'); 
    enc.resultLink.value=''; 
  } 
  resetEncMeta(); 
});
enc.out.addEventListener('input', ()=>{ if(enc.getText) enc.getText.disabled = enc.out.value.trim().length === 0; });

dec.clear.addEventListener('click', ()=>{ dec.input.value=''; resetDecMeta(); updateInputLen(); });

enc.file.addEventListener('change', ()=>{
  const f=enc.file.files[0]; if(!f){ resetEncMeta(); return; }
  setText(enc.fileName, f.name); setText(enc.fileSize, `${f.size.toLocaleString()} (${humanSize(f.size)})`);
  fileToArrayBuffer(f).then(sha256).then(h=> setText(enc.hash,h)).catch(()=>{});
});

enc.copy.addEventListener('click', async ()=>{ try{ await navigator.clipboard.writeText(enc.out.value); enc.copy.textContent='Copied'; setTimeout(()=> enc.copy.textContent='Copy output',1200);}catch{ alert('Copy failed'); } });
enc.download.addEventListener('click', ()=>{
  const txt=enc.out.value; const ext = enc.encoding.value==='hex' ? 'hex' : (enc.encoding.value==='base85'?'a85':(enc.encoding.value==='base91'?'b91':'b64'));
  const name=(enc.file.files[0]?.name||'output') + (enc.pkg.checked?'.json':`.${ext}`);
  downloadBlob(new Blob([txt],{type:'text/plain'}), name);
});

function updateInputLen(){ if(dec.inLen){ const len=dec.input.value.length; dec.inLen.textContent=`${len.toLocaleString()} chars`; } }
['input','change','keyup'].forEach(evt=> dec.input.addEventListener(evt, updateInputLen));

dec.textFile.addEventListener('change', async ()=>{ const f=dec.textFile.files[0]; if(!f) return; const text=await f.text(); dec.input.value=text; updateInputLen(); });

function tryParseJson(text){ try{ return JSON.parse(text); }catch{ return null; }
}
function looksLikeBase64(s){ return /^[A-Za-z0-9+/\r\n=]+$/.test(s.trim()); }
function looksLikeBase64Url(s){ return /^[A-Za-z0-9\-_]+$/.test(s.trim()); }
function looksLikeHex(s){ return /^[0-9a-fA-F\s]+$/.test(s.trim()); }
function looksLikeAscii85(s){ return /^[\x21-\x75z\s]+$/.test(s.trim()); }
function looksLikeBase91(s){ return /^[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~\"\s]+$/.test(s.trim()); }

async function sendToCtxt(text){
  const payload = { ext: 'chrome', v: 2, ttl: '', content: text };
  const prefix = CTXT_BASE;

  try{
    if(window.chrome?.runtime?.sendMessage){
      const tabId = undefined;
      const params = { ...payload, tabId, returnOnly: 1 };
      return await new Promise((resolve, reject)=>{
        try{
          window.chrome.runtime.sendMessage(params, (response)=>{
            const err = window.chrome.runtime.lastError;
            if(err){ reject(new Error(err.message)); return; }
            if(response?.data){ resolve(prefix + response.data); }
            else if(response?.url){ resolve(response.url); }
            else if(response?.error){ reject(new Error(response.error)); }
            else{ reject(new Error('No response')); }
          });
        }catch(e){ reject(e); }
      });
    }
  }catch{}

  // POST using proxy-aware fetch (direct first, then proxies)
  const directUrl = `${CTXT_BASE}/new`;
  const res = await fetchWithCors(directUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const txt = await res.text();
  if(!res.ok) throw new Error(txt || `HTTP ${res.status}`);
  return prefix + txt;
}

// Heuristic: detect common file types from magic bytes or text content and suggest extension
function detectFileExtFromBytes(buf){
  const u8 = new Uint8Array(buf);
  const starts = (...xs)=> xs.every((v,i)=> u8[i]===v);

  if(u8.length>=4){
    if(starts(0x25,0x50,0x44,0x46)) return 'pdf'; // %PDF
    if(u8.length>=8 && starts(0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)) return 'png';
    if(u8[0]===0xFF && u8[1]===0xD8 && u8[2]===0xFF) return 'jpg';
    if(starts(0x47,0x49,0x46,0x38)) return 'gif';
    if(starts(0x42,0x4D)) return 'bmp';
    if(starts(0x1F,0x8B)) return 'gz';
    if(starts(0x50,0x4B,0x03,0x04) || starts(0x50,0x4B,0x05,0x06) || starts(0x50,0x4B,0x07,0x08)) return 'zip';
    if(starts(0x37,0x7A,0xBC,0xAF,0x27,0x1C)) return '7z';
    if(starts(0x52,0x61,0x72,0x21,0x1A,0x07,0x00) || starts(0x52,0x61,0x72,0x21,0x1A,0x07,0x01)) return 'rar';
    if(starts(0x4D,0x5A)) return 'exe';
    if(starts(0x7F,0x45,0x4C,0x46)) return 'elf';
    if(starts(0x4F,0x67,0x67,0x53)) return 'ogg';
    if(starts(0x49,0x44,0x33) || (u8[0]===0xFF && (u8[1] & 0xE0)===0xE0)) return 'mp3';
    if(u8.length>=12 && u8[4]===0x66 && u8[5]===0x74 && u8[6]===0x79 && u8[7]===0x70) return 'mp4';
    if(u8.length>262 && String.fromCharCode(...u8.slice(257,262))==='ustar') return 'tar';
    if(u8.length>=12 && starts(0x52,0x49,0x46,0x46)){
      const tag = String.fromCharCode(u8[8],u8[9],u8[10],u8[11]);
      if(tag==='WAVE') return 'wav';
      if(tag==='WEBP') return 'webp';
      return 'riff';
    }
  }
  try{
    const td=new TextDecoder('utf-8',{fatal:false});
    const s=td.decode(u8.slice(0, Math.min(4096,u8.length))).trim();
    if(!s) return 'bin';
    if(s[0]==='{' || s[0]==='['){ try{ JSON.parse(s); return 'json'; }catch{} }
    if(/^<\?xml\b/i.test(s)) return 'xml';
    if(/^<svg[\s>]/i.test(s)) return 'svg';
    if(/^[\x09\x0A\x0D\x20-\x7E]/.test(s)) return 'txt';
  }catch{}
  return 'bin';
}
function suggestDownloadName(meta, buf){
  if(meta?.name) return meta.name;
  const ext = detectFileExtFromBytes(buf);
  return `decoded.${ext}`;
}

if(enc.resultCopy){
  enc.resultCopy.addEventListener('click', async ()=>{
    if(!enc.resultLink?.value) return;
    try{ await navigator.clipboard.writeText(enc.resultLink.value); enc.resultCopy.textContent='Copied'; setTimeout(()=> enc.resultCopy.textContent='Copy code',1200);}catch{ enc.resultLink.select(); }
  });
}

if(enc.getText){
  // Wrap outgoing text with a light JSON package (to preserve filename) if needed
  function ensureSharePackage(text){
    const pkg = tryParseJson(text);
    if(pkg && pkg.data) return text; // already packaged
    const f = enc.file?.files?.[0];
    if(!f) return text;
    const meta = { name: f.name, size: f.size };
    const h = (enc.hash?.textContent || '').trim();
    if(/^[0-9a-f]{64}$/i.test(h)) meta.sha256 = h;
    const wrapped = { v: 2, meta, data: text };
    return JSON.stringify(wrapped);
  }

  enc.getText.addEventListener('click', async ()=>{
    // Fix minor label typo
    const text = enc.out.value.trim();
    if(!text){ alert('No encoded text to send.'); return; }
    const originalLabel = enc.getText.textContent;
    enc.getText.textContent = 'Compressing...';
    enc.getText.disabled = true;
    if(enc.resultBox){ enc.resultBox.classList.add('hidden'); enc.resultLink.value=''; }
    if(enc.showQrBtn) enc.showQrBtn.disabled=true;
    try{
      const toSend = ensureSharePackage(text);
      const url = await sendToCtxt(toSend);
      if(enc.resultBox && enc.resultLink){
        enc.resultLink.value = toKoolCode(url) || '';
        enc.resultBox.classList.remove('hidden');
        // Enable Show QR button when Kool Code is available
        if(enc.showQrBtn) enc.showQrBtn.disabled = !enc.resultLink.value;
        try{ enc.resultLink.focus(); enc.resultLink.select(); }catch{}
      }
      enc.getText.textContent = 'Get Kool Code';
    }catch(e){
      console.error(e);
      alert('Failed to send: ' + e.message);
      enc.getText.textContent = originalLabel;
    }finally{
      enc.getText.disabled = enc.out.value.trim().length === 0;
    }
  });
}

enc.run.addEventListener('click', async ()=>{
  enc.warn.textContent=''; enc.copy.disabled=true; enc.download.disabled=true; if(enc.getText) enc.getText.disabled=true; enc.out.value=''; enc.outLen.textContent='—'; setText(enc.method,'—');
  const file=enc.file.files[0]; if(!file){ enc.warn.textContent='Select a file first.'; return; }
  try{
    const buf0=await fileToArrayBuffer(file);
    const origHash=await sha256(buf0);
    let workBuf=buf0; let steps=[];

    // IMPORTANT: Compress first, then encrypt (encryption destroys redundancy)
    let comp = await compressIfHelpful(workBuf);
    if(comp.used){ workBuf = comp.buf; steps.push(comp.name); }

    if(enc.encrypt.checked){
      const pwd=enc.password.value||''; if(!pwd){ enc.warn.textContent='Enter a password for encryption.'; return; }
      workBuf=await aesGcmEncrypt(workBuf,pwd); steps.push('AES-GCM');
    }

    const choice = enc.encoding.value;
    function variant(label, text){ return {label, text, len:text.length}; }

    const candidates=[];
    const b64 = bufToBase64(workBuf); candidates.push(variant('base64', b64));
    const b64u = bufToBase64Url(workBuf); candidates.push(variant('base64url', b64u));
    const b91 = bufToBase91(workBuf); candidates.push(variant('base91', b91));
    const a85 = bufToAscii85(workBuf); candidates.push(variant('base85', a85));
    const hx = bufToHex(workBuf); candidates.push(variant('hex', hx));

    let chosen;
    if(choice==='auto'){
      chosen = candidates.reduce((a,b)=> a.len<=b.len?a:b);
    }else{
      chosen = candidates.find(c=>c.label===choice) || candidates[0];
    }

    let outputText = chosen.text;
    if(enc.pkg.checked){
      const pkg={ v:2, meta:{ name:file.name, size:file.size, sha256: origHash, ts: Date.now(), enc: chosen.label, encrypted: enc.encrypt.checked, gzip: false, comp: comp.used ? comp.name : 'none' }, data: outputText };
      outputText = JSON.stringify(pkg);
    }

    enc.out.value=outputText; enc.outLen.textContent=`${outputText.length.toLocaleString()} chars`; setText(enc.method, `${steps.join(' + ')}${steps.length? ' + ':''}${chosen.label}`);
    enc.copy.disabled=false; enc.download.disabled=false; if(enc.getText) enc.getText.disabled=false;
    if(outputText.length>2_000_000){ enc.warn.textContent='Warning: Output is large; some sites may truncate pasted text. Prefer download.'; }
  }catch(err){ console.error(err); enc.warn.textContent='Error: '+err.message; }
});

// Decode

dec.run.addEventListener('click', async ()=>{
  resetDecMeta(); updateInputLen();
  const text = dec.input.value.trim(); if(!text){ dec.status.textContent='Provide text to decode.'; return; }
  try{
    let meta=null, dataStr=null, detected='raw';
    const pkg=tryParseJson(text);
    if(pkg && pkg.data){ detected='JSON package'; meta=pkg.meta||{}; dataStr=pkg.data; setText(dec.name, meta.name||'unknown'); setText(dec.expected, meta.sha256||'—'); setText(dec.detected, `${detected}${meta.encrypted?' + AES-GCM':''}${meta.gzip?' + gzip':''}${meta.comp?` + ${meta.comp}`:''} + ${(meta.enc||'base64').toUpperCase()}`); dec.passWrap.classList.toggle('hidden', !meta.encrypted); }
    else{
      const mode=dec.encoding.value;
      if(mode==='auto'){
        if(looksLikeBase64Url(text)) { detected='Base64url'; dataStr=text; }
        else if(looksLikeBase64(text)) { detected='Base64'; dataStr=text; }
        else if(looksLikeBase91(text)) { detected='Base91'; dataStr=text; }
        else if(looksLikeAscii85(text)) { detected='Base85'; dataStr=text; }
        else if(looksLikeHex(text)) { detected='Hex'; dataStr=text.replace(/\s+/g,''); }
        else throw new Error('Unknown text format. Provide JSON, Base64/Base91/Base85/Hex.');
      }else{ detected=mode.toUpperCase(); dataStr=text; }
      setText(dec.detected, detected);
    }

    const encLabel = meta?.enc || detected.toLowerCase();
    let buf;
    if(encLabel.includes('91')) buf = base91ToBuf(dataStr);
    else if(encLabel.includes('85')) buf = ascii85ToBuf(dataStr);
    else if(encLabel.includes('64url')) buf = base64UrlToBuf(dataStr);
    else if(encLabel.includes('64')) buf = base64ToBuf(dataStr);
    else if(encLabel.includes('hex')) buf = hexToBuf(dataStr);
    else throw new Error('Unsupported encoding');

    // IMPORTANT: Decrypt first (if encrypted), then decompress
    if(meta?.encrypted || (!meta && !dec.passWrap.classList.contains('hidden') && dec.password.value)){
      const pwd=dec.password.value||''; if(!pwd) throw new Error('Password required for encrypted data');
      buf = await aesGcmDecrypt(buf,pwd);
    }

    // Decompression: support old meta.gzip as well as new meta.comp
    if(meta?.gzip && !meta?.comp){
      if('DecompressionStream' in window){
        buf = await new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
      }else if(window.fflate?.gunzipSync){
        buf = window.fflate.gunzipSync(new Uint8Array(buf)).buffer;
      }else{
        throw new Error('Gzip decode not supported in this browser');
      }
    } else if(meta?.comp === 'gzip'){
      if('DecompressionStream' in window){
        buf = await new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
      }else if(window.fflate?.gunzipSync){
        buf = window.fflate.gunzipSync(new Uint8Array(buf)).buffer;
      }else{
        throw new Error('Gzip decode not supported in this browser');
      }
    } else if(meta?.comp === 'lzma'){
      buf = await lzmaDecompress(buf);
    }

    const actualHash=await sha256(buf); setText(dec.actual, actualHash);
    const outName = suggestDownloadName(meta, buf);
    if(meta?.sha256){ if((meta.sha256||'').toLowerCase()===actualHash){ dec.status.textContent='Integrity: OK'; dec.status.style.color='var(--accent-2)'; } else { dec.status.textContent='Integrity: MISMATCH'; dec.status.style.color='var(--danger)'; } }
    else { dec.status.textContent='Decoded. No expected hash to verify.'; dec.status.style.color=''; }

    downloadBlob(new Blob([buf]), outName);
  }catch(err){ console.error(err); dec.status.textContent='Error: '+err.message; dec.status.style.color='var(--danger)'; }
});

function normalizeCtxtUrl(url){
  const s = (url || '').trim();
  if(!s) return '';

  // Prefer converting anything we recognize into a direct page URL (no raw/download variants)
  const code = extractCtxtCode(s);
  if(code) return `${CTXT_BASE}/${code}`;

  // Fallback: accept any explicit http(s) URL
  const withScheme = (u) => (/^https?:\/\//i.test(u) ? u : `https://${u}`);
  try {
    const u = new URL(withScheme(s));
    return u.toString();
  } catch {}

  return '';
}

// Simple validator: accept either a recognizable code or any http(s) URL
function isValidCtxtInput(s){
  if(!s) return false;
  if(extractCtxtCode(s)) return true;
  try{
    const u = new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`);
    return u.protocol === 'http:' || u.protocol === 'https:';
  }catch{ return false; }
}

// New: extract main text from an HTML page (fallback when raw is not served)
function extractTextFromHtml(html){
  try{
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // Prefer obvious content holders, then largest <pre>/<code>
    const candidates = [];
    const pushIf = el => { if(el && el.textContent) candidates.push(el); };
    pushIf(doc.querySelector('#content'));
    pushIf(doc.querySelector('.content'));
    doc.querySelectorAll('pre, code').forEach(el => pushIf(el));

    let best = null;
    for(const el of candidates){
      if(!best || el.textContent.length > best.textContent.length) best = el;
    }
    const raw = best ? best.textContent : (doc.body ? doc.body.innerText : '');
    return raw || '';
  }catch{ return ''; }
}

async function fetchCtxtText(url){
  // Normalize input and construct base URL candidates
  let s = String(url || '').trim();
  const code = extractCtxtCode(s);
  const bases = [];

  const ensureAbs = (u) => {
    const withScheme = /^https?:\/\//i.test(u) ? u : `https://${u}`;
    return withScheme.replace(/\/$/, '');
  };

  if (code && !/ctxt\.io/i.test(s)) {
    // Bare code: prefer versioned path first
    bases.push(`${CTXT_BASE}/2/${code}`);
    bases.push(`${CTXT_BASE}/${code}`);
  } else {
    // Already a URL/host; normalize and try both versioned and unversioned when applicable
    s = ensureAbs(s);
    const u0 = new URL(s);
    const parts = u0.pathname.split('/').filter(Boolean);
    if (parts.length === 1 && /^[A-Za-z0-9]{4,}$/.test(parts[0])) {
      // Looks like /{code} – also try /2/{code}
      bases.push(`${u0.origin}/2/${parts[0]}`);
    }
    bases.push(s.replace(/\/$/, ''));
  }

  // De-duplicate while preserving order
  const seen = new Set();
  const baseList = bases.filter(b => {
    const k = b.toLowerCase();
    if (seen.has(k)) return false; seen.add(k); return true;
  });

  let lastErr;
  for (const base of baseList) {
    const u = base.replace(/\/$/, '');

    // 1) Try fetching as plain text directly (with proxy fallback)
    try {
      const res = await fetchWithCors(u, { headers: { 'Accept': 'text/plain,*/*;q=0.8' }, redirect: 'follow' });
      if (res.ok) {
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (ct.includes('text/plain') || ct.includes('octet-stream')) {
          return await res.text();
        }
      } else {
        lastErr = new Error(`HTTP ${res.status}`);
      }
    } catch (e) { lastErr = e; }

    // 3) Fallback: fetch HTML page and extract text (with proxy fallback)
    try {
      const htmlRes = await fetchWithCors(u, { headers: { 'Accept': 'text/html,*/*;q=0.8' }, redirect: 'follow' });
      if (!htmlRes.ok) { lastErr = new Error(`HTTP ${htmlRes.status}`); continue; }
      const html = await htmlRes.text();

      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');

      const candidates = [];
      const pushIf = el => { if (el && el.textContent) candidates.push(el); };
      pushIf(doc.querySelector('#content'));
      pushIf(doc.querySelector('.content'));
      doc.querySelectorAll('pre, code').forEach(el => pushIf(el));

      let best = null;
      for (const el of candidates) {
        if (!best || (el.textContent.length > best.textContent.length)) best = el;
      }

      const extracted = best ? best.textContent : (doc.body ? doc.body.innerText : '');
      if (extracted) return extracted;
    } catch (e) { lastErr = e; }
  }

  throw lastErr || new Error('Failed to fetch CTXT content');
}

// Remove constant CTXT boilerplate and any leading spaces/blank lines from fetched text
function sanitizeFetchedText(raw){
  if (raw == null) return '';
  let out = String(raw);

  // Remove CDATA Google conversion snippet block (if present)
  out = out.replace(/\/\*\s*<!\[CDATA\[[\s\S]*?\]\]>\s*\*\//g, '');

  // Remove combined footer line that sometimes appears without a newline
  out = out.replace(/Terms of Service\s*Report this/gi, '');

  const lines = out.split(/\r?\n/);
  const isBoilerplate = (s) => {
    const t = s.trim();
    return (
      /^This paste expires in\b/i.test(t) ||
      /^Public IP access\.?$/i.test(t) ||
      /^Share whatever you see with others in seconds with\b/i.test(t) ||
      /^Context\.?$/i.test(t) ||
      /^Terms of Service$/i.test(t) ||
      /^Report this$/i.test(t)
    );
  };

  // Filter out boilerplate lines anywhere in the text
  let filtered = lines.filter(line => !isBoilerplate(line));

  // Remove leading blank lines
  while (filtered.length && filtered[0].trim() === '') filtered.shift();
  // Remove trailing blank lines
  while (filtered.length && filtered[filtered.length - 1].trim() === '') filtered.pop();

  if (filtered.length) {
    // Ensure no spaces at the start of the text (first line only)
    filtered[0] = filtered[0].replace(/^\s+/, '');
  }

  return filtered.join('\n');
}

if(dec.fetch){
  dec.fetch.addEventListener('click', async ()=>{
    const rawInput = (dec.link?.value || '').trim();
    if(!isValidCtxtInput(rawInput)){
      dec.status.textContent = 'Enter a valid CTXT code or link.';
      dec.status.style.color='var(--danger)';
      return;
    }
    dec.status.textContent = 'Fetching…';
    dec.status.style.color='';
    try{
      // Important: pass the original input so we also try the page URL, like webapp.js
      const text = await fetchCtxtText(rawInput);
      const cleaned = sanitizeFetchedText(text);
      dec.input.value = cleaned; // apply sanitization and preserve remaining content
      updateInputLen();
      dec.status.textContent = 'Loaded content from code.';
      dec.status.style.color = 'var(--accent-2)';
    }catch(e){
      console.error(e);
      dec.status.textContent = 'Fetch failed: ' + (e.message || e);
      dec.status.style.color = 'var(--danger)';
    }
  });
}

// THEME TOGGLE (light/dark) with persistence
(function setupThemeToggle(){
  try{
    const btn = document.getElementById('theme-toggle');
    if(!btn) return;

    const themeKey = 'vr-theme';
    const apply = (mode)=>{
      document.body.dataset.theme = mode;
      const meta = document.querySelector('meta[name="theme-color"]');
      if(meta){ meta.setAttribute('content', mode==='light' ? '#f6f8fb' : '#0b1020'); }
      const toMode = mode === 'light' ? 'dark' : 'light';
      btn.setAttribute('aria-label', `Switch to ${toMode} mode`);
      btn.title = 'Toggle theme';
      btn.setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
    };

    let saved = localStorage.getItem(themeKey);
    if(!saved){
      const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
      saved = prefersLight ? 'light' : 'dark';
    }
    apply(saved);

    btn.addEventListener('click', ()=>{
      const next = (document.body.dataset.theme === 'light') ? 'dark' : 'light';
      localStorage.setItem(themeKey, next);
      apply(next);
    });
  }catch{}
})();

// QR Code generation (after Kool Code produced)
function renderKoolQr(code){
  if(!enc.qrBox) return;
  enc.qrBox.innerHTML='';
  
  const payload = code.trim();
  console.log('Generating QR for:', payload);
  
  // Use qrserver.com online QR service - Method 2 (the working one)
  try {
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(payload)}`;
    const img = document.createElement('img');
    img.src = qrUrl;
    img.style.width = '200px';
    img.style.height = '200px';
    img.style.border = '1px solid #ccc';
    img.onerror = () => {
      console.error('QR service unavailable');
      enc.qrBox.innerHTML = `
        <div style="text-align: center; padding: 20px;">
          <p>QR service temporarily unavailable</p>
          <p style="font-size: 12px; word-break: break-all;">${payload}</p>
        </div>
      `;
    };
    img.onload = () => {
      console.log('QR code generated successfully using qrserver.com');
    };
    enc.qrBox.appendChild(img);
  } catch (error) {
    console.error('QR generation error:', error);
    enc.qrBox.innerHTML = `
      <div style="text-align: center; padding: 20px;">
        <p>Failed to generate QR code</p>
        <p style="font-size: 12px; word-break: break-all;">${payload}</p>
      </div>
    `;
  }
}

function openQrModal(){ if(!enc.qrModal) return; enc.qrModal.classList.remove('hidden'); }
function closeQrModal(){ if(!enc.qrModal) return; enc.qrModal.classList.add('hidden'); }
if(enc.showQrBtn){
  enc.showQrBtn.addEventListener('click', ()=>{
    const code = enc.resultLink?.value || '';
    if(!code){ alert('No Kool Code yet.'); return; }
    renderKoolQr(code);
    openQrModal();
  });
}
if(enc.qrClose){ enc.qrClose.addEventListener('click', closeQrModal); }
window.addEventListener('keydown', e=>{ if(e.key==='Escape') closeQrModal(); });
enc.qrModal?.addEventListener('click', e=>{ if(e.target===enc.qrModal) closeQrModal(); });

// QR Scanning
let qrScanStream=null, qrScanActive=false;
function ensureJsQr(){ return typeof jsQR === 'function'; }
async function startQrScan(){
  if(!dec.scanOverlay) return;
  if(!ensureJsQr()){ alert('QR scan library missing.'); return; }
  dec.scanStatus.textContent='📷 Starting camera...';
  dec.scanOverlay.classList.remove('hidden');
  try{
    // Optimized camera settings for speed and QR detection
    qrScanStream = await navigator.mediaDevices.getUserMedia({ 
      video:{ 
        facingMode: 'environment',
        width: { ideal: 640, max: 1280 },  // Lower resolution for speed
        height: { ideal: 480, max: 720 },
        frameRate: { ideal: 30, max: 60 }  // High frame rate for responsive scanning
      } 
    });
    dec.scanVideo.srcObject = qrScanStream; 
    await dec.scanVideo.play();
    qrScanActive = true; 
    dec.scanStatus.textContent='📷 Point camera at QR code - Ultra-fast scanning active!';
    // Start scanning immediately
    scanLoop();
  }catch(e){ 
    dec.scanStatus.textContent='❌ Camera error: '+e.message; 
    console.error('Camera error:', e);
  }
}
function stopQrScan(){
  qrScanActive=false;
  if(qrScanStream){ qrScanStream.getTracks().forEach(t=>t.stop()); qrScanStream=null; }
  dec.scanOverlay?.classList.add('hidden');
}
async function scanLoop(){
  if(!qrScanActive) return;
  try{
    const video = dec.scanVideo;
    if(video.readyState===video.HAVE_ENOUGH_DATA){
      const canvas = dec.scanCanvas; const ctx = canvas.getContext('2d');
      // Use much smaller canvas for maximum speed
      const scale = 0.3; // Process at 30% resolution for ultra-fast speed
      canvas.width = video.videoWidth * scale; 
      canvas.height = video.videoHeight * scale;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      
      // Use fastest jsQR settings
      const result = jsQR(imgData.data, canvas.width, canvas.height, { 
        inversionAttempts: 'dontInvert' // Skip inversion for maximum speed
      });
      
      if(result && result.data){
        dec.scanStatus.textContent='✅ QR Code Found!';
        // IMPORTANT: Fill the Kool Code field (next to fetch button) - NOT the decode input
        if(dec.link){ 
          dec.link.value = result.data.trim();
          console.log('✅ QR scanned and pasted to Kool Code field:', result.data.trim());
          // Auto-focus the field to show it was filled
          dec.link.focus();
          dec.link.select();
        }
        stopQrScan();
        return; // Exit immediately, no delay
      }else{
        dec.scanStatus.textContent='📷 Scanning...';
      }
    }
  }catch(e){ dec.scanStatus.textContent='❌ Scan error: '+e.message; }
  // Ultra-fast scanning for instant detection
  setTimeout(scanLoop, 10); // Scan every 10ms (100 times per second!)
}
if(dec.scanBtn){ dec.scanBtn.addEventListener('click', startQrScan); }
if(dec.scanClose){ dec.scanClose.addEventListener('click', stopQrScan); }
window.addEventListener('keydown', e=>{ if(e.key==='Escape') stopQrScan(); });
dec.scanOverlay?.addEventListener('click', e=>{ if(e.target===dec.scanOverlay) stopQrScan(); });

// When a Kool Code is generated, we can optionally auto-generate QR silently
function maybeAutoQr(){
  if(!enc.resultLink?.value) return;
  if(enc.qrBox && !enc.qrModal?.classList.contains('hidden')) renderKoolQr(enc.resultLink.value);
}
// Hook into result copy generation end (after Get Kool Code sets value)
// Using MutationObserver to detect value change
if(enc.resultLink){
  const obs = new MutationObserver(()=> maybeAutoQr());
  obs.observe(enc.resultLink, { attributes:true, attributeFilter:['value'] });
}
