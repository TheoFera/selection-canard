import { readFile, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto as crypto } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, 'src', 'site.html');
const DOCS = resolve(__dirname, 'docs');
const PAYLOAD = resolve(DOCS, 'payload.json');
const IMG_DIR = resolve(__dirname, 'src', 'images');

const iterations = 150000; // PBKDF2 (SHA-256)
const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64(uint8){ return Buffer.from(uint8).toString('base64'); }

// --- Inline local images (src="images/…") et "images/…" dans des chaînes JS ---
function inlineImages(html){
  function toDataUri(file){
    const p = join(IMG_DIR, file);
    if (!existsSync(p)) return null;
    const ext = (file.split('.').pop() || '').toLowerCase();
    const mime = ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg'
              : ext === 'png'  ? 'image/png'
              : ext === 'gif'  ? 'image/gif'
              : 'application/octet-stream';
    const b64 = readFileSync(p).toString('base64');
    return `data:${mime};base64,${b64}`;
  }

  // 1) Attributs HTML: src="images/..." ou src='images/...'
  html = html.replace(/src=(["'])images\/([^"']+)\1/g, (m, q, file) => {
    const uri = toDataUri(file);
    return uri ? `src=${q}${uri}${q}` : m;
  });

  // 2) Chaînes dans le JS/HTML: "images/..." ou 'images/...'
  html = html.replace(/(["'])images\/([^"']+)\1/g, (m, q, file) => {
    const uri = toDataUri(file);
    return uri ? `${q}${uri}${q}` : m;
  });

  return html;
}

async function deriveKey(password, salt){
  const norm = password.toLowerCase().trim(); 
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(norm), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations, hash:'SHA-256'},
    keyMaterial, {name:'AES-GCM', length:256}, false, ['encrypt']
  );
}

async function main(){
  const [, , password] = process.argv;
  if (!password){ console.error('Usage: node encrypt.mjs <motdepasse>'); process.exit(1); }
  const htmlRaw = await readFile(SRC, 'utf8');
  const html    = inlineImages(htmlRaw);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const data = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(html));

  const payload = {
    v: 1, kdf: 'PBKDF2', hash: 'SHA-256', iterations,
    algo: 'AES-GCM',
    salt: toBase64(salt),
    iv:   toBase64(iv),
    data: toBase64(new Uint8Array(data))
  };
  await writeFile(PAYLOAD, JSON.stringify(payload), 'utf8');
  console.log('OK: docs/payload.json mis à jour. Déployez le dossier "docs" sur GitHub Pages.');
}
main().catch(err => { console.error(err); process.exit(1); });
