'use strict';
// UC-10 theme packages. Builds one Verify theme ZIP per brand from the repo's ci-theme/templates (offline, no tenant needed) and tries to
// register it (POST /v1.0/branding/themes). Registration is refused on this trial tenant (403 CSIAZ3060E) [LIVE], so the ZIPs are READY, not APPLIED.
// What a brand theme changes (all inside the ZIP, nothing on the tenant until branding is enabled):
//   - the login page: brand wordmark logo, brand colours (page_style.css), brand name, links, legal text and support link, in English and French
//   - labels for every locale file: brand URL and name; French and English strings for the brand sentences
// The success path of register() (201, then assign themeId to the application) was NOT executed: only the 403 was.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const FormData = require('form-data');
const { api, send, getToken, BASE, OUT_DIR } = require('../lib/verify');
const c = require('./common');

const SRC = path.join(__dirname, '..', '..', 'ci-theme', 'templates');
const THEME_DIR = path.join(OUT_DIR, 'themes');

// Replace "$KEY$=..." or append it. Properties files are UTF-8 (the header says NLS_ENCODING=UTF-8).
function setLabel(file, key, value) {
  const txt = fs.readFileSync(file, 'utf8');
  const re = new RegExp(`^\\$${key}\\$=.*$`, 'm');
  const line = `$${key}$=${value}`;
  fs.writeFileSync(file, re.test(txt) ? txt.replace(re, () => line) : `${txt.replace(/\s*$/, '\n')}${line}\n`);
}

const logoSvg = (b) => `<?xml version="1.0" encoding="UTF-8"?>\n<svg width="292px" height="46px" viewBox="0 0 292 46" xmlns="http://www.w3.org/2000/svg">` +
  `<title>${b.name}</title><rect x="0" y="6" width="34" height="34" rx="6" fill="${b.colour}"/>` +
  `<text x="17" y="31" font-family="Helvetica, Arial, sans-serif" font-size="22" font-weight="700" fill="#ffffff" text-anchor="middle">${b.name[0]}</text>` +
  `<text x="46" y="31" font-family="Helvetica, Arial, sans-serif" font-size="22" font-weight="600" fill="${b.dark}">${b.name}</text></svg>\n`;

// Builds demo/out/themes/<themeName>.zip. Returns {zip, bytes, dir}.
function build(b) {
  const work = path.join(THEME_DIR, b.key);
  fs.rmSync(work, { recursive: true, force: true });
  fs.mkdirSync(work, { recursive: true });
  const tpl = path.join(work, 'templates');
  fs.cpSync(SRC, tpl, { recursive: true });

  // labels: every locale file gets the brand URL and name; en (default) and fr get the brand sentences in their language
  const labelsDir = path.join(tpl, 'common', 'labels');
  for (const loc of fs.readdirSync(labelsDir)) {
    const f = path.join(labelsDir, loc, 'template_labels.properties');
    if (!fs.existsSync(f)) continue;
    const lang = loc === 'default' ? 'en' : loc === 'fr' ? 'fr' : 'en'; // other locales: English brand sentences (not part of IFC's EN/FR ask)
    const t = b.text[lang];
    setLabel(f, 'DEMO_APPLICATION_URL', c.origin(b));
    setLabel(f, 'DEMO_APPLICATION_NAME', b.name);
    setLabel(f, 'BRAND_LEGAL', t.legal);
    setLabel(f, 'BRAND_SUPPORT', t.support);
    setLabel(f, 'BRAND_SUPPORT_URL', b.supportUrl);
    if (loc === 'default' || loc === 'fr') {
      setLabel(f, 'PRODUCT_NAME', b.name);
      setLabel(f, 'LOGIN_TITLE', `${t.signIn} - ${b.name}`);
      setLabel(f, 'REGISTER_ACCOUNT', lang === 'fr' ? `Nouveau chez ${b.name} ?` : `New to ${b.name}?`);
      setLabel(f, 'OPEN_AN_ACCOUNT', lang === 'fr' ? 'Ouvrir un compte' : 'Open an account');
      setLabel(f, 'EMAIL_SENDER', `support@${b.host.replace('.localhost', '.example')}`);
    }
  }

  // login page: legal text and support link above the footer
  const login = path.join(tpl, 'authentication', 'login', 'identity_source', 'identity_source_selection', 'default', 'combined_login_selection.html');
  const html = fs.readFileSync(login, 'utf8');
  const block = '    <p class="brand-legal">$BRAND_LEGAL$ <a href="$BRAND_SUPPORT_URL$" class="blue">$BRAND_SUPPORT$</a></p>\n    <div class="footer">';
  if (!html.includes('<div class="footer">')) throw new Error('login template changed: footer marker not found');
  fs.writeFileSync(login, html.replace('    <div class="footer">', block));

  // colours: the demo theme's two blues become the brand colour and its dark shade
  const css = path.join(tpl, 'common', 'page_components', 'default', 'page_style.css');
  let style = fs.readFileSync(css, 'utf8');
  style = style.replace(/#00468C/gi, b.colour).replace(/#024f9c/gi, b.dark);
  fs.writeFileSync(css, `${style}\n.brand-legal { text-align: center; font-size: 13px; margin: 12px auto; max-width: 600px; color: #555; }\n`);

  // logo
  const logoDir = path.join(tpl, 'common', 'logo', 'default');
  fs.writeFileSync(path.join(logoDir, 'logo.svg'), logoSvg(b));
  fs.writeFileSync(path.join(logoDir, 'logo2.svg'), logoSvg(b));

  const zip = path.join(THEME_DIR, `${b.themeName}.zip`);
  fs.rmSync(zip, { force: true });
  execFileSync('zip', ['-r', '-X', '-q', zip, 'templates'], { cwd: work });
  return { zip, bytes: fs.statSync(zip).size, dir: tpl };
}

async function list() {
  const r = await api('GET', '/v1.0/branding/themes', { quiet: true });
  return (r.data && r.data.themeRegistrations) || [];
}

// Tries to register (or update) the brand theme. Returns {status, blocked, id, message}. Never throws on HTTP errors.
async function register(b, zip) {
  const existing = (await list()).find((t) => t.name === b.themeName);
  const form = new FormData();
  form.append('configuration', JSON.stringify({ name: b.themeName, description: `UC-10 ${b.name}` }));
  form.append('files', fs.createReadStream(zip), `"${b.themeName}.zip"`);
  const r = await send({
    method: existing ? 'put' : 'post', url: `${BASE}/v1.0/branding/themes${existing ? `/${existing.id}` : ''}`,
    headers: { ...form.getHeaders(), Authorization: `Bearer ${await getToken()}` }, data: form, maxBodyLength: Infinity,
    validateStatus: () => true, transformResponse: (x) => x,
  });
  let body = r.data; try { body = JSON.parse(r.data); } catch (e) { /* keep raw */ }
  const blocked = r.status === 403 && body && body.messageId === 'CSIAZ3060E';
  const id = r.status < 300 ? ((await list()).find((t) => t.name === b.themeName) || {}).id : null;
  return { status: r.status, blocked, id, message: body && body.messageDescription ? body.messageDescription : null, messageId: body && body.messageId ? body.messageId : null };
}

module.exports = { build, register, list, setLabel, THEME_DIR };

// CLI: node demo/uc10-brands/themes.js   -> builds both ZIPs and tries to register them
if (require.main === module) {
  (async () => {
    for (const b of c.BRAND_LIST) {
      const out = build(b);
      console.log(`Theme ${b.themeName}: built ${out.zip} (${out.bytes} bytes)`);
      const r = await register(b, out.zip);
      console.log(`  register: HTTP ${r.status} ${r.messageId || ''} ${r.message || ''}${r.blocked ? '  -> branding is not enabled on this tenant' : ''}`);
    }
  })().catch((e) => { console.error(e.message || e); process.exit(1); });
}
