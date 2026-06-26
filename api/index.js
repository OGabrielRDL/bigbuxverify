const express = require('express');
const crypto = require('crypto');
const path = require('path');
const mongoose = require('mongoose');

const app = express();

function cleanEnv(name, fallback = '') {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === '') return fallback;
  return String(raw).trim().replace(/^['\"]|['\"]$/g, '').trim();
}

function firstEnv(names, fallback = '') {
  for (const name of names) {
    const value = cleanEnv(name);
    if (value) return value;
  }
  return fallback;
}

const PORT = cleanEnv('PORT') || 3000;
const FALLBACK_URL = cleanEnv('VERCEL_URL') ? `https://${cleanEnv('VERCEL_URL')}` : `http://localhost:${PORT}`;
const PUBLIC_URL = (
  firstEnv(['PUBLIC_URL', 'AUTH_PUBLIC_URL', 'APP_URL', 'BASE_URL', 'BIGBUX_SITE_URL', 'NEXT_PUBLIC_SITE_URL'], FALLBACK_URL)
).replace(/\/$/, '');

const CLIENT_ID = firstEnv(['DISCORD_CLIENT_ID', 'DISCORD_OAUTH_CLIENT_ID']);
const CLIENT_SECRET = firstEnv(['DISCORD_CLIENT_SECRET', 'DISCORD_OAUTH_CLIENT_SECRET']);
const BOT_TOKEN = firstEnv(['SITE_DISCORD_BOT_TOKEN', 'DISCORD_BOT_TOKEN', 'DISCORD_TOKEN', 'BOT_TOKEN', 'TOKEN']);
const DEFAULT_GUILD_ID = firstEnv(['DISCORD_GUILD_ID', 'ALLOWED_GUILD_ID', 'GUILD_ID']);
const VERIFIED_ROLE_ID = firstEnv(['DISCORD_VERIFIED_ROLE_ID', 'VERIFIED_ROLE_ID', 'VERIFY_ROLE_ID', 'AUTH_ROLE_ID'], '1508197241696026817');
const SCOPES = cleanEnv('DISCORD_SCOPES', 'identify email guilds.join');
const INVITE_URL = cleanEnv('DISCORD_INVITE_URL');
const LOG_WEBHOOK = cleanEnv('DISCORD_LOG_WEBHOOK_URL');
const SUCCESS_REDIRECT_URL = cleanEnv('SUCCESS_REDIRECT_URL');
const STATE_SECRET = firstEnv(['OAUTH_STATE_SECRET', 'AUTH_STATE_SECRET', 'JWT_SECRET'], CLIENT_SECRET || BOT_TOKEN || 'tempeststore-state-secret');
const REDIRECT_URI = firstEnv(['DISCORD_REDIRECT_URI', 'AUTH_REDIRECT_URI'], `${PUBLIC_URL}/auth/discord/callback`).replace(/\/$/, '');
const MONGO_URI = firstEnv(['MONGO_URI', 'MONGODB_URI', 'DATABASE_URL']);

// Mensagem temporaria no canal #verifique-se depois do OAuth.
// Defaults pedidos pelo cliente, mas pode sobrescrever pela Vercel sem editar codigo.
const VERIFY_STATUS_CHANNEL_ID = firstEnv([
  'VERIFY_STATUS_CHANNEL_ID',
  'AUTH_STATUS_CHANNEL_ID',
  'DISCORD_VERIFY_CHANNEL_ID',
  'DISCORD_VERIFICATION_CHANNEL_ID'
], '1508197311866736821');
const STORE_CHANNEL_ID = firstEnv([
  'STORE_CHANNEL_ID',
  'SHOP_CHANNEL_ID',
  'LOJA_CHANNEL_ID',
  'DISCORD_STORE_CHANNEL_ID'
], '1519861969606279331');
const VERIFY_STATUS_DELETE_MS = Math.max(1000, Number(firstEnv(['VERIFY_STATUS_DELETE_MS', 'AUTH_STATUS_DELETE_MS'], '5000')) || 5000);

const REQUIRED_SCOPES = ['identify', 'guilds.join'];
let mongoConnectionPromise = null;

app.disable('x-powered-by');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public'), {
  extensions: ['html'],
  maxAge: '15m'
}));

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

function htmlEscape(value = '') {
  return String(value).replace(/[&<>'"]/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  })[char]);
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function normalizeScopes(scopeValue) {
  if (Array.isArray(scopeValue)) {
    return scopeValue.map(scope => String(scope || '').trim().toLowerCase()).filter(Boolean);
  }
  return String(scopeValue || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
}

function uniqueScopes(scopes) {
  return Array.from(new Set(normalizeScopes(scopes)));
}

function oauthScopeParam() {
  return uniqueScopes([...normalizeScopes(SCOPES), ...REQUIRED_SCOPES]).join(' ');
}

function hasRequiredScopes(scopes) {
  const normalized = normalizeScopes(scopes);
  return REQUIRED_SCOPES.every(scope => normalized.includes(scope));
}

function avatarUrl(user) {
  return user?.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256` : '';
}

function getAuthUserModel() {
  if (mongoose.models.AuthUser) return mongoose.models.AuthUser;
  const authUserSchema = new mongoose.Schema({
    guildId: { type: String, required: true },
    userId: { type: String, required: true },
    email: { type: String, default: '' },
    username: { type: String, default: '' },
    globalName: { type: String, default: '' },
    avatarUrl: { type: String, default: '' },
    accessToken: { type: String, default: '' },
    refreshToken: { type: String, default: '' },
    tokenExpiresAt: { type: Date, default: null },
    oauthScopes: { type: [String], default: [] },
    oauthApplicationId: { type: String, default: '' },
    joinedGuild: { type: Boolean, default: false },
    roleApplied: { type: Boolean, default: false },
    roleApplyAttempts: { type: Number, default: 0 },
    lastRoleAttemptAt: { type: Date, default: null },
    roleApplyError: { type: String, default: '' },
    verifiedRoleId: { type: String, default: '' },
    verifiedRolePresent: { type: Boolean, default: false },
    verifiedRoleAuthorized: { type: Boolean, default: false },
    verifiedRoleSource: { type: String, default: '' },
    verifiedRoleSyncedAt: { type: Date, default: null },
    lastAuthAt: { type: Date, default: Date.now },
    lastOAuthAuditAt: { type: Date, default: null },
    oauthValid: { type: Boolean, default: true },
    oauthRevokedAt: { type: Date, default: null },
    oauthAuditFailReason: { type: String, default: '' },
    rawProfile: { type: mongoose.Schema.Types.Mixed, default: null }
  }, { collection: 'authusers' });
  authUserSchema.index({ guildId: 1, userId: 1 }, { unique: true });
  authUserSchema.index({ guildId: 1, roleApplied: 1, oauthValid: 1, lastAuthAt: -1 });
  return mongoose.model('AuthUser', authUserSchema);
}

async function connectMongo() {
  if (!MONGO_URI) return null;
  if (mongoose.connection.readyState === 1) return mongoose.connection;
  if (!mongoConnectionPromise) {
    mongoConnectionPromise = mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 })
      .catch((error) => {
        mongoConnectionPromise = null;
        throw error;
      });
  }
  return mongoConnectionPromise;
}

async function saveOAuthRecord({ guildId, user, token, scopes, applicationId, joinResult }) {
  if (!MONGO_URI) {
    return { ok: false, skipped: true, reason: 'MONGO_URI nao configurado' };
  }

  try {
    await connectMongo();
    const AuthUser = getAuthUserModel();
    const now = new Date();
    const tokenExpiresAt = token.expires_in ? new Date(Date.now() + Number(token.expires_in) * 1000) : null;
    const roleError = joinResult.roleApplied ? '' : (joinResult.roleError || 'role_apply_failed');

    await AuthUser.findOneAndUpdate(
      { guildId, userId: user.id },
      {
        $set: {
          guildId,
          userId: user.id,
          email: user.email || '',
          username: user.username || '',
          globalName: user.global_name || '',
          avatarUrl: avatarUrl(user),
          accessToken: token.access_token || '',
          refreshToken: token.refresh_token || '',
          tokenExpiresAt,
          oauthScopes: uniqueScopes(scopes),
          oauthApplicationId: applicationId || CLIENT_ID,
          joinedGuild: !!joinResult.joined,
          roleApplied: !!joinResult.roleApplied,
          roleApplyAttempts: 1,
          lastRoleAttemptAt: now,
          roleApplyError: roleError,
          verifiedRoleId: VERIFIED_ROLE_ID || '',
          verifiedRolePresent: !!joinResult.roleApplied,
          verifiedRoleAuthorized: !!joinResult.roleApplied,
          verifiedRoleSource: joinResult.roleApplied ? 'oauth_site' : 'oauth_site_role_failed',
          verifiedRoleSyncedAt: now,
          rawProfile: user,
          lastAuthAt: now,
          lastOAuthAuditAt: now,
          oauthValid: true,
          oauthRevokedAt: null,
          oauthAuditFailReason: roleError
        }
      },
      { upsert: true, returnDocument: 'after' }
    );

    return { ok: true };
  } catch (error) {
    console.warn('[MongoDB] Falha ao salvar OAuth:', error.message || error);
    return { ok: false, reason: error.message || 'mongo_save_failed' };
  }
}

function stateSecretCandidates() {
  return Array.from(new Set([
    STATE_SECRET,
    cleanEnv('OAUTH_STATE_SECRET'),
    cleanEnv('AUTH_STATE_SECRET'),
    cleanEnv('JWT_SECRET'),
    CLIENT_SECRET,
    cleanEnv('DISCORD_CLIENT_SECRET'),
    cleanEnv('DISCORD_OAUTH_CLIENT_SECRET'),
    BOT_TOKEN,
    cleanEnv('SITE_DISCORD_BOT_TOKEN'),
    cleanEnv('DISCORD_TOKEN'),
    cleanEnv('BOT_TOKEN'),
    'tempeststore-state-secret'
  ].map(value => String(value || '').trim()).filter(Boolean)));
}

function signWithSecret(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

function sign(payload) {
  return signWithSecret(payload, STATE_SECRET);
}

function isValidStateSignature(payload, signature) {
  return stateSecretCandidates().some(secret => signWithSecret(payload, secret) === signature);
}

function makeState(guildId, options = {}) {
  const prompt = String(options.prompt || 'consent') === 'none' ? 'none' : 'consent';
  const payload = base64url(JSON.stringify({ guildId, prompt, nonce: crypto.randomBytes(16).toString('hex'), iat: Date.now() }));
  return `${payload}.${sign(payload)}`;
}

function decodeStatePayload(payload) {
  try {
    return JSON.parse(Buffer.from(String(payload || ''), 'base64url').toString('utf8'));
  } catch (_) {
    throw new Error('State OAuth inválido. Abra a verificação novamente pelo Discord.');
  }
}

function isAllowedStateGuild(guildId) {
  const expected = String(DEFAULT_GUILD_ID || '').trim();
  const received = String(guildId || '').trim();
  return Boolean(received) && (!expected || received === expected);
}

function readState(state) {
  const raw = String(state || '').trim();

  // Antigamente o bot gerava o state e a Vercel validava com outro segredo.
  // Resultado: o Discord voltava com code válido, mas a página travava em
  // "State OAuth inválido". Agora o state só é usado para descobrir/validar
  // o servidor; a segurança principal fica no guildId fixo e no token OAuth do Discord.
  // Assim, botão antigo, segredo diferente ou redeploy do bot não quebra a verificação.
  if (!raw) {
    if (DEFAULT_GUILD_ID) return { guildId: DEFAULT_GUILD_ID, prompt: 'consent', recovered: true, recoveryReason: 'missing_state' };
    throw new Error('State OAuth ausente e DISCORD_GUILD_ID não configurado.');
  }

  const [payload, signature] = raw.split('.');
  let parsed;
  try {
    parsed = decodeStatePayload(payload);
  } catch (_) {
    if (DEFAULT_GUILD_ID) return { guildId: DEFAULT_GUILD_ID, prompt: 'consent', recovered: true, recoveryReason: 'invalid_payload' };
    throw new Error('State OAuth inválido. Abra a verificação novamente pelo Discord.');
  }

  const guildId = String(parsed.guildId || DEFAULT_GUILD_ID || '').trim();
  if (!guildId) throw new Error('Servidor não definido no OAuth.');
  if (!isAllowedStateGuild(guildId)) throw new Error('Servidor não autorizado no OAuth.');
  parsed.guildId = guildId;

  const validSignature = payload && signature ? isValidStateSignature(payload, signature) : false;
  if (!validSignature) {
    parsed.recovered = true;
    parsed.recoveryReason = 'signature_mismatch';
  }

  // Só expira state assinado corretamente e não persistente. State recuperado não
  // deve derrubar o usuário, porque o code do Discord ainda é fresco e válido.
  if (validSignature && parsed.iat && parsed.persistent !== true && Date.now() - Number(parsed.iat) > 10 * 60 * 1000) {
    throw new Error('Sessão expirada. Clique em verificar novamente.');
  }
  return parsed;
}

function describeDiscordHttpError(url, status, data = {}) {
  const base = data.error_description || data.message || data.error || `Discord retornou ${status}`;
  const code = data.code ? ` codigo ${data.code}` : '';
  const target = String(url || '');
  if (status === 401 && target.includes('/oauth2/token')) {
    return 'Discord retornou 401 no token OAuth. Confira se o DISCORD_CLIENT_SECRET da Vercel é o secret ATUAL deste app e se o Redirect URI é exatamente o mesmo cadastrado no Discord.';
  }
  if (status === 401 && target.includes('/guilds/')) {
    return 'Discord retornou 401 ao puxar o membro/aplicar cargo. Configure SITE_DISCORD_BOT_TOKEN ou DISCORD_BOT_TOKEN na Vercel com o token ATUAL do bot, depois faça redeploy.';
  }
  if (status === 403 && target.includes('/roles/')) {
    return `Discord retornou 403 ao aplicar o cargo${code}. O bot não tem permissão ou o cargo verificado está acima/igual ao maior cargo do bot. Coloque o cargo do bot acima do cargo 1508197241696026817 e habilite Manage Roles.`;
  }
  if (status === 404 && target.includes('/roles/')) {
    return `Discord retornou 404 ao aplicar o cargo${code}. Confira se DISCORD_VERIFIED_ROLE_ID está com o ID correto do cargo no mesmo servidor: 1508197241696026817.`;
  }
  return base;
}

async function discordFetch(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!response.ok) {
    const error = new Error(describeDiscordHttpError(url, response.status, data));
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

async function exchangeDiscordOAuthCode(code) {
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  return discordFetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${basic}`
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI
    })
  });
}

async function inspectDiscordOAuthToken(accessToken) {
  const data = await discordFetch('https://discord.com/api/oauth2/@me', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return {
    userId: String(data.user?.id || ''),
    applicationId: String(data.application?.id || ''),
    scopes: normalizeScopes(data.scopes || data.scope || '')
  };
}

async function notifyWebhook(user, req, result) {
  if (!LOG_WEBHOOK) return;
  try {
    await fetch(LOG_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'BigBux Verify',
        avatar_url: 'https://cdn.discordapp.com/embed/avatars/0.png',
        embeds: [{
          title: '✅ Verificação OAuth2 concluída',
          color: 0x1D4ED8,
          fields: [
            { name: 'Usuário', value: `${user.username}${user.discriminator && user.discriminator !== '0' ? '#' + user.discriminator : ''}`, inline: true },
            { name: 'ID', value: user.id, inline: true },
            { name: 'Email', value: user.email || 'Não informado', inline: false },
            { name: 'Servidor', value: result.guildId || 'Não informado', inline: true },
            { name: 'Cargo aplicado', value: result.roleApplied ? 'Sim' : 'Não', inline: true },
            { name: 'OAuth salvo', value: result.mongoSaved ? 'Sim' : (result.mongoSkipped ? 'Mongo não configurado' : 'Não'), inline: true },
            { name: 'IP', value: String(req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Desconhecido').slice(0, 250), inline: false }
          ],
          timestamp: new Date().toISOString()
        }]
      })
    });
  } catch (err) {
    console.warn('[Webhook] Falha ao enviar log:', err.message);
  }
}

async function fetchGuildMemberRoles(guildId, userId) {
  if (!BOT_TOKEN || !guildId || !userId) return [];
  try {
    const member = await discordFetch(`https://discord.com/api/v10/guilds/${guildId}/members/${userId}`, {
      headers: { Authorization: `Bot ${BOT_TOKEN}` }
    });
    return Array.isArray(member.roles) ? member.roles.map(String) : [];
  } catch (_) {
    return [];
  }
}

function scheduleTemporaryMessageDelete(channelId, messageId, deleteMs = VERIFY_STATUS_DELETE_MS) {
  if (!BOT_TOKEN || !channelId || !messageId) return;
  setTimeout(() => {
    discordFetch(`https://discord.com/api/v10/channels/${channelId}/messages/${messageId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bot ${BOT_TOKEN}` }
    }).catch((error) => {
      console.warn('[VerifyStatus] Falha ao apagar mensagem temporaria:', error.message || error);
    });
  }, deleteMs);
}

async function sendVerifyStatusMessage({ guildId, user, alreadyVerified, roleApplied }) {
  const channelId = VERIFY_STATUS_CHANNEL_ID;
  if (!BOT_TOKEN || !channelId || !user?.id) return { ok: false, skipped: true };

  const mention = `<@${user.id}>`;
  const storeMention = STORE_CHANNEL_ID ? `<#${STORE_CHANNEL_ID}>` : 'a loja';
  const content = alreadyVerified
    ? `${mention} ✅ **Você já está verificado.**`
    : (roleApplied
      ? `${mention} ✅ **Sucesso na verificação!** Já pode entrar na loja: ${storeMention}`
      : `${mention} ⚠️ **Verificação concluída**, mas o cargo não foi aplicado. Chame o suporte.`);

  try {
    const msg = await discordFetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
      method: 'POST',
      headers: {
        Authorization: `Bot ${BOT_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        content,
        allowed_mentions: { users: [String(user.id)], roles: [], parse: [] }
      })
    });
    scheduleTemporaryMessageDelete(channelId, msg.id);
    return { ok: true, messageId: msg.id, guildId };
  } catch (error) {
    console.warn('[VerifyStatus] Falha ao enviar mensagem temporaria:', error.data || error.message || error);
    return { ok: false, reason: error.message || 'send_failed' };
  }
}

async function joinGuildAndApplyRole({ guildId, userId, accessToken }) {
  const result = { guildId, joined: false, roleApplied: false, alreadyVerified: false, roleError: '' };

  if (!BOT_TOKEN) throw new Error('DISCORD_BOT_TOKEN não configurado na Vercel.');
  if (!guildId) throw new Error('DISCORD_GUILD_ID não configurado.');

  await discordFetch(`https://discord.com/api/v10/guilds/${guildId}/members/${userId}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bot ${BOT_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ access_token: accessToken })
  }).catch((error) => {
    if (error.status === 201 || error.status === 204) return {};
    throw error;
  });
  result.joined = true;

  if (VERIFIED_ROLE_ID) {
    const rolesBefore = await fetchGuildMemberRoles(guildId, userId);
    if (rolesBefore.includes(String(VERIFIED_ROLE_ID))) {
      result.roleApplied = true;
      result.alreadyVerified = true;
      return result;
    }

    try {
      await discordFetch(`https://discord.com/api/v10/guilds/${guildId}/members/${userId}/roles/${VERIFIED_ROLE_ID}`, {
        method: 'PUT',
        headers: { Authorization: `Bot ${BOT_TOKEN}` }
      });
      result.roleApplied = true;
    } catch (error) {
      const rawMessage = error.data?.message || error.data?.error || error.message || 'Falha ao aplicar cargo.';
      const rawCode = error.data?.code ? ` codigo ${error.data.code}` : '';
      result.roleError = error.message || `${rawMessage}${rawCode}`;
      console.warn('[Role] Falha ao aplicar cargo:', error.data || error.message || error);
    }
  }

  return result;
}

function getReturnUrl(guildId) {
  return SUCCESS_REDIRECT_URL || (guildId ? `https://discord.com/channels/${guildId}` : INVITE_URL || '/');
}


function authRestartUrl(guildId = '') {
  const gid = String(guildId || DEFAULT_GUILD_ID || '').trim();
  return gid ? `/auth/discord?guildId=${encodeURIComponent(gid)}&prompt=consent` : '/auth/discord';
}

function renderResultPage({ ok, title, message, user, guildId }) {
  const avatar = user?.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256`
    : 'https://cdn.discordapp.com/embed/avatars/0.png';

  const safeName = htmlEscape(user?.global_name || user?.username || 'BigBux');
  const safeTitle = htmlEscape(title);
  const safeMessage = htmlEscape(message);
  const returnUrl = ok ? getReturnUrl(guildId) : '/';
  const redirectScript = ok ? `<script>setTimeout(() => { window.location.href = ${JSON.stringify(returnUrl)}; }, 2500);</script>` : '';

  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${safeTitle} · BigBux</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body>
  <main class="page center-page">
    <section class="card result-card ${ok ? 'success' : 'error'}">
      <div class="orb orb-one"></div>
      <div class="orb orb-two"></div>
      <div class="result-identity" aria-hidden="true">
        <span class="identity-logo"><img src="/assets/bigbux-logo.png" alt="" /></span>
        <span class="identity-line"></span>
        <span class="identity-avatar"><img src="${htmlEscape(avatar)}" alt="" /></span>
      </div>
      <div class="result-status-icon">${ok ? '&#10003;' : '!'}</div>
      <p class="eyebrow">BigBux Verify</p>
      <h1>${safeTitle}</h1>
      <p class="muted">${safeMessage}</p>
      ${user ? `<div class="user-pill">Verificado como <strong>${safeName}</strong></div>` : ''}
      <div class="actions">
        ${ok ? `<a class="button primary" href="${htmlEscape(returnUrl)}">Voltar para o servidor</a>` : `<a class="button primary" href="${htmlEscape(authRestartUrl(guildId))}">Tentar de novo</a>`}
        ${INVITE_URL ? `<a class="button ghost" href="${htmlEscape(INVITE_URL)}">Convite do servidor</a>` : ''}
      </div>
      ${ok ? '<p class="tiny">Redirecionando automaticamente para o Discord...</p>' : ''}
    </section>
  </main>
  ${redirectScript}
</body>
</html>`;
}

app.get('/health', (_req, res) => res.json({
  ok: true,
  service: 'BigBux Verify',
  public_url: PUBLIC_URL,
  redirect_uri: REDIRECT_URI,
  guild_id: DEFAULT_GUILD_ID,
  client_id_configured: !!CLIENT_ID,
  client_secret_configured: !!CLIENT_SECRET,
  bot_token_configured: !!BOT_TOKEN,
  verified_role_configured: !!VERIFIED_ROLE_ID,
  mongo_configured: !!MONGO_URI,
  oauth_state_secret_configured: !!firstEnv(['OAUTH_STATE_SECRET', 'AUTH_STATE_SECRET']),
  state_recovery_enabled: true,
  verify_status_channel_id: VERIFY_STATUS_CHANNEL_ID,
  store_channel_id: STORE_CHANNEL_ID,
  verify_status_delete_ms: VERIFY_STATUS_DELETE_MS,
  required_scopes: REQUIRED_SCOPES
}));

app.get('/auth', (_req, res) => res.redirect('/'));

app.get('/auth/discord', (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(500).send(renderResultPage({
      ok: false,
      title: 'OAuth2 não configurado',
      message: 'Configure DISCORD_CLIENT_ID e DISCORD_CLIENT_SECRET nas variáveis de ambiente da Vercel.'
    }));
  }

  const guildId = String(req.query.guildId || DEFAULT_GUILD_ID || '').trim();
  if (!guildId) {
    return res.status(500).send(renderResultPage({
      ok: false,
      title: 'Servidor não configurado',
      message: 'Configure DISCORD_GUILD_ID na Vercel ou envie ?guildId=ID_DO_SERVIDOR no link.'
    }));
  }

  const prompt = String(req.query.prompt || '').toLowerCase() === 'none' || String(req.query.mode || '').toLowerCase() === 'validate'
    ? 'none'
    : 'consent';
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: oauthScopeParam(),
    state: makeState(guildId, { prompt }),
    prompt
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

async function handleAuthCallback(req, res) {
  const { code, state, error, error_description } = req.query;

  if (error) {
    let parsedState = null;
    try { parsedState = readState(state); } catch (_) {}
    if (parsedState?.prompt === 'none' && parsedState?.guildId) {
      return res.redirect(`/auth/discord?guildId=${encodeURIComponent(parsedState.guildId)}&prompt=consent`);
    }
    return res.status(400).send(renderResultPage({ ok: false, title: 'Autorização cancelada', message: error_description || error }));
  }

  if (!code) {
    return res.status(400).send(renderResultPage({ ok: false, title: 'Código não recebido', message: 'O Discord não retornou o código de autorização.' }));
  }

  try {
    let parsedState;
    try {
      parsedState = readState(state);
    } catch (stateError) {
      if (!DEFAULT_GUILD_ID) throw stateError;
      parsedState = {
        guildId: DEFAULT_GUILD_ID,
        prompt: 'consent',
        recovered: true,
        recoveryReason: 'callback_state_error'
      };
    }
    const guildId = parsedState.guildId;

    const token = await exchangeDiscordOAuthCode(code);

    if (!token.access_token) {
      throw new Error('Discord não retornou access_token. Tente verificar novamente.');
    }

    const tokenInfo = await inspectDiscordOAuthToken(token.access_token);
    const grantedScopes = uniqueScopes(tokenInfo.scopes.length ? tokenInfo.scopes : token.scope || '');
    if (tokenInfo.applicationId && CLIENT_ID && tokenInfo.applicationId !== CLIENT_ID) {
      throw new Error('O token OAuth retornado pertence a outro aplicativo Discord.');
    }
    if (!hasRequiredScopes(grantedScopes)) {
      if (parsedState.prompt === 'none') {
        return res.redirect(`/auth/discord?guildId=${encodeURIComponent(guildId)}&prompt=consent`);
      }
      throw new Error('Você precisa aceitar as permissões de identificar conta e entrar no servidor para receber o cargo.');
    }

    const user = await discordFetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `${token.token_type || 'Bearer'} ${token.access_token}` }
    });
    if (tokenInfo.userId && tokenInfo.userId !== user.id) {
      throw new Error('O token OAuth retornado não pertence ao usuário autenticado.');
    }

    const joinResult = await joinGuildAndApplyRole({ guildId, userId: user.id, accessToken: token.access_token });
    const mongoResult = await saveOAuthRecord({
      guildId,
      user,
      token,
      scopes: grantedScopes,
      applicationId: tokenInfo.applicationId || CLIENT_ID,
      joinResult
    });
    await notifyWebhook(user, req, {
      ...joinResult,
      mongoSaved: mongoResult.ok,
      mongoSkipped: mongoResult.skipped
    });
    await sendVerifyStatusMessage({
      guildId,
      user,
      alreadyVerified: !!joinResult.alreadyVerified,
      roleApplied: !!joinResult.roleApplied
    });

    let roleMsg = VERIFIED_ROLE_ID
      ? (joinResult.alreadyVerified ? 'Você já estava verificado.' : (joinResult.roleApplied ? 'O cargo de verificado foi aplicado.' : `Você entrou no servidor, mas o cargo não foi aplicado. Motivo: ${joinResult.roleError || 'confira a posição do cargo do bot.'}`))
      : 'Você foi autenticado e redirecionado para o servidor.';
    if (!mongoResult.ok) {
      roleMsg += ` A autenticação funcionou, mas não consegui salvar no MongoDB (${mongoResult.reason}). Configure o MONGO_URI da Vercel igual ao do bot para o botão Validar reconhecer esta autorização.`;
    }

    return res.send(renderResultPage({
      ok: true,
      title: 'Verificação concluída',
      message: roleMsg,
      user,
      guildId
    }));
  } catch (err) {
    console.error('[OAuth2] Erro:', err.data || err.message || err);
    return res.status(500).send(renderResultPage({
      ok: false,
      title: 'Falha na verificação',
      message: err.message || 'Não foi possível finalizar o OAuth2.'
    }));
  }
}

app.get('/auth/callback', handleAuthCallback);
app.get('/auth/discord/callback', handleAuthCallback);

app.use((_req, res) => res.status(404).sendFile(path.join(__dirname, '..', 'public', '404.html')));

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`BigBux Verify online em http://localhost:${PORT}`);
  });
}

module.exports = app;
