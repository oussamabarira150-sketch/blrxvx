const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 13480;
const LOG_FILE = 'virtus_log.json';
const HWID_DB = 'hwids.json';

// ==================== VIRTUS PROTOCOL ====================
// المفتاح الحقيقي الذي يستخدمه العميل لفك الروابط المشفرة
// encryption = Base64(XOR(url, KEY))
// مؤكد من ذاكرة اللودر الحية: KEY = "VIRTUS_HANDSHAKE" + nonce الطلب (ديناميكي per-request)
const VIRTUS_URL_KEY = 'VIRTUS_HANDSHAKE';
// مفتاح المكوّن الثاني (payload) — ثابت في ردود الخادم الحقيقي
const VIRTUS_PAYLOAD_KEY = 'VIRTUS_SECURE_@2026_KEY_PRO';

const VIRTUS_OFFSETS = {
  Initbase: '0xAAA5B20', Access: '0x5C', m_Match: '0x50', LocalPlayer: '0x94',
  DictionaryEntities: '0x68', Avatar: '0xA8', AvatarManager: '0x4C8',
  Avatar_Data: '0x14', Avatar_Data_IsTeam: '0x59', Avatar_IsVisible: '0x95',
  Xpose: '0x78', Player_Name: '0x2E8', Player_IsDead: '0x50', Player_Data: '0x48',
  Player_ShadowBase: '0x18C8', PlayerID: '0x8', MainCameraTransform: '0x250',
  FollowCamera: '0x458', Camera: '0x18', View_Matrix: '0xE8',
  Player_Head: '0x460', Player_Hip: '0x464', Player_Spine: '0x468', Player_Root: '0x474',
  Player_LeftAnkle: '0x47C', Player_RightAnkle: '0x480', Player_LeftToe: '0x484',
  Player_RightToe: '0x488', Player_LeftShoulder: '0x494', Player_RightShoulder: '0x498',
  Player_RightWrist: '0x49C', Player_LeftWrist: '0x4A0', Player_RightForeArm: '0x4A4',
  Player_LeftForeArm: '0x4A8', BaseProfileInfo: '0x18DC', Nickname: '0x18', Level: '0x14',
  AimRotation: '0x408', Weapon: '0x3FC', WeaponData: '0x58', WeaponRecoil: '0xC',
  SimulationTimer: '0x10', FixedDeltaTime: '0x24', RunSpeedUpScale: '0x270',
  FallingSpeedUpScale: '0x26C', TransformOffset: '0x8', GameObjectFromTransform: '0x8',
  MatrixFromGameObject: '0x20', MatrixRotationOffset: '0x70', MatrixPositionOffset: '0x60',
  InfinityAmmo: '0xE0', LocalPlayerAttributes: '0x4C4', NoReloadPtr: '0x99',
  AimbotVisible: '0x4AC'
};

function protocolEncrypt(plain, nonce) {
  // المفتاح الديناميكي: "VIRTUS_HANDSHAKE" + nonce المرسل من العميل في الطلب
  const key = Buffer.from(VIRTUS_URL_KEY + (nonce || ''), 'ascii');
  const bytes = Buffer.from(plain, 'utf8');
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length];
  return out.toString('base64');
}

function baseUrl(req) {
  return `http://${req.headers.host}`;
}

// Inicializa arquivos
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, '[]');
if (!fs.existsSync(HWID_DB)) fs.writeFileSync(HWID_DB, '{}');

function loadHWIDs() {
  try { return JSON.parse(fs.readFileSync(HWID_DB, 'utf8')); }
  catch { return {}; }
}

function saveHWIDs(db) {
  fs.writeFileSync(HWID_DB, JSON.stringify(db, null, 2));
}

const sessions = new Map();

const server = http.createServer((req, res) => {
  const timestamp = new Date().toISOString();
  const { method, url, headers } = req;
  let body = '';

  req.on('data', chunk => { body += chunk.toString(); });

  req.on('end', () => {
    const parsed = tryParseJSON(body);

    // Log
    console.log('\n' + '='.repeat(60));
    console.log(`[${timestamp}] ${method} ${url}`);
    console.log(`  UA: ${headers['user-agent'] || 'none'}`);
    if (body) console.log(`  Body: ${body.substring(0, 200)}`);

    // Salvar log
    saveLog({ timestamp, method, url, headers, body: parsed, ip: req.socket.remoteAddress });

    // Roteamento
    let response;
    switch (url) {
      case '/api/update':
        response = handleUpdate(headers, parsed);
        break;
      case '/api/auth':
        response = handleAuth(headers, parsed);
        break;
      case '/api/heartbeat':
        response = handleHeartbeat(headers, parsed);
        break;
      case '/api/handshake':
        response = handleHandshake(headers, parsed);
        break;
      case '/api/config':
        response = handleConfig(headers, parsed);
        break;
      case '/api/inject':
        response = handleInject(headers, parsed);
        break;
      case '/api/bypass':
        if (method === 'GET') return serveBypass(res);
        response = handleInject(headers, parsed);
        break;
      case '/bypass.so':
        return serveBypass(res);
      case '/api/avatar':
        return serveAvatar(res);
      case '/api/hwid/status':
        response = handleHwidStatus(parsed);
        break;
      case '/api/hwid/register':
        response = handleHwidRegister(parsed);
        break;
      case '/api/hwid/reset':
        response = handleHwidReset(parsed);
        break;
      default:
        // Servir arquivos de /files/*
        if (url.startsWith('/files/')) {
          return serveFile(url, res);
        }
        response = { status: 'ok', endpoint: url };
        break;
    }

    console.log(`  Response: ${JSON.stringify(response).substring(0, 120)}...`);
    console.log('='.repeat(60));

    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify(response));
  });
});

// ==================== HANDLERS ====================

function handleUpdate(headers, body) {
  return {
    status: 'ok',
    code: 1,
    update_available: false,
    current_version: 'v16.0.0-S',
    latest_version: 'v16.0.0-S',
    message: 'You are up to date'
  };
}

function handleAuth(headers, body) {
  if (!body) return { status: 'error', message: 'missing body' };

  const hwid = body.hwid;
  const db = loadHWIDs();

  // Registra/atualiza HWID
  if (!db[hwid]) {
    db[hwid] = {
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      version: body.version,
      package: body.package,
      auth_count: 1,
      status: 'active',
      label: '',
      sessions: []
    };
    console.log(`  [+] NOVO HWID: ${hwid}`);
  } else {
    db[hwid].last_seen = new Date().toISOString();
    db[hwid].auth_count++;
    db[hwid].version = body.version;
  }

  // Verifica ban
  if (db[hwid].status === 'banned') {
    saveHWIDs(db);
    console.log(`  [X] HWID BANIDO: ${hwid}`);
    return { status: 'error', authenticated: false, reason: 'hwid_banned' };
  }

  // Gera sessão
  const sessionId = crypto.randomBytes(16).toString('hex');
  const sessionKey = crypto.randomBytes(16).toString('hex');
  const launchTicket = crypto.randomBytes(32).toString('hex');
  const nextNonce = crypto.randomBytes(8).toString('hex');
  const sig = crypto.createHash('sha256').update(sessionId + hwid + body.nonce).digest('hex');

  sessions.set(sessionId, { hwid, created: Date.now() });
  db[hwid].sessions.push(sessionId);
  if (db[hwid].sessions.length > 10) db[hwid].sessions = db[hwid].sessions.slice(-10);
  saveHWIDs(db);

  // ====== رد مطابق حرفياً لبروتوكول VIRTUS الحقيقي ======
  // client decrypt: urls = Base64Decode( XOR( cipher, "VIRTUS_HANDSHAKE" + nonce ) )
  const base = baseUrl(req);
  const encKey = body.nonce; // مفتاح ديناميكي per-request
  const urls = {
    url_inject: protocolEncrypt(`${base}/files/libinject`, encKey),
    url_virtus: protocolEncrypt(`${base}/files/libLibVirtus.so`, encKey),
    url_bypass: protocolEncrypt(`${base}/files/bypass.so`, encKey)
  };

  return {
    status: 'approved',
    discord_user: 'osama',
    discord_avatar: 'https://cdn.discordapp.com/embed/avatars/5.png',
    expires_at: String(Date.now() + 30 * 86400000),
    code: 1,
    session_id: sessionId,
    session_key: sessionKey,
    launch_ticket: launchTicket,
    next_nonce: nextNonce,
    payload: VIRTUS_PAYLOAD_KEY,
    ...urls,
    ...VIRTUS_OFFSETS,
    // حقول إضافية متوافقة مع إصدارات الخادم القديمة (يتم تجاهلها من العميل)
    token: sessionKey,
    sig: sig,
    authenticated: true,
    init: true,
    hwid: hwid,
    nonce: body.nonce,
    server_ts: Math.floor(Date.now() / 1000),
    version: body.version,
    package: body.package,
    config: {
      heartbeat_interval: 30,
      trap_enabled: false,
      detection_level: 0,
      report_detections: false,
      bypass: true
    }
  };
}

function handleHeartbeat(headers, body) {
  if (!body) return { status: 'ok', ack: true };

  const hwid = body.hwid;
  const db = loadHWIDs();

  if (db[hwid]) {
    db[hwid].last_seen = new Date().toISOString();
    saveHWIDs(db);
  }

  if (body.trap_triggered || body.reason) {
    console.log(`  [!] DETECÇÃO: ${body.reason} (HWID: ${hwid})`);
  }

  if (db[hwid] && db[hwid].status === 'banned') {
    return { status: 'ok', ack: true, action: 'ban', ban: true, kick: true };
  }

  return {
    status: 'ok',
    ack: true,
    action: 'none',
    ban: false,
    kick: false,
    warn: false,
    next_heartbeat: 30,
    server_ts: Math.floor(Date.now() / 1000)
  };
}

function handleHandshake(headers, body) {
  return {
    status: 'ok',
    session: 'accepted',
    session_id: crypto.randomBytes(16).toString('hex'),
    protocol_version: 2,
    server_ts: Math.floor(Date.now() / 1000),
    features: { trap_enabled: false, detection_reporting: false, auto_update: false }
  };
}

function handleConfig(headers, body) {
  return {
    status: 'ok',
    config: {
      trap_enabled: false,
      detection_level: 0,
      blacklist_windows: [],
      blacklist_processes: [],
      report_detections: false,
      auto_ban: false,
      heartbeat_interval: 60,
      update_check_interval: 3600
    }
  };
}

function handleInject(headers, body) {
  console.log('  [INJECT] Requisição de injeção');
  return { status: 'expired', inject: true, bypass: true, message: 'authorized' };
}

// ==================== FILE SERVING ====================

function serveAvatar(res) {
  return serveFile('/files/avatar.png', res);
}

function serveBypass(res) {
  return serveFile('/files/bypass.so', res);
}

function serveFile(url, res) {
  const filename = url.replace('/files/', '');
  const filePath = path.join(__dirname, 'files', filename);
  
  console.log(`  [FILE] Requisição: ${filename}`);

  if (fs.existsSync(filePath)) {
    const file = fs.readFileSync(filePath);
    const ext = path.extname(filename).toLowerCase();
    const contentTypes = {
      '.so': 'application/octet-stream',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.json': 'application/json'
    };
    res.writeHead(200, {
      'Content-Type': contentTypes[ext] || 'application/octet-stream',
      'Content-Length': file.length,
      'Cache-Control': 'no-cache'
    });
    res.end(file);
    console.log(`  [FILE] Servido: ${filename} (${file.length} bytes)`);
  } else {
    console.log(`  [FILE] NÃO ENCONTRADO: ${filename} (coloque em ./files/${filename})`);
    // Retorna placeholder pra não travar
    if (filename.endsWith('.png')) {
      const png = Buffer.from(
        '89504e470d0a1a0a0000000d49484452000000010000000108020000009001' +
        '2e00000000c4944415478016360f8cf00000001010000187218e600000000' +
        '0049454e44ae426082', 'hex'
      );
      res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': png.length });
      res.end(png);
    } else if (filename.endsWith('.so')) {
      // ELF placeholder mínimo
      const elf = Buffer.alloc(128, 0);
      elf[0] = 0x7F; elf[1] = 0x45; elf[2] = 0x4C; elf[3] = 0x46;
      elf[4] = 0x02; elf[5] = 0x01; elf[6] = 0x01;
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': elf.length });
      res.end(elf);
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'error', message: 'file not found' }));
    }
  }
}

// ==================== HWID MANAGEMENT ====================

function handleHwidStatus(body) {
  const db = loadHWIDs();
  if (body && body.hwid) {
    if (!db[body.hwid]) return { status: 'error', message: 'HWID not found' };
    return { status: 'ok', hwid: body.hwid, data: db[body.hwid] };
  }
  const summary = Object.entries(db).map(([hwid, data]) => ({
    hwid, status: data.status, label: data.label, auth_count: data.auth_count,
    first_seen: data.first_seen, last_seen: data.last_seen
  }));
  return { status: 'ok', total: summary.length, hwids: summary };
}

function handleHwidRegister(body) {
  if (!body || !body.hwid) return { status: 'error', message: 'hwid required' };
  const db = loadHWIDs();
  if (!db[body.hwid]) {
    db[body.hwid] = {
      first_seen: new Date().toISOString(), last_seen: new Date().toISOString(),
      version: 'manual', package: 'manual', auth_count: 0,
      status: body.status || 'active', label: body.label || '', sessions: []
    };
  } else {
    if (body.status) db[body.hwid].status = body.status;
    if (body.label) db[body.hwid].label = body.label;
  }
  saveHWIDs(db);
  console.log(`  [HWID] ${body.hwid} → ${db[body.hwid].status}`);
  return { status: 'ok', hwid: body.hwid, data: db[body.hwid] };
}

function handleHwidReset(body) {
  if (!body || !body.hwid) return { status: 'error', message: 'hwid required' };
  const db = loadHWIDs();
  if (!db[body.hwid]) return { status: 'error', message: 'HWID not found' };
  db[body.hwid].status = 'active';
  db[body.hwid].auth_count = 0;
  db[body.hwid].sessions = [];
  saveHWIDs(db);
  return { status: 'ok', hwid: body.hwid, message: 'reset to active' };
}

// ==================== UTILS ====================

function saveLog(entry) {
  try {
    const logs = JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
    logs.push(entry);
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
  } catch (e) {}
}

function tryParseJSON(str) {
  try { return JSON.parse(str); } catch { return null; }
}

// ==================== START ====================

server.listen(PORT, '0.0.0.0', () => {
  const db = loadHWIDs();
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║       VIRTUS Server v3.0                    ║');
  console.log(`║       Porta: ${PORT}                         ║`);
  console.log(`║       HWIDs: ${Object.keys(db).length}                              ║`);
  console.log('╚══════════════════════════════════════════════╝');
  console.log('\n  Rotas client:');
  console.log('    GET  /api/update     → Sem update');
  console.log('    POST /api/auth       → Autentica (approved + lifetime)');
  console.log('    POST /api/heartbeat  → Aceita pulsos');
  console.log('    GET  /api/bypass     → Serve bypass.so');
  console.log('    GET  /api/avatar     → Serve avatar.png');
  console.log('\n  Gerenciamento:');
  console.log('    POST /api/hwid/status   → Listar HWIDs');
  console.log('    POST /api/hwid/register → Registrar/banir');
  console.log('    POST /api/hwid/reset    → Desbanir');
  console.log('\n  Aguardando conexões...\n');
});

