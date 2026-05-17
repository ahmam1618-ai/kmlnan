const http = require('http');
const https = require('https');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

// Database setup
const db = new sqlite3.Database('./kammelna.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    email TEXT,
    display_name TEXT,
    bio TEXT,
    avatar_url TEXT,
    rank INTEGER DEFAULT 0,
    points INTEGER DEFAULT 0,
    coins INTEGER DEFAULT 1000,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS achievements (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    achievement_id TEXT,
    progress INTEGER DEFAULT 0,
    completed INTEGER DEFAULT 0,
    completed_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS auth_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT,
    expires_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS game_servers (
    id TEXT PRIMARY KEY,
    name TEXT,
    host TEXT,
    port INTEGER,
    zone TEXT,
    game_type TEXT,
    players_count INTEGER DEFAULT 0,
    max_players INTEGER DEFAULT 100,
    status TEXT DEFAULT 'active'
  )`);

  // Default game servers
  db.run(`INSERT OR IGNORE INTO game_servers (id, name, host, port, zone, game_type) VALUES 
    ('srv-1', 'Baloot Server 1', '20.216.1.188', 8443, 'KammelnaZone', 'baloot'),
    ('srv-2', 'Tarneeb Server 1', '20.216.1.188', 9933, 'KammelnaZone', 'tarneeb'),
    ('srv-3', 'Jackaroo Server 1', '20.216.1.188', 8443, 'KammelnaZone', 'jackaroo')
  `);

  console.log('Database ready ✅');
});

// Helper functions
const generateId = () => crypto.randomBytes(16).toString('hex');
const generateToken = () => crypto.randomBytes(32).toString('hex');
const hashPassword = (pass) => crypto.createHash('sha256').update(pass).digest('hex');

const json = (res, status, data) => {
  res.writeHead(status, { 
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
};

const success = (res, data) => json(res, 200, { success: true, ...data });
const error = (res, msg, code = 400) => json(res, code, { success: false, error: { message: msg } });

// Auth middleware
const authenticate = (req, cb) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return cb(null, null);
  
  db.get('SELECT * FROM auth_tokens WHERE token = ? AND expires_at > datetime("now")', [token], (err, row) => {
    if (err || !row) return cb(null, null);
    db.get('SELECT * FROM users WHERE id = ?', [row.user_id], (err, user) => {
      cb(null, user);
    });
  });
};

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    let parsed = {};
    try { parsed = JSON.parse(body); } catch(e) {}

    const url = req.url.split('?')[0];
    const query = {};
    req.url.split('?')[1]?.split('&').forEach(p => {
      const [k, v] = p.split('=');
      if (k) query[k] = v;
    });

    console.log(req.method, url);

    // ===== AUTHENTICATION =====

    // Sign Up
    if (url === '/v1/authentication/usernamepassword/sign-up' && req.method === 'POST') {
      const { username, password, email } = parsed;
      if (!username || !password) return error(res, 'Username and password required');

      const id = generateId();
      const token = generateToken();
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

      db.run('INSERT INTO users (id, username, password_hash, email, display_name) VALUES (?, ?, ?, ?, ?)',
        [id, username, hashPassword(password), email, username], (err) => {
          if (err) return error(res, 'Username already taken');
          db.run('INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
            [token, id, expires], () => {
              success(res, {
                id,
                token,
                expiresAt: expires,
                userId: id
              });
            });
        });
    }

    // Sign In
    else if (url === '/v1/authentication/usernamepassword/sign-in' && req.method === 'POST') {
      const { username, password } = parsed;
      if (!username || !password) return error(res, 'Username and password required');

      db.get('SELECT * FROM users WHERE username = ? AND password_hash = ?',
        [username, hashPassword(password)], (err, user) => {
          if (!user) return error(res, 'Invalid credentials', 401);

          const token = generateToken();
          const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

          db.run('INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
            [token, user.id, expires], () => {
              db.run('UPDATE users SET last_login = datetime("now") WHERE id = ?', [user.id]);
              success(res, {
                id: token,
                token,
                expiresAt: expires,
                userId: user.id
              });
            });
        });
    }

    // Anonymous Sign In
    else if (url === '/v1/authentication/anonymous' && req.method === 'POST') {
      const id = generateId();
      const username = 'guest_' + id.substring(0, 8);
      const token = generateToken();
      const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

      db.run('INSERT INTO users (id, username, display_name) VALUES (?, ?, ?)',
        [id, username, 'ضيف'], () => {
          db.run('INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
            [token, id, expires], () => {
              success(res, { id: token, token, expiresAt: expires, userId: id });
            });
        });
    }

    // Session Token Refresh
    else if (url === '/v1/authentication/session-token' && req.method === 'POST') {
      authenticate(req, (err, user) => {
        if (!user) return error(res, 'Unauthorized', 401);
        const token = generateToken();
        const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
        db.run('INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
          [token, user.id, expires], () => {
            success(res, { id: token, token, expiresAt: expires, userId: user.id });
          });
      });
    }

    // ===== USERS =====

    // Get User
    else if (url.match(/^\/v1\/users\/[^/]+$/) && req.method === 'GET') {
      const playerId = url.split('/')[3];
      authenticate(req, (err, authUser) => {
        db.get('SELECT * FROM users WHERE id = ?', [playerId], (err, user) => {
          if (!user) return error(res, 'User not found', 404);
          success(res, {
            id: user.id,
            username: user.username,
            displayName: user.display_name || user.username,
            bio: user.bio || '',
            avatarUrl: user.avatar_url || null,
            rank: user.rank,
            points: user.points,
            coins: user.coins,
            status: user.status,
            createdAt: user.created_at
          });
        });
      });
    }

    // Update User
    else if (url.match(/^\/v1\/users\/[^/]+$/) && req.method === 'PUT') {
      authenticate(req, (err, user) => {
        if (!user) return error(res, 'Unauthorized', 401);
        const { displayName, bio } = parsed;
        db.run('UPDATE users SET display_name = ?, bio = ? WHERE id = ?',
          [displayName || user.display_name, bio || user.bio, user.id], () => {
            success(res, { updated: true });
          });
      });
    }

    // Get User Notifications WebSocket
    else if (url.match(/^\/v1\/users\/[^/]+\/notifications\/websocket/) && req.method === 'GET') {
      authenticate(req, (err, user) => {
        if (!user) return error(res, 'Unauthorized', 401);
        success(res, { 
          url: `ws://localhost:${PORT}/ws/notifications`,
          token: generateToken()
        });
      });
    }

    // ===== GAME SERVERS =====

    else if (url === '/api/Servers/LoadServers' || url.includes('LoadServers')) {
      db.all('SELECT * FROM game_servers WHERE status = "active"', [], (err, servers) => {
        success(res, {
          servers: servers.map(s => ({
            id: s.id,
            name: s.name,
            host: s.host,
            port: s.port,
            zone: s.zone,
            gameType: s.game_type,
            playersCount: s.players_count,
            maxPlayers: s.max_players
          }))
        });
      });
    }

    // ===== ACHIEVEMENTS =====

    else if (url.includes('/achievements') && req.method === 'GET') {
      authenticate(req, (err, user) => {
        if (!user) return error(res, 'Unauthorized', 401);
        db.all('SELECT * FROM achievements WHERE user_id = ?', [user.id], (err, rows) => {
          success(res, { achievements: rows || [] });
        });
      });
    }

    else if (url.includes('/achievements') && req.method === 'POST') {
      authenticate(req, (err, user) => {
        if (!user) return error(res, 'Unauthorized', 401);
        const { achievementId, progress } = parsed;
        const id = generateId();
        db.run('INSERT OR REPLACE INTO achievements (id, user_id, achievement_id, progress, completed, completed_at) VALUES (?, ?, ?, ?, ?, ?)',
          [id, user.id, achievementId, progress, progress >= 100 ? 1 : 0, progress >= 100 ? new Date().toISOString() : null], () => {
            success(res, { id, achievementId, progress });
          });
      });
    }

    // ===== ADMIN PANEL =====

    else if (url === '/admin') {
      db.all('SELECT * FROM users ORDER BY created_at DESC', [], (err, users) => {
        db.all('SELECT * FROM game_servers', [], (err2, servers) => {
          const usersHtml = users.map(u => `
            <tr>
              <td>${u.username}</td>
              <td>${u.display_name || '-'}</td>
              <td>${u.rank}</td>
              <td>${u.points}</td>
              <td>${u.coins}</td>
              <td>${u.created_at?.split('T')[0] || '-'}</td>
              <td>
                <button onclick="giveCoins('${u.id}')" class="btn">منح عملات</button>
                <button onclick="giveRank('${u.id}')" class="btn btn-gold">رفع رانك</button>
              </td>
            </tr>
          `).join('');

          const html = `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>لوحة تحكم كملنا</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; }
  .header { background: #1a1d27; padding: 20px 30px; border-bottom: 1px solid #2d3148; display: flex; justify-content: space-between; align-items: center; }
  .header h1 { color: #7c6aff; font-size: 22px; }
  .container { padding: 30px; max-width: 1200px; margin: 0 auto; }
  .card { background: #1a1d27; border: 1px solid #2d3148; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
  .card h2 { color: #7c6aff; margin-bottom: 20px; font-size: 18px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .stat { background: #1a1d27; border: 1px solid #2d3148; border-radius: 10px; padding: 20px; text-align: center; }
  .stat-num { font-size: 28px; font-weight: 700; color: #7c6aff; }
  .stat-label { font-size: 12px; color: #888; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: right; padding: 12px; color: #7c6aff; border-bottom: 1px solid #2d3148; font-size: 13px; }
  td { padding: 12px; border-bottom: 1px solid #1e2133; font-size: 13px; }
  tr:hover td { background: #1e2133; }
  .btn { background: #7c6aff; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; margin: 2px; }
  .btn-gold { background: #f0a500; }
  .btn:hover { opacity: 0.8; }
  input, select { background: #0f1117; border: 1px solid #2d3148; color: #e0e0e0; padding: 10px 14px; border-radius: 8px; font-size: 14px; }
</style>
</head>
<body>
<div class="header">
  <h1>🎮 لوحة تحكم كملنا</h1>
  <span style="color:#888">السيرفر يعمل ✅</span>
</div>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="stat-num">${users.length}</div><div class="stat-label">إجمالي اللاعبين</div></div>
    <div class="stat"><div class="stat-num">${servers.length}</div><div class="stat-label">السيرفرات</div></div>
    <div class="stat"><div class="stat-num">${users.filter(u => u.last_login).length}</div><div class="stat-label">دخلوا مرة</div></div>
  </div>

  <div class="card">
    <h2>👥 اللاعبون</h2>
    <table>
      <thead>
        <tr>
          <th>اسم المستخدم</th>
          <th>الاسم</th>
          <th>الرانك</th>
          <th>النقاط</th>
          <th>العملات</th>
          <th>تاريخ التسجيل</th>
          <th>إجراءات</th>
        </tr>
      </thead>
      <tbody>${usersHtml}</tbody>
    </table>
  </div>
</div>
<script>
async function giveCoins(id) {
  const amount = prompt('كم عملة تريد منح؟', '1000');
  if (!amount) return;
  await fetch('/admin/give-coins', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({userId: id, amount: parseInt(amount)}) });
  location.reload();
}
async function giveRank(id) {
  const rank = prompt('ما الرانك الجديد؟ (0-6)', '1');
  if (rank === null) return;
  await fetch('/admin/give-rank', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({userId: id, rank: parseInt(rank)}) });
  location.reload();
}
</script>
</body>
</html>`;
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(html);
        });
      });
    }

    // Admin: Give Coins
    else if (url === '/admin/give-coins' && req.method === 'POST') {
      const { userId, amount } = parsed;
      db.run('UPDATE users SET coins = coins + ? WHERE id = ?', [amount, userId], () => {
        json(res, 200, { success: true });
      });
    }

    // Admin: Give Rank
    else if (url === '/admin/give-rank' && req.method === 'POST') {
      const { userId, rank } = parsed;
      db.run('UPDATE users SET rank = ? WHERE id = ?', [rank, userId], () => {
        json(res, 200, { success: true });
      });
    }

    // Catch All
    else {
      json(res, 200, { success: true, message: 'Kammelna Server Running' });
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🎮 Kammelna Server running on port ${PORT}`));
