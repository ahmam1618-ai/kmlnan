const http = require('http');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./kammelna.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT, url TEXT,
    request_body TEXT, response_body TEXT,
    status INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  console.log('Database ready');
});

const forwardRequest = (method, path, headers, body, callback) => {
  const options = {
    hostname: 'kammelna.com',
    port: 443,
    path: path,
    method: method,
    headers: { ...headers, host: 'kammelna.com' },
    rejectUnauthorized: false
  };
  delete options.headers['content-length'];

  const req = https.request(options, (res) => {
    let data = Buffer.alloc(0);
    res.on('data', chunk => { data = Buffer.concat([data, chunk]); });
    res.on('end', () => callback(null, res.statusCode, res.headers, data));
  });
  req.on('error', callback);
  if (body) req.write(body);
  req.end();
};

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') { res.writeHead(200); return res.end(); }

  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    const url = req.url;
    console.log(req.method, url);

    if (url === '/admin') {
      db.all('SELECT * FROM requests ORDER BY id DESC LIMIT 50', [], (err, rows) => {
        const rowsHtml = rows.map(r => `<tr><td>${r.method}</td><td>${r.url}</td><td>${r.status}</td><td>${(r.request_body||'').substring(0,80)}</td><td>${(r.response_body||'').substring(0,80)}</td><td>${r.created_at}</td></tr>`).join('');
        const html = `<!DOCTYPE html><html dir="rtl"><head><meta charset="UTF-8"><title>Proxy Monitor</title>
<style>body{background:#0f1117;color:#e0e0e0;font-family:monospace}table{width:100%;border-collapse:collapse;font-size:11px}th,td{padding:8px;border-bottom:1px solid #333;text-align:right}th{color:#7c6aff}.header{padding:20px;background:#1a1d27}h1{color:#7c6aff}.container{padding:20px}button{background:#7c6aff;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;margin-bottom:12px}</style>
</head><body><div class="header"><h1>🔍 Proxy Monitor - كملنا</h1></div>
<div class="container"><button onclick="location.reload()">تحديث</button>
<table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Request</th><th>Response</th><th>Time</th></tr></thead>
<tbody>${rowsHtml}</tbody></table></div></body></html>`;
        res.writeHead(200, {'Content-Type':'text/html;charset=utf-8'});
        res.end(html);
      });
      return;
    }

    forwardRequest(req.method, url, req.headers, body, (err, status, resHeaders, responseBody) => {
      if (err) {
        console.error('Error:', err.message);
        res.writeHead(502);
        return res.end(JSON.stringify({error: err.message}));
      }

      db.run('INSERT INTO requests (method,url,request_body,response_body,status) VALUES(?,?,?,?,?)',
        [req.method, url, body.substring(0,500), responseBody.toString().substring(0,500), status]);

      const skip = ['transfer-encoding','connection','keep-alive'];
      Object.entries(resHeaders).forEach(([k,v]) => {
        if (!skip.includes(k.toLowerCase())) try { res.setHeader(k,v); } catch(e){}
      });
      res.writeHead(status);
      res.end(responseBody);
    });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Proxy running on port ' + PORT));
