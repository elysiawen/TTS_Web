require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const { db, initDb } = require('./database'); // 引入数据库
const authenticateRequest = require('./authMiddleware');
const ensureAdmin = require('./adminMiddleware');

// 初始化数据库和表
initDb();

// 新增：用于存储每个角色轮询计数器的对象
const roundRobinCounters = {};

const app = express();
app.set('trust proxy', 1);
const port = 3001;

// --- 中间件配置 ---

app.use(cors({
  origin: process.env.APP_BASE_URL,
  credentials: true
}));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 } // 24小时
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// --- 新增：一个简单的中间件，用于保护需要登录的路由 ---
const ensureLoggedIn = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).redirect('/'); // 未登录则重定向到首页
  }
};

// --- API 与 OAuth 路由 ---

// 1. 获取会话信息 (用于前端判断登录状态)
app.get('/api/session-info', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// 2. 获取 CSRF Token (保持不变)
app.get('/api/get-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = csrfToken;
  res.json({ csrfToken });
});

// 3. TTS 主 API (保持不变)
// --- 改造：从数据库读取配置进行TTS合成 ---
app.get('/api/tts', authenticateRequest, async (req, res) => {

  // 1. 准备日志所需的信息
  const logInfo = {
    userId: req.session.user ? req.session.user.sub : null,
    ipAddress: req.ip, // 'trust proxy' 确保了IP的准确性
    character: req.query.character || 'unknown',
    requestText: req.query.text || ''
  };

  // 2. 创建一个辅助函数，用于将日志写入数据库
  const writeFrontendLog = (statusMessage) => {
    // 只有当请求被 authMiddleware 标记为来自前端时，才执行写入
    if (req.isFrontendCall) {
      const sql = `INSERT INTO frontend_logs (user_id, ip_address, character_used, request_text, status_message) VALUES (?, ?, ?, ?, ?)`;
      db.run(sql, [logInfo.userId, logInfo.ipAddress, logInfo.character, logInfo.requestText, statusMessage], (err) => {
        if (err) console.error("Failed to write frontend log:", err);
      });
    }
  };

  try {
    const { text, media_type = 'wav', character = 'elysia', ...otherParams } = req.query;

    const [config] = await db.query("SELECT * FROM characters WHERE id = ?", [character]);

    if (!config || !config.enabled) {
      const errorMessage = '无效或未启用的角色标识符';
      writeFrontendLog(`Failed: ${errorMessage}`); // 记录失败日志
      return res.status(400).json({ error: errorMessage });
    }

    let urls;
    try { urls = JSON.parse(config.api_url); } catch (e) { urls = config.api_url; }
    if (!Array.isArray(urls)) urls = [urls];
    if (urls.length === 0) {
      const errorMessage = '配置错误：该角色没有可用的API URL。';
      writeFrontendLog(`Failed: ${errorMessage}`); // 记录失败日志
      return res.status(500).json({ error: errorMessage });
    }

    const characterCounter = roundRobinCounters[character] || 0;
    let lastError = null;

    for (let i = 0; i < urls.length; i++) {
      const urlIndex = (characterCounter + i) % urls.length;
      const selectedUrl = urls[urlIndex];
      console.log(`[Load Balancer] Attempting request for '${character}' to URL: ${selectedUrl}`);
      try {
        const response = await axios.get(selectedUrl, {
          params: {
            text,
            media_type,
            ref_audio_path: config.ref_audio_path,
            prompt_text: config.prompt_text,
            prompt_lang: config.prompt_lang || 'zh',
            text_lang: config.text_lang || 'zh',
            text_split_method: config.text_split_method || 'cut0',
            ...otherParams
          },
          responseType: 'arraybuffer',
          timeout: 30000
        });

        roundRobinCounters[character] = (urlIndex + 1) % urls.length;
        res.set({ 'Content-Type': `audio/${media_type}`, 'Content-Disposition': `attachment; filename="output.${media_type}"` });

        // 3. 在成功返回数据前，记录成功日志
        writeFrontendLog('Success');

        return res.send(response.data);

      } catch (error) {
        console.error(`[Load Balancer] Failed to connect to ${selectedUrl}:`, error.message);
        lastError = error;
      }
    }

    throw lastError || new Error("All upstream servers are unavailable.");
  } catch (error) {
    // 4. 在最终捕获到错误时，记录失败日志
    writeFrontendLog(`Failed: ${error.message}`);

    console.error('语音合成失败:', error.message);
    res.status(500).json({ error: '语音合成失败，所有后端节点均无响应。' });
  }
});

// --- OAuth 登录流程 ---

// 4. 登录入口: /login
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauth_state = state; // 存储 state 用于后续验证

  const authorizationUrl = new URL(process.env.OAUTH_AUTHORIZE_URL);
  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set('client_id', process.env.OAUTH_CLIENT_ID);
  authorizationUrl.searchParams.set('redirect_uri', `${process.env.APP_BASE_URL}/oauth/callback`);
  authorizationUrl.searchParams.set('scope', 'profile email openid'); // 假设 scope 是 'userinfo'
  authorizationUrl.searchParams.set('state', state);

  res.redirect(authorizationUrl.toString());
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Could not log out.');
    }
    res.redirect('/');
  });
});

// 5. OAuth 回调: /oauth/callback
app.get('/oauth/callback', async (req, res) => {
  // ... state 验证逻辑不变 ...
  const { code, state } = req.query;
  const savedState = req.session.oauth_state;
  delete req.session.oauth_state;
  if (!state || state !== savedState) return res.status(403).send('Invalid state.');

  try {
    // ... 换取 token, 获取用户信息的逻辑不变 ...
    const tokenResponse = await axios.post(process.env.OAUTH_TOKEN_URL, new URLSearchParams({ grant_type: 'authorization_code', code, client_id: process.env.OAUTH_CLIENT_ID, client_secret: process.env.OAUTH_CLIENT_SECRET, redirect_uri: `${process.env.APP_BASE_URL}/oauth/callback` }));
    const accessToken = tokenResponse.data.access_token;
    const userInfoResponse = await axios.get(process.env.OAUTH_USERINFO_URL, { headers: { 'Authorization': `Bearer ${accessToken}` } });
    const userInfo = userInfoResponse.data;

    // **新增**: 将用户信息存入数据库（如果不存在则插入，如果存在则更新）
    const sql = `INSERT INTO users (id, name, email, avatar) VALUES (?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET name=excluded.name, email=excluded.email, avatar=excluded.avatar`;
    db.run(sql, [userInfo.sub, userInfo.name, userInfo.email, userInfo.picture], (err) => {
      if (err) console.error("Error saving user to DB:", err);
    });

    // 将用户信息存入 session 并重定向
    req.session.user = userInfo;
    res.redirect('/');
  } catch (error) {
    console.error('OAuth Callback Error:', error.response ? error.response.data : error.message);
    res.status(500).send('Login process failed.');
  }
});

// --- 新增：API 管理页面路由 ---
app.get('/manage-api', ensureLoggedIn, (req, res) => {
  // 发送管理页面文件
  res.sendFile(path.join(__dirname, '../public/manage.html'));
});

// --- 新增：获取可用角色列表的 API ---
app.get('/api/characters', async (req, res) => {
  try {
    const characters = await db.query("SELECT id, name, enabled FROM characters");
    // 数据库返回的 enabled 是 1 或 0，我们转为 true/false
    const characterList = characters.map(char => ({
      ...char,
      enabled: Boolean(char.enabled)
    }));
    res.json(characterList);
  } catch (error) {
    console.error("Failed to load characters from database:", error);
    res.status(500).json({ error: "无法加载角色列表" });
  }
});

// --- 新增：API 文档页面路由 ---
app.get('/api-docs', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/docs.html'));
});

// --- 新增：管理 API Token 的 CRUD 接口 ---

// 读取当前用户的所有 tokens
app.get('/api/tokens', ensureLoggedIn, (req, res) => {
  const userId = req.session.user.sub;

  // **修改**：查询语句中增加 usage_count 和 last_used_at 字段
  const sql = "SELECT id, token, name, created_at, usage_count, last_used_at FROM api_tokens WHERE user_id = ?";

  db.all(sql, [userId], (err, rows) => {
    if (err) {
      console.error("Database error fetching tokens:", err);
      return res.status(500).json({ error: "Database error." });
    }

    const sanitizedRows = rows.map(row => ({
      ...row,
      token_preview: `${row.token.substring(0, 8)}...`
    }));
    res.json(sanitizedRows);
  });
});

// 创建一个新的 token
app.post('/api/tokens', ensureLoggedIn, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "Token name is required." });
  }

  // 从 session 中获取用户的 'sub'
  const userIdFromSession = req.session.user ? req.session.user.sub : undefined;

  if (!userIdFromSession) {
    return res.status(401).json({ error: "User session is invalid or ID is missing. Please log in again." });
  }

  const newToken = `tts_token_${crypto.randomBytes(24).toString('hex')}`;
  const sql = "INSERT INTO api_tokens (token, user_id, name) VALUES (?, ?, ?)";

  // --- 这是修正的核心 ---
  // 确保将 userIdFromSession 作为第二个参数传递给数据库
  db.run(sql, [newToken, userIdFromSession, name.trim()], function(err) {
    if (err) {
      console.error('Database error when creating token:', err);
      return res.status(500).json({ error: "Failed to create token due to a database error." });
    }
    // 创建成功，返回包含完整新Token的对象
    res.status(201).json({ id: this.lastID, name: name.trim(), token: newToken });
  });
});

// 删除一个 token
app.delete('/api/tokens/:id', ensureLoggedIn, (req, res) => {
  const tokenId = req.params.id;
  const userId = req.session.user.sub;

  // 确保用户只能删除自己的 token
  const sql = "DELETE FROM api_tokens WHERE id = ? AND user_id = ?";
  db.run(sql, [tokenId, userId], function(err) {
    if (err) return res.status(500).json({ error: "Database error." });
    if (this.changes === 0) {
      return res.status(404).json({ error: "Token not found or you do not have permission." });
    }
    res.status(204).send(); // No Content
  });
});

// --- 新增：管理员后台的入口路由 ---
// 这个路由受 ensureAdmin 中间件保护
app.get('/admin', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/dashboard.html'));
});

// --- 新增：为管理员仪表盘提供数据的 API ---

// 1. 获取核心统计数据
app.get('/api/admin/stats', ensureAdmin, async (req, res) => {
  try {
    // 并行执行所有统计查询
    const results = await Promise.all([
      db.query('SELECT COUNT(*) as count FROM users'),
      db.query('SELECT COUNT(*) as count FROM api_tokens'),
      db.query('SELECT COUNT(*) as count FROM usage_logs'),
      db.query("SELECT COUNT(*) as count FROM usage_logs WHERE DATE(request_timestamp) = DATE('now', 'localtime')")
    ]);

    // db.query 返回的是一个数组，例如 [{ count: 10 }]
    // 所以我们需要先取数组的第一个元素 [0]，然后再取 .count 属性
    const totalUsers = results[0][0].count;
    const totalTokens = results[1][0].count;
    const totalCalls = results[2][0].count;
    const todayCalls = results[3][0].count;

    res.json({
      totalUsers,
      totalTokens,
      totalCalls,
      todayCalls
    });
  } catch (error) {
    console.error("Error fetching admin stats:", error);
    res.status(500).json({ error: "Failed to load statistics." });
  }
});


// 2. 获取最近7天的调用数据用于图表
app.get('/api/admin/daily-stats', ensureAdmin, async (req, res) => {
  try {
    // 使用更现代的 Promise 封装来替代回调
    const promiseQuery = (sql) => new Promise((resolve, reject) => {
      db.all(sql, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });

    const rows = await promiseQuery(`
            SELECT DATE(request_timestamp) as date, COUNT(*) as count 
            FROM usage_logs 
            WHERE request_timestamp >= DATE('now', '-6 days', 'localtime')
            GROUP BY date 
            ORDER BY date ASC
        `);

    // 生成最近7天的所有日期标签
    const labels = [...Array(7)].map((_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - i);
      return d.toISOString().split('T')[0];
    }).reverse();

    // 将数据库数据映射到日期标签上
    const data = labels.map(label => {
      const found = rows.find(row => row.date === label);
      return found ? found.count : 0;
    });

    res.json({ labels, data });

  } catch (error) {
    console.error("Error fetching daily stats:", error);
    res.status(500).json({ error: "Failed to load daily statistics." });
  }
});

// 新增：指向用户管理页面的路由
app.get('/admin/users', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/users.html'));
});

// --- 新增：为管理员提供用户管理的 API ---

// 1. 获取用户列表（带分页）
app.get('/api/admin/users', ensureAdmin, async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const offset = (page - 1) * limit;

  try {
    const [totalResult] = await db.query('SELECT COUNT(*) as total FROM users');
    const total = totalResult.total;
    const totalPages = Math.ceil(total / limit);

    const users = await db.query('SELECT id, name, email, avatar FROM users ORDER BY rowid DESC LIMIT ? OFFSET ?', [limit, offset]);

    res.json({
      users: users,
      pagination: { total, limit, page, totalPages }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load users.' });
  }
});

// 2. 删除指定用户（及其所有关联数据）
app.delete('/api/admin/users/:id', ensureAdmin, async (req, res) => {
  const userId = req.params.id;
  try {
    // 使用 serialize 确保操作按顺序执行，实现事务性
    db.serialize(async () => {
      await db.query('DELETE FROM usage_logs WHERE user_id = ?', [userId]);
      await db.query('DELETE FROM api_tokens WHERE user_id = ?', [userId]);
      await db.query('DELETE FROM users WHERE id = ?', [userId]);
    });
    res.status(204).send(); // 204 No Content
  } catch (error) {
    console.error(`Failed to delete user ${userId}:`, error);
    res.status(500).json({ error: 'Failed to delete user.' });
  }
});

// 新增：指向 Token 管理页面的路由
app.get('/admin/tokens', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/tokens.html'));
});


// --- 新增：为管理员提供 Token 管理的 API ---

// 1. 获取所有 Token 列表（带分页和用户信息）
app.get('/api/admin/tokens', ensureAdmin, async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const offset = (page - 1) * limit;

  try {
    const [totalResult] = await db.query('SELECT COUNT(*) as total FROM api_tokens');
    const total = totalResult.total;
    const totalPages = Math.ceil(total / limit);

    // 使用 LEFT JOIN 关联 users 表，以获取 token 所有者的名字
    const sql = `
            SELECT t.id, t.name, t.token, t.usage_count, t.created_at, t.last_used_at, u.name as owner_name
            FROM api_tokens t
            LEFT JOIN users u ON t.user_id = u.id
            ORDER BY t.id DESC
            LIMIT ? OFFSET ?
        `;
    const tokens = await db.query(sql, [limit, offset]);

    res.json({
      tokens: tokens,
      pagination: { total, limit, page, totalPages }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load tokens.' });
  }
});

// 2. 管理员删除指定 ID 的 Token
//    (注意，这是 /api/admin/tokens 路由，与用户自己删除的 /api/tokens 不同)
app.delete('/api/admin/tokens/:id', ensureAdmin, async (req, res) => {
  const tokenId = req.params.id;
  try {
    // 管理员可以直接删除任何 token，无需检查 user_id
    await db.query('DELETE FROM api_tokens WHERE id = ?', [tokenId]);
    // 我们也可以选择性地删除这个token的日志，这里暂时不处理，以保留完整的调用记录
    res.status(204).send(); // 204 No Content
  } catch (error) {
    console.error(`Admin failed to delete token ${tokenId}:`, error);
    res.status(500).json({ error: 'Failed to delete token.' });
  }
});

// 新增：指向日志管理页面的路由
app.get('/admin/logs', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/logs.html'));
});


// --- 新增：为管理员提供日志查询的 API ---

app.get('/api/admin/logs', ensureAdmin, async (req, res) => {
  // ... 分页和筛选逻辑不变 ...
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 15;
  const offset = (page - 1) * limit;
  const { userId, tokenId } = req.query;
  let whereClauses = [];
  let params = [];
  let countParams = [];
  if (userId) { whereClauses.push('l.user_id = ?'); params.push(userId); countParams.push(userId); }
  if (tokenId) { whereClauses.push('l.token_id = ?'); params.push(tokenId); countParams.push(tokenId); }
  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  try {
    const totalSql = `SELECT COUNT(*) as total FROM usage_logs l ${whereSql}`;
    const [totalResult] = await db.query(totalSql, countParams);
    const total = totalResult.total;
    const totalPages = Math.ceil(total / limit);

    // --- 修改：在 SELECT 语句中加入 request_text 字段 ---
    const logsSql = `
      SELECT l.id, l.user_id, l.token_id, l.character_used, l.request_timestamp, l.status_code, l.request_text,
             u.name as owner_name, tk.name as token_name
      FROM usage_logs l
             LEFT JOIN users u ON l.user_id = u.id
             LEFT JOIN api_tokens tk ON l.token_id = tk.id
        ${whereSql}
      ORDER BY l.id DESC
        LIMIT ? OFFSET ?
    `;
    params.push(limit, offset);
    const logs = await db.query(logsSql, params);

    res.json({
      logs,
      pagination: { total, limit, page, totalPages }
    });
  } catch (error) {
    console.error("Failed to fetch usage logs:", error);
    res.status(500).json({ error: 'Failed to load usage logs.' });
  }
});

// 新增：指向角色管理页面的路由
app.get('/admin/characters', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/characters.html'));
});


// --- 新增：为管理员提供角色管理的 API ---

// 1. 获取所有角色列表
app.get('/api/admin/characters', ensureAdmin, async (req, res) => {
  try {
    const characters = await db.query('SELECT * FROM characters ORDER BY created_at DESC');
    res.json(characters);
  } catch (error) {
    res.status(500).json({ error: 'Failed to load characters.' });
  }
});

// 2. 删除指定 ID 的角色
app.delete('/api/admin/characters/:id', ensureAdmin, async (req, res) => {
  const charId = req.params.id;
  try {
    await db.query('DELETE FROM characters WHERE id = ?', [charId]);
    res.status(204).send(); // No Content
  } catch (error) {
    console.error(`Admin failed to delete character ${charId}:`, error);
    res.status(500).json({ error: 'Failed to delete character.' });
  }
});

// 1. 获取单个角色的详细信息 (用于编辑)
app.get('/api/admin/characters/:id', ensureAdmin, async (req, res) => {
  try {
    const [character] = await db.query('SELECT * FROM characters WHERE id = ?', [req.params.id]);
    if (character) {
      res.json(character);
    } else {
      res.status(404).json({ error: 'Character not found.' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to load character details.' });
  }
});

// 2. 创建一个新角色
app.post('/api/admin/characters', ensureAdmin, async (req, res) => {
  const { id, name, enabled, ref_audio_path, prompt_text, api_url, prompt_lang, text_lang, text_split_method } = req.body;
  if (!id || !name || !api_url) {
    return res.status(400).json({ error: 'ID, Name, and API URL are required.' });
  }

  try {
    const sql = `
            INSERT INTO characters (id, name, enabled, ref_audio_path, prompt_text, api_url, prompt_lang, text_lang, text_split_method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
    await db.query(sql, [id, name, enabled, ref_audio_path, prompt_text, api_url, prompt_lang, text_lang, text_split_method]);
    res.status(201).json({ message: 'Character created successfully.' });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ error: `Character ID '${id}' already exists.` });
    }
    console.error("Failed to create character:", error);
    res.status(500).json({ error: 'Failed to create character.' });
  }
});

// 3. 更新一个现有角色
app.put('/api/admin/characters/:id', ensureAdmin, async (req, res) => {
  const { name, enabled, ref_audio_path, prompt_text, api_url, prompt_lang, text_lang, text_split_method } = req.body;
  const charId = req.params.id;

  try {
    const sql = `
            UPDATE characters SET
            name = ?, enabled = ?, ref_audio_path = ?, prompt_text = ?, api_url = ?, 
            prompt_lang = ?, text_lang = ?, text_split_method = ?
            WHERE id = ?
        `;
    await db.query(sql, [name, enabled, ref_audio_path, prompt_text, api_url, prompt_lang, text_lang, text_split_method, charId]);
    res.status(200).json({ message: 'Character updated successfully.' });
  } catch (error) {
    console.error(`Failed to update character ${charId}:`, error);
    res.status(500).json({ error: 'Failed to update character.' });
  }
});

// 新增：指向前端日志管理页面的路由
app.get('/admin/frontend-logs', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/frontend_logs.html'));
});

// --- 在管理员 API 部分，添加以下接口 ---

// 获取前端使用日志 (带分页和筛选)
app.get('/api/admin/frontend-logs', ensureAdmin, async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 15;
  const offset = (page - 1) * limit;

  const { userId, ipAddress } = req.query;
  let whereClauses = [];
  let params = [];

  if (userId) { whereClauses.push('l.user_id = ?'); params.push(userId); }
  if (ipAddress) { whereClauses.push('l.ip_address = ?'); params.push(ipAddress); }
  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  try {
    const totalSql = `SELECT COUNT(*) as total FROM frontend_logs l ${whereSql}`;
    const [totalResult] = await db.query(totalSql, params);
    const total = totalResult.total;
    const totalPages = Math.ceil(total / limit);

    const logsSql = `
            SELECT l.*, u.name as owner_name
            FROM frontend_logs l
            LEFT JOIN users u ON l.user_id = u.id
            ${whereSql}
            ORDER BY l.id DESC
            LIMIT ? OFFSET ?
        `;
    const logs = await db.query(logsSql, [...params, limit, offset]);

    res.json({ logs, pagination: { total, limit, page, totalPages } });
  } catch (error) {
    console.error("Failed to fetch frontend logs:", error);
    res.status(500).json({ error: 'Failed to load frontend logs.' });
  }
});

app.listen(port, () => {
  console.log(`TTS 服务已启动，请访问 http://localhost:${port}`);
});