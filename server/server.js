require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const createAuthMiddleware = require('./authMiddleware');
const createAdminMiddleware = require('./adminMiddleware'); // <-- 引入创建函数

let db; // 将 db 提升为全局变量
const app = express();

const initializeApp = async () => {
  // 1. 加载并等待数据库初始化函数完成
  const initializeDatabase = require('./db');
  const dbConnection = await initializeDatabase();
  db = dbConnection.db; // 将连接成功的 db 对象赋值给全局变量

  // --- 核心修改：在获取到 db 对象后，才创建中间件 ---
  const authenticateRequest = createAuthMiddleware(db);
  const ensureAdmin = createAdminMiddleware(db); // <-- 正确的创建方式


// 新增：用于存储每个角色轮询计数器的对象
const roundRobinCounters = {};
  let dashboardCache = null; // <-- 添加这一行
  const CACHE_DURATION_SECONDS = 60; // <-- 添加这一行

app.set('trust proxy', 1);
const port = process.env.APP_PORT || 3000;

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
      db.run_query(sql, [logInfo.userId, logInfo.ipAddress, logInfo.character, logInfo.requestText, statusMessage], (err) => {
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
  // 1. 从URL查询参数中获取 code 和 state
  const { code, state } = req.query;

  // 2. 安全验证：检查 state 参数以防止 CSRF 攻击
  const savedState = req.session.oauth_state;
  delete req.session.oauth_state; // state 只能使用一次，用完即删
  if (!state || !savedState || state !== savedState) {
    return res.status(403).send('<h1>认证失败</h1><p>State参数无效，可能存在跨站请求伪造攻击。请返回首页重试。</p><a href="/">返回首页</a>');
  }

  try {
    // 3. 向 OAuth 提供商的 token 端点发送请求，用 code 换取 access_token
    const tokenResponse = await axios.post(process.env.OAUTH_TOKEN_URL, new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      redirect_uri: `${process.env.APP_BASE_URL}/oauth/callback`
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const accessToken = tokenResponse.data.access_token;
    if (!accessToken) {
      throw new Error('OAuth provider did not return an access token.');
    }

    // 4. 使用 access_token 获取用户信息
    const userInfoResponse = await axios.get(process.env.OAUTH_USERINFO_URL, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const userInfo = userInfoResponse.data;

    if (!userInfo || !userInfo.sub) {
      throw new Error('OAuth provider did not return valid user info or user ID (sub).');
    }

    // 5. 与我们的数据库进行同步（更新或插入 Upsert）
    const [existingUser] = await db.query('SELECT id FROM users WHERE id = ?', [userInfo.sub]);

    if (existingUser) {
      // 如果用户已存在，则更新他们的信息（名字、头像等可能已更改）
      const sql = 'UPDATE users SET name = ?, email = ?, avatar = ? WHERE id = ?';
      await db.run_query(sql, [userInfo.name, userInfo.email, userInfo.picture, userInfo.sub]);
    } else {
      // 如果是新用户，则插入一条新记录
      const sql = 'INSERT INTO users (id, name, email, avatar) VALUES (?, ?, ?, ?)';
      await db.run_query(sql, [userInfo.sub, userInfo.name, userInfo.email, userInfo.picture]);
    }

    // 6. 为用户创建 session，完成登录
    req.session.user = userInfo;

    // 7. 将用户重定向回首页
    res.redirect('/');

  } catch (error) {
    // 8. 统一处理流程中可能出现的任何错误
    console.error('OAuth Callback Error:', error.response ? error.response.data : error.message);
    res.status(500).send('<h1>登录失败</h1><p>与认证服务器通信时发生错误，请稍后重试。</p><a href="/">返回首页</a>');
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
  app.get('/api/tokens', ensureLoggedIn, async (req, res) => {
    try {
      const userId = req.session.user.sub;
      const sql = "SELECT id, token, name, created_at, usage_count, last_used_at FROM api_tokens WHERE user_id = ? ORDER BY id DESC";

      // 使用新的 db.query 辅助函数
      const rows = await db.query(sql, [userId]);

      const sanitizedRows = rows.map(row => ({
        ...row,
        token_preview: `${row.token.substring(0, 8)}...`
      }));

      res.json(sanitizedRows);
    } catch (error) {
      console.error("Failed to retrieve user tokens:", error);
      res.status(500).json({ error: "获取Token列表失败。" });
    }
  });

// 创建一个新的 token
  app.post('/api/tokens', ensureLoggedIn, async (req, res) => {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Token名称不能为空。" });
    }

    try {
      const userIdFromSession = req.session.user.sub;
      const newToken = `tts_token_${crypto.randomBytes(24).toString('hex')}`;
      const sql = "INSERT INTO api_tokens (token, user_id, name) VALUES (?, ?, ?)";

      // 使用新的 db.run_query 辅助函数
      const result = await db.run_query(sql, [newToken, userIdFromSession, name.trim()]);

      res.status(201).json({ id: result.lastID, name: name.trim(), token: newToken });
    } catch (error) {
      console.error("Failed to create user token:", error);
      res.status(500).json({ error: "创建Token失败。" });
    }
  });

// 删除一个 token
  app.delete('/api/tokens/:id', ensureLoggedIn, async (req, res) => {
    try {
      const tokenId = req.params.id;
      const userId = req.session.user.sub;
      const sql = "DELETE FROM api_tokens WHERE id = ? AND user_id = ?";

      // 使用新的 db.run_query 辅助函数
      const result = await db.run_query(sql, [tokenId, userId]);

      if (result.changes === 0) {
        return res.status(404).json({ error: "未找到Token或您没有权限删除。" });
      }

      res.status(204).send(); // 成功，无内容返回
    } catch (error) {
      console.error("Failed to delete user token:", error);
      res.status(500).json({ error: "删除Token失败。" });
    }
  });

// --- 新增：管理员后台的入口路由 ---
// 这个路由受 ensureAdmin 中间件保护
app.get('/admin', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/dashboard.html'));
});

// --- 新增：为管理员仪表盘提供数据的 API ---

// --- 新增：为全新仪表盘提供所有数据的统一接口 ---
// 获取仪表盘所有数据的统一接口 (最终重构版)
  app.get('/api/admin/dashboard-data', ensureAdmin, async (req, res) => {
    // 缓存逻辑保持不变
    if (dashboardCache && (Date.now() - dashboardCache.timestamp) < CACHE_DURATION_SECONDS * 1000) {
      console.log("[Cache] Serving dashboard data from cache.");
      return res.json(dashboardCache.data);
    }

    console.log("[Cache] Cache expired or not present. Fetching new dashboard data.");
    try {
      const dbType = process.env.DB_TYPE || 'sqlite';
      const timeZoneOffset = '+8 hours';
      const mysqlTimeZone = '+08:00';

      let todayTokenSql, todayFrontendSql, dailyStatsSql;

      if (dbType === 'mysql') {
        todayTokenSql = `SELECT COUNT(*) as count FROM usage_logs WHERE request_timestamp >= CONVERT_TZ(CURDATE(), '${mysqlTimeZone}', '+00:00') AND request_timestamp < CONVERT_TZ(CURDATE() + INTERVAL 1 DAY, '${mysqlTimeZone}', '+00:00')`;
        todayFrontendSql = `SELECT COUNT(*) as count FROM frontend_logs WHERE request_timestamp >= CONVERT_TZ(CURDATE(), '${mysqlTimeZone}', '+00:00') AND request_timestamp < CONVERT_TZ(CURDATE() + INTERVAL 1 DAY, '${mysqlTimeZone}', '+00:00')`;
        dailyStatsSql = `SELECT DATE(CONVERT_TZ(request_timestamp, '+00:00', '${mysqlTimeZone}')) as date, COUNT(*) as count FROM usage_logs WHERE request_timestamp >= DATE_SUB(CONVERT_TZ(CURDATE(), '${mysqlTimeZone}', '+00:00'), INTERVAL 6 DAY) GROUP BY date ORDER BY date ASC`;
      } else { // SQLite
        todayTokenSql = `SELECT COUNT(*) as count FROM usage_logs WHERE DATE(request_timestamp, '${timeZoneOffset}') = DATE('now', 'localtime', '${timeZoneOffset}')`;
        todayFrontendSql = `SELECT COUNT(*) as count FROM frontend_logs WHERE DATE(request_timestamp, '${timeZoneOffset}') = DATE('now', 'localtime', '${timeZoneOffset}')`;
        dailyStatsSql = `SELECT DATE(request_timestamp, '${timeZoneOffset}') as date, COUNT(*) as count FROM usage_logs WHERE request_timestamp >= DATE('now', '-6 days', 'localtime', '${timeZoneOffset}') GROUP BY date ORDER BY date ASC`;
      }

      const [
        userCountResult, tokenCountResult, totalCallsResult, frontendCallsResult,
        todayCallsResult, todayFrontendCallsResult, dailyStats,
        recentLogs, topCharacters
      ] = await Promise.all([
        db.query('SELECT COUNT(*) as count FROM users'),
        db.query('SELECT COUNT(*) as count FROM api_tokens'),
        db.query('SELECT COUNT(*) as count FROM usage_logs'),
        db.query('SELECT COUNT(*) as count FROM frontend_logs'),
        db.query(todayTokenSql),
        db.query(todayFrontendSql),
        db.query(dailyStatsSql),
        db.query(`SELECT l.id, l.request_timestamp, u.name as owner_name, tk.name as token_name FROM usage_logs l LEFT JOIN users u ON l.user_id = u.id LEFT JOIN api_tokens tk ON l.token_id = tk.id ORDER BY l.id DESC LIMIT 5`),
        db.query(`SELECT character_used, COUNT(*) as count FROM usage_logs WHERE character_used IS NOT NULL GROUP BY character_used ORDER BY count DESC LIMIT 5`)
      ]);

      // --- 在后端准备图表数据 ---
      const labels = [...Array(7)].map((_, i) => {
        // 注意：这里我们基于服务器的当前时间生成标签，以匹配SQL查询
        const d = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Shanghai" }));
        d.setDate(d.getDate() - i);
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
      }).reverse();

      const chartData = labels.map(label => {
        const found = dailyStats.find(row => (row.date instanceof Date ? row.date.toISOString().split('T')[0] : row.date) === label);
        return found ? found.count : 0;
      });

      const responseData = {
        stats: {
          totalUsers: userCountResult[0].count,
          totalTokens: tokenCountResult[0].count,
          totalCalls: totalCallsResult[0].count,
          frontendCalls: frontendCallsResult[0].count,
          todayCalls: todayCallsResult[0].count,
          todayFrontendCalls: todayFrontendCallsResult[0].count
        },
        chartData: { labels, data: chartData }, // 直接返回准备好的图表数据
        recentLogs,
        topCharacters
      };

      dashboardCache = { data: responseData, timestamp: Date.now() };
      res.json(responseData);

    } catch (error) {
      console.error("Error fetching dashboard data:", error);
      res.status(500).json({ error: "Failed to load dashboard data." });
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

    // 修正：移除 SQLite 特有的 rowid，使用主键 id 排序
    const users = await db.query('SELECT id, name, email, avatar FROM users ORDER BY id DESC LIMIT ? OFFSET ?', [limit, offset]);

    res.json({
      users: users,
      pagination: { total, limit, page, totalPages }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load users.' });
  }
});

// 2. 删除指定用户（及其所有关联数据）
// 删除指定用户（及其所有关联数据）- 已修复数据库兼容性问题
  app.delete('/api/admin/users/:id', ensureAdmin, async (req, res) => {
    const userId = req.params.id;
    try {
      // 移除 db.serialize，直接使用 await 来保证操作的先后顺序
      // 这种方式同时兼容 SQLite 和 MySQL

      // 第1步：删除该用户的所有 token 使用日志
      await db.run_query('DELETE FROM usage_logs WHERE user_id = ?', [userId]);

      // 第2步：删除该用户的所有前端使用日志
      await db.run_query('DELETE FROM frontend_logs WHERE user_id = ?', [userId]);

      // 第3步：删除该用户的所有 API Token
      await db.run_query('DELETE FROM api_tokens WHERE user_id = ?', [userId]);

      // 第4步：删除用户本身
      await db.run_query('DELETE FROM users WHERE id = ?', [userId]);

      console.log(`Successfully deleted user ${userId} and all associated data.`);
      res.status(204).send(); // 成功，无内容返回

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
};

initializeApp();