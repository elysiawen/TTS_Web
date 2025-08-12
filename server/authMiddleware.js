const { db } = require('./database');

const TRUSTED_FRONTEND_DOMAIN = process.env.APP_BASE_URL || 'http://localhost:3001';

// 修改辅助函数，增加 requestText 参数
function logApiUsage(tokenId, userId, character, statusCode, requestText) {
    const sql = `INSERT INTO usage_logs (token_id, user_id, character_used, status_code, request_text) VALUES (?, ?, ?, ?, ?)`;
    // 增加 requestText 到参数列表
    db.run(sql, [tokenId, userId, character, statusCode, requestText], (err) => {
        if (err) {
            console.error('Failed to log API usage:', err);
        }
    });
}

const authenticateRequest = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    let apiToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!apiToken && req.query && req.query.api_token) apiToken = req.query.api_token;
    if (!apiToken && req.body && req.body.api_token) apiToken = req.body.api_token;

    if (apiToken) {
        const sqlSelect = "SELECT id, user_id FROM api_tokens WHERE token = ?";
        db.get(sqlSelect, [apiToken], (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            if (row) {
                const sqlUpdate = `UPDATE api_tokens SET usage_count = usage_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?`;
                db.run(sqlUpdate, [row.id]);

                // 修改：在调用日志函数时，传入 req.query.text
                logApiUsage(row.id, row.user_id, req.query.character || 'unknown', 200, req.query.text || '');

                return next();
            } else {
                checkCsrf(req, res, next);
            }
        });
    } else {
        checkCsrf(req, res, next);
    }
};

// CSRF检查逻辑保持不变
function checkCsrf(req, res, next) {
    const referer = req.get('Referer');
    if (referer && referer.startsWith(TRUSTED_FRONTEND_DOMAIN)) {
        const csrfTokenFromHeader = req.headers['x-csrf-token'];
        const csrfTokenFromSession = req.session.csrfToken;
        if (csrfTokenFromHeader && csrfTokenFromSession && csrfTokenFromHeader === csrfTokenFromSession) {
            delete req.session.csrfToken;

            // --- 核心修改：为请求对象添加一个标记 ---
            req.isFrontendCall = true;

            return next();
        }
    }
    res.status(401).json({ error: 'Unauthorized: A valid API token or a valid session is required.' });
}


module.exports = authenticateRequest;