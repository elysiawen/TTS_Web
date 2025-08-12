// 注意：这里不再 require db
// const { db } = require('./db');

const TRUSTED_FRONTEND_DOMAIN = process.env.APP_BASE_URL || 'http://localhost:3001';

// 导出一个创建中间件的函数，它接收 db 对象作为参数
function createAuthMiddleware(db) {

    // 辅助函数：记录 API Token 的使用情况
    function logApiUsage(tokenId, userId, queryParams) {
        const { character = 'unknown', text = '' } = queryParams;
        const sql = `INSERT INTO usage_logs (token_id, user_id, character_used, status_code, request_text) VALUES (?, ?, ?, ?, ?)`;
        db.run_query(sql, [tokenId, userId, character, 200, text])
            .catch(err => console.error('Failed to log API usage:', err));
    }

    // CSRF 检查逻辑
    function checkCsrf(req, res, next) {
        const referer = req.get('Referer');
        if (referer && referer.startsWith(TRUSTED_FRONTEND_DOMAIN)) {
            const csrfTokenFromHeader = req.headers['x-csrf-token'];
            const csrfTokenFromSession = req.session.csrfToken;
            if (csrfTokenFromHeader && csrfTokenFromSession && csrfTokenFromHeader === csrfTokenFromSession) {
                delete req.session.csrfToken;
                req.isFrontendCall = true;
                return next();
            }
        }
        res.status(401).json({ error: 'Unauthorized: A valid API token or a valid session is required.' });
    }

    // 返回真正的中间件函数
    // 这个函数可以安全地使用传入的 db 对象
    return async function authenticateRequest(req, res, next) {
        try {
            const authHeader = req.headers['authorization'];
            let apiToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

            if (!apiToken && req.query && req.query.api_token) apiToken = req.query.api_token;
            if (!apiToken && req.body && req.body.api_token) apiToken = req.body.api_token;

            if (apiToken) {
                const [tokenRow] = await db.query("SELECT * FROM api_tokens WHERE token = ?", [apiToken]);

                if (tokenRow) {
                    const sqlUpdate = `UPDATE api_tokens SET usage_count = usage_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?`;
                    db.run_query(sqlUpdate, [tokenRow.id]);
                    logApiUsage(tokenRow.id, tokenRow.user_id, req.query);
                    return next();
                }
            }

            checkCsrf(req, res, next);

        } catch (error) {
            console.error("Authentication error:", error);
            res.status(500).json({ error: "An internal server error occurred during authentication." });
        }
    };
}

module.exports = createAuthMiddleware;