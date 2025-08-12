/**
 * 创建一个用于验证管理员权限的中间件
 * @param {object} db - 数据库连接对象 (虽然此中间件当前未使用db，但为了模式统一而传入)
 * @returns {function} Express 中间件
 */
function createAdminMiddleware(db) {

    // 返回真正的中间件函数
    return function ensureAdmin(req, res, next) {
        // 增加对 req.session 本身的检查，更加健壮
        if (!req.session || !req.session.user || !req.session.user.sub) {
            // 如果未登录，重定向到首页
            return res.status(401).redirect('/');
        }

        // 从环境变量中获取管理员ID列表
        const adminIds = (process.env.ADMIN_USER_IDS || '').split(',');
        const currentUserId = req.session.user.sub;

        // 检查当前用户ID是否在管理员列表中
        if (adminIds.includes(currentUserId)) {
            // 是管理员，放行
            next();
        } else {
            // 不是管理员，返回403 Forbidden错误
            res.status(403).send('<h1>403 - Forbidden</h1><p>您没有权限访问此页面。</p><a href="/">返回首页</a>');
        }
    };
}

module.exports = createAdminMiddleware;