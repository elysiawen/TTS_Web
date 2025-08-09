const ensureAdmin = (req, res, next) => {
    // 检查用户是否已登录
    if (!req.session.user || !req.session.user.sub) {
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

module.exports = ensureAdmin;