const mysql = require('mysql2/promise');

let db;

/**
 * 初始化并连接到 MySQL 数据库。
 * @returns {Promise<{db: object, initDb: function}>}
 */
async function initialize() {
    // 如果已连接，直接返回，防止重复初始化
    if (db) return { db, initDb };

    try {
        const pool = await mysql.createPool({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            // dateStrings: true // 保持注释或删除，以返回标准日期对象
        });
        console.log('Connected to the MySQL database.');

        // 为连接池对象添加统一的 query 和 run_query 方法以匹配 SQLite 适配器
        pool.query = async function (sql, params) {
            const [rows] = await this.execute(sql, params);
            return rows;
        };
        pool.run_query = async function (sql, params) {
            const [result] = await this.execute(sql, params);
            return { lastID: result.insertId, changes: result.affectedRows };
        };

        db = pool; // 将连接池赋值给 db
        await initDb(); // 等待表初始化完成

        return { db, initDb };

    } catch (error) {
        console.error('Failed to connect to MySQL database:', error);
        process.exit(1); // 连接失败则强制退出程序
    }
}

// initDb 现在是一个独立的异步函数，执行 MySQL 语法的建表语句
const initDb = async () => {
    if (!db) throw new Error("Database not connected for initDb.");

    console.log("Checking and creating MySQL tables...");

    const queries = [
        `CREATE TABLE IF NOT EXISTS users (
                                              id VARCHAR(255) PRIMARY KEY,
            name TEXT, email TEXT, avatar TEXT,
            enabled BOOLEAN DEFAULT TRUE
            )`,
        `CREATE TABLE IF NOT EXISTS characters (
                                                   id VARCHAR(255) PRIMARY KEY,
            name TEXT NOT NULL, ref_audio_path TEXT, prompt_text TEXT, api_url TEXT NOT NULL,
            enabled BOOLEAN DEFAULT TRUE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            prompt_lang TEXT, text_lang TEXT, text_split_method TEXT
            )`,
        `CREATE TABLE IF NOT EXISTS api_tokens (
                                                   id INT AUTO_INCREMENT PRIMARY KEY,
                                                   token TEXT NOT NULL, user_id VARCHAR(255) NOT NULL, name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            usage_count INT DEFAULT 0, last_used_at DATETIME,
            enabled BOOLEAN DEFAULT TRUE,
            INDEX idx_user_id (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`,
        // --- 核心修改在这里 ---
        `CREATE TABLE IF NOT EXISTS usage_logs (
                                                   id INT AUTO_INCREMENT PRIMARY KEY,
                                                   token_id INT, -- 1. 移除了 NOT NULL，允许此字段为空
                                                   user_id VARCHAR(255) NOT NULL,
            character_used TEXT, request_text TEXT, request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, status_code INT,
            INDEX idx_timestamp (request_timestamp),
            -- 2. 将 ON DELETE CASCADE 修改为 ON DELETE SET NULL
            FOREIGN KEY (token_id) REFERENCES api_tokens(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`,
        `CREATE TABLE IF NOT EXISTS frontend_logs (
                                                      id INT AUTO_INCREMENT PRIMARY KEY,
                                                      user_id VARCHAR(255), ip_address TEXT, request_text TEXT, character_used TEXT,
            status_message TEXT, request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )`
    ];
    for (const query of queries) {
        await db.query(query);
    }
    console.log("MySQL tables checked/created.");
};

module.exports = initialize;