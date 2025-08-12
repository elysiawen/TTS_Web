const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '../database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database.', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// 一个辅助函数，用于安全地为已存在的表添加新列，以保证向后兼容性
function addColumn(tableName, columnName, columnType) {
    db.all(`PRAGMA table_info(${tableName})`, (err, columns) => {
        if (err) {
            console.error(`Error checking columns for ${tableName}:`, err);
            return;
        }
        const columnExists = columns.some(col => col.name === columnName);
        if (!columnExists) {
            db.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`, (alterErr) => {
                if (alterErr) {
                    console.error(`Error adding column ${columnName} to ${tableName}:`, alterErr);
                } else {
                    console.log(`Column ${columnName} added to ${tableName}.`);
                }
            });
        }
    });
}

// 初始化数据库中所有表的函数
const initDb = () => {
    db.serialize(() => {
        // 1. 用户表
        db.run(`CREATE TABLE IF NOT EXISTS users (
                                                     id TEXT PRIMARY KEY,
                                                     name TEXT,
                                                     email TEXT,
                                                     avatar TEXT
                )`);

        // 2. API Tokens 表
        db.run(`CREATE TABLE IF NOT EXISTS api_tokens (
                                                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                          token TEXT NOT NULL UNIQUE,
                                                          user_id TEXT NOT NULL,
                                                          name TEXT NOT NULL,
                                                          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                          usage_count INTEGER DEFAULT 0,
                                                          last_used_at DATETIME,
                                                          FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )`, (err) => {
            if (!err) {
                addColumn('api_tokens', 'usage_count', 'INTEGER DEFAULT 0');
                addColumn('api_tokens', 'last_used_at', 'DATETIME');
            }
        });

        // 3. API 使用日志表
        db.run(`CREATE TABLE IF NOT EXISTS usage_logs (
                                                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                          token_id INTEGER NOT NULL,
                                                          user_id TEXT NOT NULL,
                                                          character_used TEXT,
                                                          request_text TEXT,
                                                          request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                          status_code INTEGER,
                                                          FOREIGN KEY (token_id) REFERENCES api_tokens (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )`, (err) => {
            if (!err) {
                addColumn('usage_logs', 'request_text', 'TEXT');
            }
        });

        // 4. TTS 角色配置表 (包含最新字段)
        db.run(`CREATE TABLE IF NOT EXISTS characters (
                                                          id TEXT PRIMARY KEY,
                                                          name TEXT NOT NULL,
                                                          ref_audio_path TEXT,
                                                          prompt_text TEXT,
                                                          api_url TEXT NOT NULL,
                                                          enabled BOOLEAN DEFAULT TRUE,
                                                          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                          prompt_lang TEXT,
                                                          text_lang TEXT,
                                                          text_split_method TEXT
                )`, (err) => {
            if (!err) {
                addColumn('characters', 'prompt_lang', 'TEXT');
                addColumn('characters', 'text_lang', 'TEXT');
                addColumn('characters', 'text_split_method', 'TEXT');
            }
        });

        db.run(`CREATE TABLE IF NOT EXISTS frontend_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,                         -- 用户ID, 可以为空 (未登录用户)
        ip_address TEXT,                      -- 请求者IP地址
        request_text TEXT,                    -- 合成的文本
        character_used TEXT,                  -- 使用的角色
        status_message TEXT,                  -- 状态信息 ('Success' 或 错误信息)
        request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    )`);
    });
};

// 为 db 对象添加一个 .query 方法，使其支持 Promise (async/await)
db.query = function (sql, params) {
    return new Promise((resolve, reject) => {
        // 'this' 指代 db 对象本身
        this.all(sql, params, (err, rows) => {
            if (err) {
                console.error('DB Query Error:', err.message);
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
};

module.exports = { db, initDb };