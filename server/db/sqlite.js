const sqlite3 = require('sqlite3').verbose();
const path = require('path');

let db;

/**
 * 初始化并连接到 SQLite 数据库。
 * @returns {Promise<{db: object, initDb: function}>}
 */
function initialize() {
    return new Promise((resolve, reject) => {
        // 如果已连接，直接返回，防止重复初始化
        if (db) return resolve({ db, initDb });

        const dbPath = process.env.DB_SQLITE_PATH || path.join(__dirname, '../../database.sqlite');
        const database = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error('Error connecting to SQLite database.', err.message);
                reject(err);
            } else {
                console.log('Connected to the SQLite database.');
                db = database;

                /**
                 * Promise 封装的 .all() 方法 (用于 SELECT)
                 */
                db.query = function (sql, params = []) {
                    return new Promise((resolve, reject) => {
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

                /**
                 * Promise 封装的 .run() 方法 (用于 INSERT, UPDATE, DELETE)
                 */
                db.run_query = function (sql, params = []) {
                    return new Promise((resolve, reject) => {
                        this.run(sql, params, function (err) {
                            if (err) {
                                console.error('DB Run Error:', err.message);
                                reject(err);
                            } else {
                                resolve({ lastID: this.lastID, changes: this.changes });
                            }
                        });
                    });
                };

                initDb(); // 初始化表
                resolve({ db, initDb });
            }
        });
    });
}

const initDb = () => {
    db.serialize(() => {
        console.log("Checking and creating SQLite tables...");

        db.run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, email TEXT, avatar TEXT, enabled BOOLEAN DEFAULT TRUE)`);
        db.run(`CREATE TABLE IF NOT EXISTS characters (id TEXT PRIMARY KEY, name TEXT NOT NULL, ref_audio_path TEXT, prompt_text TEXT, api_url TEXT NOT NULL, enabled BOOLEAN DEFAULT TRUE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, prompt_lang TEXT, text_lang TEXT, text_split_method TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS api_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, usage_count INTEGER DEFAULT 0, last_used_at DATETIME, enabled BOOLEAN DEFAULT TRUE, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)`);
        db.run(`CREATE TABLE IF NOT EXISTS usage_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, token_id INTEGER NOT NULL, user_id TEXT NOT NULL, character_used TEXT, request_text TEXT, request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, status_code INTEGER, FOREIGN KEY (token_id) REFERENCES api_tokens (id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)`);
        db.run(`CREATE TABLE IF NOT EXISTS frontend_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ip_address TEXT, request_text TEXT, character_used TEXT, status_message TEXT, request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL)`);

        console.log("Checking and creating indexes for SQLite...");
        db.run(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON usage_logs (request_timestamp)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_logs_user_id ON usage_logs (user_id)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_logs_token_id ON usage_logs (token_id)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON api_tokens (user_id)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_frontend_logs_timestamp ON frontend_logs (request_timestamp)`);
    });
};

module.exports = initialize;