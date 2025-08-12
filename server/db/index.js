const dbType = process.env.DB_TYPE || 'sqlite';

console.log(`Using database type: ${dbType}`);

if (dbType === 'mysql') {
    module.exports = require('./mysql');
} else {
    module.exports = require('./sqlite');
}