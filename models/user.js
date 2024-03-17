const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const res = require("express/lib/response");
const db = new sqlite3.Database("test.sqlite");

const sql =
  "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL, age INT NOT NULL, isAdmin INTEGER DEFAULT 0  )";

db.run(sql);

const query = "SELECT * FROM users WHERE name = ?";

db.get(query, (err, user) => {
  if (err) {
    console.error(err);
    return;
  }
  if (user) {
    const updateQuery = "UPDATE users SET isAdmin = ? WHERE id = ?";
    db.run(updateQuery);
  }
});
class User {
  static async create(dataForm, cb) {
    try {
      const sql =
        "INSERT INTO users (name, email, password, age) VALUES (?, ?, ?, ?)";
      db.run(
        sql,
        dataForm.name,
        dataForm.email,
        dataForm.password,
        dataForm.age,
        cb
      );
    } catch (err) {
      if (err) {
        logger.error("Ошибка создания пользователя");
        console.error("Ошибка создания пользователя");
        return cb(err);
      }
    }
  }

  static findByEmail(email, cb) {
    db.get("SELECT * FROM users WHERE email = ?", email, cb);
  }

  static authenticate(dataForm, cb) {
    User.findByEmail(dataForm.email, (error, user) => {
      if (error) return cb(error);
      if (!user) return cb();
      if (dataForm.password === user.password) {
        return cb(null, user);
      } else {
        return cb();
      }
    });
  }
}

module.exports = User;
