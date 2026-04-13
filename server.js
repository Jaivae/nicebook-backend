// 导入必要的模块
const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const crypto = require("crypto");

// 初始化Express应用
const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, "nice-book.db");

// 初始化数据库和令牌存储
const db = new sqlite3.Database(DB_PATH);
const tokens = new Map();

// 中间件设置
app.use(cors());  //跨域资源共享
app.use(express.json());  //解析JSON请求体

// 数据库初始化：创建用户和书籍表
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS books (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      author TEXT NOT NULL,
      summary TEXT DEFAULT ''
    )
  `);
});

// 工具函数：密码哈希   
function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// 工具函数：生成随机令牌
function generateToken() {
  return crypto.randomBytes(24).toString("hex");
}

// 中间件：用户认证
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token || !tokens.has(token)) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  req.user = tokens.get(token);
  next();
}

// 路由：用户注册
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }

  const hashedPassword = hashPassword(password);
  const sql = "INSERT INTO users (username, password) VALUES (?, ?)";

  db.run(sql, [username.trim(), hashedPassword], function onInsert(error) {
    if (error) {
      if (error.message.includes("UNIQUE")) {
        return res.status(409).json({ message: "Username already exists." });
      }

      return res.status(500).json({ message: "Failed to register user." });
    }

    return res.status(201).json({
      message: "Registration successful.",
      user: { id: this.lastID, username: username.trim() }
    });
  });
});

// 路由：用户登录
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }

  const sql = "SELECT * FROM users WHERE username = ?";

  db.get(sql, [username.trim()], (error, user) => {
    if (error) {
      return res.status(500).json({ message: "Failed to login." });
    }

    if (!user || user.password !== hashPassword(password)) {
      return res.status(401).json({ message: "Invalid username or password." });
    }

    const token = generateToken();
    tokens.set(token, { id: user.id, username: user.username });

    return res.json({
      message: "Login successful.",
      token,
      user: { id: user.id, username: user.username }
    });
  });
});

// 路由：重置密码
app.post("/api/reset-password", (req, res) => {
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
    return res.status(400).json({ message: "Username and new password are required." });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ message: "New password must be at least 6 characters." });
  }

  const sql = "UPDATE users SET password = ? WHERE username = ?";
  const hashedPassword = hashPassword(newPassword);

  db.run(sql, [hashedPassword, username.trim()], function onReset(error) {
    if (error) {
      return res.status(500).json({ message: "Failed to reset password." });
    }

    if (this.changes === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    for (const [token, user] of tokens.entries()) {
      if (user.username === username.trim()) {
        tokens.delete(token);
      }
    }

    return res.json({ message: "Password reset successful. Please login again." });
  });
});

// 路由：获取所有书籍（需要认证）
app.get("/api/books", authenticate, (req, res) => {
  const sql = "SELECT id, title, author, summary FROM books ORDER BY id DESC";

  db.all(sql, [], (error, rows) => {
    if (error) {
      return res.status(500).json({ message: "Failed to fetch books." });
    }

    return res.json(rows);
  });
});

// 路由：创建新书籍（需要认证）
app.post("/api/books", authenticate, (req, res) => {
  const { title, author, summary } = req.body;

  if (!title || !author) {
    return res.status(400).json({ message: "Title and author are required." });
  }

  const sql = "INSERT INTO books (title, author, summary) VALUES (?, ?, ?)";

  db.run(sql, [title.trim(), author.trim(), summary || ""], function onInsert(error) {
    if (error) {
      return res.status(500).json({ message: "Failed to create book." });
    }

    return res.status(201).json({
      id: this.lastID,
      title: title.trim(),
      author: author.trim(),
      summary: summary || ""
    });
  });
});

// 路由：更新书籍（需要认证）
app.put("/api/books/:id", authenticate, (req, res) => {
  const { id } = req.params;
  const { title, author, summary } = req.body;

  if (!title || !author) {
    return res.status(400).json({ message: "Title and author are required." });
  }

  const sql = "UPDATE books SET title = ?, author = ?, summary = ? WHERE id = ?";

  db.run(sql, [title.trim(), author.trim(), summary || "", id], function onUpdate(error) {
    if (error) {
      return res.status(500).json({ message: "Failed to update book." });
    }

    if (this.changes === 0) {
      return res.status(404).json({ message: "Book not found." });
    }

    return res.json({
      id: Number(id),
      title: title.trim(),
      author: author.trim(),
      summary: summary || ""
    });
  });
});

// 路由：删除书籍（需要认证）
app.delete("/api/books/:id", authenticate, (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM books WHERE id = ?";

  db.run(sql, [id], function onDelete(error) {
    if (error) {
      return res.status(500).json({ message: "Failed to delete book." });
    }

    if (this.changes === 0) {
      return res.status(404).json({ message: "Book not found." });
    }

    return res.json({ message: "Book deleted successfully." });
  });
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`Nice Book backend is running at http://localhost:${PORT}`);
});
