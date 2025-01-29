require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// MySQL databsasen 'meldings_system'
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "2328",
  database: process.env.DB_NAME || "meldings_system",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}).promise();

// teste database-forbindelsen
pool.query("SELECT 1")
  .then(() => console.log("✅ Tilkoblet MySQL-databasen!"))
  .catch(err => console.error("❌ Feil ved tilkobling til MySQL:", err));

//  autentisering med Middleware
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "No acess" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Ugyldig token" });
    req.user = user;
    next();
  });
};

// ruter
app.get("/", (req, res) => {
  res.send("Meldingssystem API kjører");
});

// for å starte serveren
app.listen(port, () => {
  console.log(`🚀 Server kjører på http://localhost:${port}`);
});


// registrering av bruker 
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const [result] = await pool.execute(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, hashedPassword, role]
    );
    res.json({ userId: result.insertId });
  } catch (err) {
    res.status(500).json({ error: "Her må forklaring stå" });
  }
});


// innlogginsdelen
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(400).json({ error: "Bruker ikke funnet" });

    const user = rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Feil passord" });

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Her må forklaring stå" });
  }
});

// for studenter: sending av melding 
app.post("/messages", authenticateToken, async (req, res) => {
  const { subject_id, content } = req.body;

  try {
    const [result] = await pool.execute(
      "INSERT INTO messages (student_id, subject_id, content) VALUES (NULL, ?, ?)",
      [subject_id, content]
    );
    res.json({ messageId: result.insertId });
  } catch (err) {
    res.status(500).json({ error: "Her er forklaringen" });
  }
});


// for forelesere: sending av melding 
app.post("/replies", authenticateToken, async (req, res) => {
  if (req.user.role !== "foreleser") return res.status(403).json({ error: "No Acess" });

  const { message_id, content } = req.body;
  try {
    const [result] = await pool.execute(
      "INSERT INTO replies (message_id, teacher_id, content) VALUES (?, ?, ?)",
      [message_id, req.user.id, content]
    );
    res.json({ replyId: result.insertId });
  } catch (err) {
    res.status(500).json({ error: "Her er forklaringen" });
  }
});







