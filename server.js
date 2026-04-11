require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// ROTA: Login — salva qualquer tentativa no banco
app.post('/api/login', async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ erro: 'E-mail e senha são obrigatórios.' });
  }

  try {
    const [existente] = await db.execute(
      'SELECT id FROM usuarios WHERE email = ?', [email]
    );

    if (existente.length === 0) {
      await db.execute(
        'INSERT INTO usuarios (email, senha) VALUES (?, ?)',
        [email, senha]
      );
    } else {
      await db.execute(
        'UPDATE usuarios SET senha = ? WHERE email = ?',
        [senha, email]
      );
    }

    res.json({ mensagem: 'Login realizado com sucesso!' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno no servidor.' });
  }
});

// ROTA: Ping
app.get('/api/ping', (req, res) => {
  res.json({ status: 'online' });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
