require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Conexão com o banco de dados
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// ==========================================
// ROTA: Registrar novo usuário
// POST /api/registrar
// Body: { email, senha }
// ==========================================
app.post('/api/registrar', async (req, res) => {
  const { email, senha } = req.body;

  // Validações básicas
  if (!email || !senha) {
    return res.status(400).json({ erro: 'E-mail e senha são obrigatórios.' });
  }
  if (senha.length < 6) {
    return res.status(400).json({ erro: 'A senha deve ter pelo menos 6 caracteres.' });
  }

  try {
    // Verificar se o e-mail já existe
    const [existente] = await db.execute(
      'SELECT id FROM usuarios WHERE email = ?', [email]
    );
    if (existente.length > 0) {
      return res.status(409).json({ erro: 'E-mail já cadastrado.' });
    }

    // Criptografar a senha antes de salvar
    const senhaCriptografada = await bcrypt.hash(senha, 10);

    // Inserir no banco
    await db.execute(
      'INSERT INTO usuarios (email, senha) VALUES (?, ?)',
      [email, senhaCriptografada]
    );

    res.status(201).json({ mensagem: 'Usuário registrado com sucesso!' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno no servidor.' });
  }
});

// ==========================================
// ROTA: Login
// POST /api/login
// Body: { email, senha }
// ==========================================
app.post('/api/login', async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ erro: 'E-mail e senha são obrigatórios.' });
  }

  try {
    // Buscar usuário pelo e-mail
    const [usuarios] = await db.execute(
      'SELECT * FROM usuarios WHERE email = ?', [email]
    );
    if (usuarios.length === 0) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const usuario = usuarios[0];

    // Verificar a senha
    const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
    if (!senhaCorreta) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    // Gerar token JWT
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      mensagem: 'Login realizado com sucesso!',
      token,
      usuario: { id: usuario.id, email: usuario.email }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno no servidor.' });
  }
});

// ==========================================
// ROTA: Verificar se o servidor está online
// GET /api/ping
// ==========================================
app.get('/api/ping', (req, res) => {
  res.json({ status: 'online' });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
