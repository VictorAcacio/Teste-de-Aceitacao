// ============================================================
//  loginService.js – Sistema de Login (o que será testado)
// ============================================================

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const SECRET_KEY = "minha_chave_secreta_2024";

// Banco de dados simulado (em memória)
const users = [
  {
    id: 1,
    nome: "Ana Silva",
    email: "ana@email.com",
    // senha original: "Senha@123"
    senha: bcrypt.hashSync("Senha@123", 8),
    ativo: true,
  },
  {
    id: 2,
    nome: "Carlos Lima",
    email: "carlos@email.com",
    // senha original: "Carlos#456"
    senha: bcrypt.hashSync("Carlos#456", 8),
    ativo: false, // conta desativada
  },
];

// ── Validações básicas ─────────────────────────────────────

function validarCampos(email, senha) {
  if (!email || email.trim() === "") {
    return { valido: false, mensagem: "E-mail é obrigatório." };
  }
  if (!senha || senha.trim() === "") {
    return { valido: false, mensagem: "Senha é obrigatória." };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valido: false, mensagem: "Formato de e-mail inválido." };
  }
  return { valido: true };
}

// ── Função principal de login ──────────────────────────────

function login(email, senha) {
  // 1. Valida campos
  const validacao = validarCampos(email, senha);
  if (!validacao.valido) {
    return { sucesso: false, mensagem: validacao.mensagem, status: 400 };
  }

  // 2. Busca usuário
  const usuario = users.find((u) => u.email === email);
  if (!usuario) {
    return { sucesso: false, mensagem: "Usuário não encontrado.", status: 404 };
  }

  // 3. Verifica se conta está ativa
  if (!usuario.ativo) {
    return { sucesso: false, mensagem: "Conta desativada. Entre em contato com o suporte.", status: 403 };
  }

  // 4. Verifica senha
  const senhaCorreta = bcrypt.compareSync(senha, usuario.senha);
  if (!senhaCorreta) {
    return { sucesso: false, mensagem: "Senha incorreta.", status: 401 };
  }

  // 5. Gera token JWT
  const token = jwt.sign(
    { id: usuario.id, nome: usuario.nome, email: usuario.email },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  return {
    sucesso: true,
    mensagem: `Bem-vindo, ${usuario.nome}!`,
    token,
    usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email },
    status: 200,
  };
}

// ── Verificação de token ───────────────────────────────────

function verificarToken(token) {
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    return { valido: true, usuario: decoded };
  } catch {
    return { valido: false, mensagem: "Token inválido ou expirado." };
  }
}

module.exports = { login, verificarToken, validarCampos };
