// ============================================================
//  login.test.js – Testes de Aceitação do Sistema de Login
//  Ferramenta: Jest  |  Sistema: Login com JWT
// ============================================================

const { login, verificarToken, validarCampos } = require("./src/loginService");

// ╔══════════════════════════════════════════════════════════╗
// ║   SUITE 1 – Validação de Campos (Regras de Negócio)     ║
// ╚══════════════════════════════════════════════════════════╝

describe("📋 SUITE 1 – Validação de Campos", () => {

  test("❌ CT-01 | Deve rejeitar e-mail vazio", () => {
    const resultado = login("", "Senha@123");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(400);
    expect(resultado.mensagem).toBe("E-mail é obrigatório.");
  });

  test("❌ CT-02 | Deve rejeitar senha vazia", () => {
    const resultado = login("ana@email.com", "");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(400);
    expect(resultado.mensagem).toBe("Senha é obrigatória.");
  });

  test("❌ CT-03 | Deve rejeitar e-mail com formato inválido", () => {
    const resultado = login("email-sem-arroba.com", "Senha@123");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(400);
    expect(resultado.mensagem).toBe("Formato de e-mail inválido.");
  });

  test("❌ CT-04 | Deve rejeitar ambos os campos vazios", () => {
    const resultado = login("", "");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(400);
  });

});

// ╔══════════════════════════════════════════════════════════╗
// ║   SUITE 2 – Autenticação (Fluxo Principal)              ║
// ╚══════════════════════════════════════════════════════════╝

describe("🔐 SUITE 2 – Autenticação", () => {

  test("✅ CT-05 | Deve fazer login com credenciais corretas", () => {
    const resultado = login("ana@email.com", "Senha@123");

    expect(resultado.sucesso).toBe(true);
    expect(resultado.status).toBe(200);
    expect(resultado.mensagem).toContain("Bem-vindo");
    expect(resultado.token).toBeDefined();          // token foi gerado
    expect(typeof resultado.token).toBe("string");  // token é uma string
  });

  test("❌ CT-06 | Deve rejeitar usuário que não existe", () => {
    const resultado = login("naoexiste@email.com", "qualquerSenha1");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(404);
    expect(resultado.mensagem).toBe("Usuário não encontrado.");
  });

  test("❌ CT-07 | Deve rejeitar senha incorreta", () => {
    const resultado = login("ana@email.com", "SenhaErrada99");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(401);
    expect(resultado.mensagem).toBe("Senha incorreta.");
  });

  test("❌ CT-08 | Deve bloquear conta desativada", () => {
    const resultado = login("carlos@email.com", "Carlos#456");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(403);
    expect(resultado.mensagem).toContain("desativada");
  });

  test("✅ CT-09 | Deve retornar dados do usuário após login", () => {
    const resultado = login("ana@email.com", "Senha@123");

    expect(resultado.usuario).toBeDefined();
    expect(resultado.usuario.nome).toBe("Ana Silva");
    expect(resultado.usuario.email).toBe("ana@email.com");
    // A senha NUNCA deve ser retornada!
    expect(resultado.usuario.senha).toBeUndefined();
  });

});

// ╔══════════════════════════════════════════════════════════╗
// ║   SUITE 3 – Token JWT (Segurança)                       ║
// ╚══════════════════════════════════════════════════════════╝

describe("🔑 SUITE 3 – Segurança do Token JWT", () => {

  test("✅ CT-10 | Token gerado deve ser válido", () => {
    const login_resultado = login("ana@email.com", "Senha@123");
    const { token } = login_resultado;

    const verificacao = verificarToken(token);

    expect(verificacao.valido).toBe(true);
    expect(verificacao.usuario.email).toBe("ana@email.com");
  });

  test("❌ CT-11 | Token adulterado deve ser rejeitado", () => {
    const tokenFalso = "eyJhbGciOiJIUzI1NiJ9.payload_adulterado.assinatura_invalida";

    const verificacao = verificarToken(tokenFalso);

    expect(verificacao.valido).toBe(false);
    expect(verificacao.mensagem).toBe("Token inválido ou expirado.");
  });

  test("❌ CT-12 | Token vazio deve ser rejeitado", () => {
    const verificacao = verificarToken("");

    expect(verificacao.valido).toBe(false);
  });

  test("✅ CT-13 | Token deve conter dados corretos do usuário", () => {
    const login_resultado = login("ana@email.com", "Senha@123");
    const verificacao = verificarToken(login_resultado.token);

    expect(verificacao.usuario.nome).toBe("Ana Silva");
    expect(verificacao.usuario.id).toBe(1);
    // Token não deve expor a senha
    expect(verificacao.usuario.senha).toBeUndefined();
  });

});

// ╔══════════════════════════════════════════════════════════╗
// ║   SUITE 4 – Casos de Borda (Edge Cases)                 ║
// ╚══════════════════════════════════════════════════════════╝

describe("⚠️  SUITE 4 – Casos de Borda", () => {

  test("❌ CT-14 | Deve ser case-sensitive no e-mail", () => {
    const resultado = login("ANA@EMAIL.COM", "Senha@123");

    // E-mail em maiúsculo não deve encontrar o usuário
    expect(resultado.sucesso).toBe(false);
  });

  test("❌ CT-15 | Deve tratar campo nulo como inválido", () => {
    const resultado = login(null, null);

    // E-mail e senha null nao deve encontrar o usuário
    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(400);
  });

  test("❌ CT-16 | Deve rejeitar senha com espaços em branco", () => {
    const resultado = login("ana@email.com", "   ");

    expect(resultado.sucesso).toBe(false);
    expect(resultado.status).toBe(400);
  });

});
