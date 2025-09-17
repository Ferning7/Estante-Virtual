const express = require('express');
const session = require('express-session');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const server = express();
const porta = 3000;

const conexaoBanco = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'EstanteVirtual'
}).promise();

server.use(express.json());
server.use(express.static(path.join(__dirname, 'public')));
server.use(express.urlencoded({ extended: true }));

server.use(session({
    secret: 'senha123',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 3600000
    }
}));

const usuarioLogado = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('login.html');
    } else {
        next();
    }
};

const checkUsuarioLogado = (req, res, next) => {
    // Se a sessao do usuário não existir, ele não pode estar logado
    if (!req.session.user) {
        return res.redirect('/login.html');
    } else {
        // Se o usuário estiver logado, permite que a requisição continua.
        next();
    }
};

server.get('/', checkUsuarioLogado, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.get('/api/user', checkUsuarioLogado, (req, res) => {
    res.json({
        nome: req.session.user.nome,
        tipo: req.session.user.tipo
    });
});

server.post('/cadastrar', async (req, res) => {
    const { nome, email, senha, usuario } = req.body;

    try {
        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(senha, salt);

        const [rows] = await conexaoBanco.query(
            'SELECT * FROM usuarios WHERE email = ?',
            [email]
        );

        if (rows.length > 0) {
            return res.redirect('/cadastro.html?error=email_existente');
        } else {
            await conexaoBanco.query(
                'INSERT INTO usuarios (nome, email, senha, usuario) values (?, ?, ?, ?)',
                [nome, email, senhaHash, usuario]
            );
            res.redirect('/login.html');
        }
    } catch (error) {
        console.error('Erro ao cadastrar usuário', error);
        res.status(500).send('Erro no servidor ao tentar cadastrar usuário');
    }
});

server.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const [rows] = await conexaoBanco.query(
            'SELECT * FROM usuarios WHERE email = ? ',
            [email]
        );

        if (rows.length === 0) {
            console.log('Email ou senha incorretos');
            return res.redirect('/login.html?error=usuario_nao_encontrado');
        } else {
            const usuario = rows[0];
            const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

            if (senhaCorreta) {
                req.session.user = {
                    id: usuario.id,
                    nome: usuario.nome,
                    email: usuario.email,
                    tipo: usuario.tipo
                };

                console.log('Login bem sucedido');
                res.redirect('/');
            } else {
                console.log('Senha incorreta');
                res.redirect('/login.html?error=Senha_Incorreta');
            }
        }
    } catch (error) {
        console.error('Erro ao realizar login: ', error);
        res.status(500).send('Erro no servidor durante o login');
    }
});

server.get('/logout', (req, res) => {
    req.session.destroy(error => {
        if (error) {
            console.error('Erro ao fazer logout: ', error);
            return res.status(500).send('Não foi possível fazer logout.');
        } else {
            res.clearCookie('connect.sid');
            res.redirect('/login.html');
        }
    });
});

server.listen(porta, () => {
    console.log(`Servidor rodando na porta ${porta}`);
});
