// server.js
const express = require('express')
const session = require('express-session')
const path = require('path')
const mysql = require('mysql2')
const bcrypt = require('bcrypt')

const server = express()
const porta = process.env.PORT || 3000

const conexaoBanco = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'EstanteVirtual'
}).promise()

server.use(express.json())
server.use(express.urlencoded({ extended: true }))
server.use(express.static(path.join(__dirname, 'public')))

server.use(session({
    secret: 'senha123',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 3600000 }
}))

// middlewares
const checkUsuarioLogado = (req, res, next) => {
    if (!req.session.user) return res.redirect('/login.html')
    next()
}

const adminOnly = (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autenticado' })
    if (req.session.user.tipo !== 'administrador') return res.status(403).json({ error: 'Acesso não autorizado' })
    next()
}

// páginas
server.get('/', checkUsuarioLogado, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

server.get('/api/user', (req, res) => {
    if (!req.session.user) return res.json({ logged: false })
    res.json({ logged: true, nome: req.session.user.nome, tipo: req.session.user.tipo })
})

/* ----------------- AUTENTICAÇÃO & CADASTRO ----------------- */
server.post('/cadastrar', async (req, res) => {
    try {
        const { nome, email, senha, tipo } = req.body

        // validações básicas back-end
        if (!nome || !email || !senha || !tipo) {
            return res.redirect('/cadastro.html?error=campos_vazios')
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(email)) {
            return res.redirect('/cadastro.html?error=email_invalido')
        }
        if (!['usuario','administrador'].includes(tipo)) {
            return res.redirect('/cadastro.html?error=tipo_invalido')
        }

        // se for administrador, checar se já existe um
        if (tipo === 'administrador') {
            const [admins] = await conexaoBanco.query("SELECT id FROM usuarios WHERE tipo = 'administrador' LIMIT 1")
            if (admins.length > 0) {
                return res.redirect('/cadastro.html?error=admin_existente')
            }
        }

        // checar email
        const [rows] = await conexaoBanco.query('SELECT id FROM usuarios WHERE email = ?', [email])
        if (rows.length > 0) {
            return res.redirect('/cadastro.html?error=email_existente')
        }

        // hash da senha
        const salt = await bcrypt.genSalt(10)
        const senhaHash = await bcrypt.hash(senha, salt)

        await conexaoBanco.query('INSERT INTO usuarios (nome, email, senha, tipo) VALUES (?, ?, ?, ?)',
            [nome, email, senhaHash, tipo])

        res.redirect('/login.html?success=cadastrado')
    } catch (err) {
        console.error(err)
        res.status(500).send('Erro no servidor ao cadastrar')
    }
})

server.post('/login', async (req, res) => {
    try {
        const { email, senha } = req.body
        if (!email || !senha) return res.redirect('/login.html?error=campos_vazios')

        // procurar por email ou nome de usuário
        const [rows] = await conexaoBanco.query('SELECT * FROM usuarios WHERE email = ? OR nome = ?', [email, email])
        if (rows.length === 0) return res.redirect('/login.html?error=usuario_nao_encontrado')

        const usuario = rows[0]
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha)
        if (!senhaCorreta) return res.redirect('/login.html?error=senha_incorreta')

        req.session.user = { id: usuario.id, nome: usuario.nome, email: usuario.email, tipo: usuario.tipo }
        res.redirect('/')
    } catch (err) {
        console.error(err)
        res.status(500).send('Erro no servidor durante login')
    }
})

server.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Erro ao fazer logout')
        res.clearCookie('connect.sid')
        res.redirect('/login.html')
    })
})

/* ----------------- ROTAS API EXEMPLARES (CRUD) ----------------- */

// Listar todos (público para usuários logados)
server.get('/api/exemplares', checkUsuarioLogado, async (req, res) => {
    try {
        const [rows] = await conexaoBanco.query('SELECT id, titulo, autor, editora, ano_publicacao, genero, sinopse, capa_url FROM exemplares ORDER BY titulo')
        res.json(rows)
    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Erro ao buscar exemplares' })
    }
})

// Obter um exemplar por id
server.get('/api/exemplares/:id', checkUsuarioLogado, async (req, res) => {
    try {
        const { id } = req.params
        const [rows] = await conexaoBanco.query('SELECT * FROM exemplares WHERE id = ?', [id])
        if (rows.length === 0) return res.status(404).json({ error: 'Exemplar não encontrado' })
        res.json(rows[0])
    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Erro ao buscar exemplar' })
    }
})

// Criar exemplar (apenas admin)
server.post('/api/exemplares', adminOnly, async (req, res) => {
    try {
        const { titulo, autor, editora, ano_publicacao, genero, sinopse, capa_url } = req.body
        if (!titulo || !autor || !editora || !ano_publicacao || !genero || !sinopse || !capa_url) {
            return res.status(400).json({ error: 'Campos obrigatórios faltando' })
        }
        await conexaoBanco.query(
            'INSERT INTO exemplares (titulo, autor, editora, ano_publicacao, genero, sinopse, capa_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [titulo, autor, editora, ano_publicacao, genero, sinopse, capa_url]
        )
        res.status(201).json({ success: true })
    } catch (err) {
        console.error(err)
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Título já cadastrado' })
        res.status(500).json({ error: 'Erro ao cadastrar exemplar' })
    }
})

// Atualizar exemplar (apenas admin)
server.put('/api/exemplares/:id', adminOnly, async (req, res) => {
    try {
        const { id } = req.params
        const { titulo, autor, editora, ano_publicacao, genero, sinopse, capa_url } = req.body
        if (!titulo || !autor || !editora || !ano_publicacao || !genero || !sinopse || !capa_url) {
            return res.status(400).json({ error: 'Campos obrigatórios faltando' })
        }
        const [result] = await conexaoBanco.query(
            'UPDATE exemplares SET titulo=?, autor=?, editora=?, ano_publicacao=?, genero=?, sinopse=?, capa_url=? WHERE id=?',
            [titulo, autor, editora, ano_publicacao, genero, sinopse, capa_url, id]
        )
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Exemplar não encontrado' })
        res.json({ success: true })
    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Erro ao atualizar exemplar' })
    }
})

// Deletar exemplar (apenas admin)
server.delete('/api/exemplares/:id', adminOnly, async (req, res) => {
    try {
        const { id } = req.params
        const [result] = await conexaoBanco.query('DELETE FROM exemplares WHERE id = ?', [id])
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Exemplar não encontrado' })
        res.json({ success: true })
    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Erro ao excluir exemplar' })
    }
})

server.listen(porta, () => {
    console.log(`Servidor rodando na porta ${porta}`)
})
