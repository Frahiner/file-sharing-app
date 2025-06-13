const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_muy_segura';

// Middleware de seguridad
app.use(helmet());
app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3001',
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100 // máximo 100 requests por IP cada 15 minutos
});
app.use(limiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Crear directorio de uploads si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configurar multer para subida de archivos
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDir = path.join(uploadsDir, req.user.id.toString());
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        cb(null, userDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB límite
    },
    fileFilter: function (req, file, cb) {
        // Filtrar tipos de archivo peligrosos
        const allowedTypes = /jpeg|jpg|png|gif|pdf|txt|doc|docx|xls|xlsx|zip|rar/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido'));
        }
    }
});

// Configurar base de datos SQLite
const db = new sqlite3.Database('./database.db');

// Crear tabla de usuarios si no existe
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        is_shared BOOLEAN DEFAULT FALSE,
        share_token TEXT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
});

// Middleware para verificar JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// Rutas de autenticación
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password || !email) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'Usuario o email ya existe' });
                    }
                    return res.status(500).json({ error: 'Error al crear usuario' });
                }
                
                const token = jwt.sign(
                    { id: this.lastID, username: username },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );
                
                res.status(201).json({
                    message: 'Usuario creado exitosamente',
                    token: token,
                    user: { id: this.lastID, username: username, email: email }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        db.get(
            'SELECT * FROM users WHERE username = ?',
            [username],
            async (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Error interno del servidor' });
                }
                
                if (!user) {
                    return res.status(401).json({ error: 'Credenciales inválidas' });
                }
                
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    return res.status(401).json({ error: 'Credenciales inválidas' });
                }
                
                const token = jwt.sign(
                    { id: user.id, username: user.username },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );
                
                res.json({
                    message: 'Login exitoso',
                    token: token,
                    user: { id: user.id, username: user.username, email: user.email }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Rutas de archivos
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se seleccionó archivo' });
        }
        
        db.run(
            `INSERT INTO files (user_id, filename, original_name, file_path, file_size, mime_type)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                req.user.id,
                req.file.filename,
                req.file.originalname,
                req.file.path,
                req.file.size,
                req.file.mimetype
            ],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Error al guardar archivo en base de datos' });
                }
                
                res.json({
                    message: 'Archivo subido exitosamente',
                    file: {
                        id: this.lastID,
                        filename: req.file.originalname,
                        size: req.file.size,
                        type: req.file.mimetype
                    }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Error al subir archivo' });
    }
});

app.get('/api/files', authenticateToken, (req, res) => {
    db.all(
        'SELECT id, filename, original_name, file_size, mime_type, is_shared, uploaded_at FROM files WHERE user_id = ?',
        [req.user.id],
        (err, files) => {
            if (err) {
                return res.status(500).json({ error: 'Error al obtener archivos' });
            }
            res.json(files);
        }
    );
});

app.get('/api/files/:id/download', authenticateToken, (req, res) => {
    const fileId = req.params.id;
    
    db.get(
        'SELECT * FROM files WHERE id = ? AND user_id = ?',
        [fileId, req.user.id],
        (err, file) => {
            if (err) {
                return res.status(500).json({ error: 'Error al buscar archivo' });
            }
            
            if (!file) {
                return res.status(404).json({ error: 'Archivo no encontrado' });
            }
            
            if (!fs.existsSync(file.file_path)) {
                return res.status(404).json({ error: 'Archivo físico no encontrado' });
            }
            
            res.download(file.file_path, file.original_name);
        }
    );
});

app.post('/api/files/:id/share', authenticateToken, (req, res) => {
    const fileId = req.params.id;
    const shareToken = jwt.sign({ fileId: fileId }, JWT_SECRET, { expiresIn: '7d' });
    
    db.run(
        'UPDATE files SET is_shared = TRUE, share_token = ? WHERE id = ? AND user_id = ?',
        [shareToken, fileId, req.user.id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Error al compartir archivo' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Archivo no encontrado' });
            }
            
            res.json({
                message: 'Archivo compartido exitosamente',
                shareUrl: `${req.protocol}://${req.get('host')}/api/shared/${shareToken}`
            });
        }
    );
});

app.get('/api/shared/:token', (req, res) => {
    const token = req.params.token;
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        db.get(
            'SELECT * FROM files WHERE id = ? AND is_shared = TRUE AND share_token = ?',
            [decoded.fileId, token],
            (err, file) => {
                if (err) {
                    return res.status(500).json({ error: 'Error al buscar archivo' });
                }
                
                if (!file) {
                    return res.status(404).json({ error: 'Archivo compartido no encontrado' });
                }
                
                if (!fs.existsSync(file.file_path)) {
                    return res.status(404).json({ error: 'Archivo físico no encontrado' });
                }
                
                res.download(file.file_path, file.original_name);
            }
        );
    } catch (error) {
        res.status(401).json({ error: 'Token de compartición inválido' });
    }
});

app.delete('/api/files/:id', authenticateToken, (req, res) => {
    const fileId = req.params.id;
    
    db.get(
        'SELECT * FROM files WHERE id = ? AND user_id = ?',
        [fileId, req.user.id],
        (err, file) => {
            if (err) {
                return res.status(500).json({ error: 'Error al buscar archivo' });
            }
            
            if (!file) {
                return res.status(404).json({ error: 'Archivo no encontrado' });
            }
            
            // Eliminar archivo físico
            if (fs.existsSync(file.file_path)) {
                fs.unlinkSync(file.file_path);
            }
            
            // Eliminar registro de base de datos
            db.run(
                'DELETE FROM files WHERE id = ?',
                [fileId],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Error al eliminar archivo' });
                    }
                    
                    res.json({ message: 'Archivo eliminado exitosamente' });
                }
            );
        }
    );
});

// Ruta de salud del servidor
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Servir archivos estáticos del cliente React en producción
if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, '../client/build')));
    
    app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, '../client/build', 'index.html'));
    });
}

// Inicializar servidor SFTP
if (process.env.ENABLE_SFTP !== 'false') {
    try {
        require('./sftp-server');
        console.log('Servidor SFTP inicializado');
    } catch (error) {
        console.log('SFTP no disponible:', error.message);
    }
}

app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en puerto ${PORT}`);
    console.log(`Modo: ${process.env.NODE_ENV || 'development'}`);
});