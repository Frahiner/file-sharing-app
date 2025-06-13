const fs = require('fs');
const path = require('path');
const { Server } = require('ssh2');
const crypto = require('crypto');

const SFTP_PORT = process.env.SFTP_PORT || 2222;
const SFTP_HOST = '0.0.0.0';

// Configuración de usuarios SFTP (en producción usar base de datos)
const sftpUsers = {
    'fileuser': {
        password: 'securepass123',
        homeDir: path.join(__dirname, 'sftp-uploads')
    }
};

// Crear directorio SFTP si no existe
if (!fs.existsSync(path.join(__dirname, 'sftp-uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'sftp-uploads'), { recursive: true });
}

const server = new Server({
    hostKeys: [fs.readFileSync(path.join(__dirname, 'host_key'))]
}, (client) => {
    console.log('Cliente SFTP conectado');
    
    client.on('authentication', (ctx) => {
        const user = sftpUsers[ctx.username];
        if (user && ctx.method === 'password' && ctx.password === user.password) {
            ctx.accept();
        } else {
            ctx.reject();
        }
    }).on('ready', () => {
        console.log('Cliente SFTP autenticado');
        
        client.on('session', (accept, reject) => {
            const session = accept();
            session.on('sftp', (accept, reject) => {
                const sftpStream = accept();
                console.log('Sesión SFTP iniciada');
                
                // Aquí puedes agregar más lógica SFTP según necesites
            });
        });
    });
});

// Generar clave host si no existe
const hostKeyPath = path.join(__dirname, 'host_key');
if (!fs.existsSync(hostKeyPath)) {
    const { generateKeyPairSync } = require('crypto');
    const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        }
    });
    fs.writeFileSync(hostKeyPath, privateKey);
    console.log('Clave host SFTP generada');
}

server.listen(SFTP_PORT, SFTP_HOST, () => {
    console.log(`Servidor SFTP ejecutándose en puerto ${SFTP_PORT}`);
});

module.exports = server;