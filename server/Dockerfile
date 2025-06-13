FROM node:18-alpine

# Creamos el directorio de la aplicación
WORKDIR /app

# Primero copiamos los package*.json
# así podemos instalar sin que el caché falle si el resto de la aplicación cambia
COPY package*.json .

# Instalamos las dependencias en el contenedor
# Utilizamos --build-from-source si tienes módulos nativos como sqlite3
RUN npm install --build-from-source

# Después copiamos el resto de la aplicación
COPY . .

# Exponemos el puerto en el que corre tu aplicación
EXPOSE 3000

# Arrancamos tu aplicación
CMD ["npm", "start"]
