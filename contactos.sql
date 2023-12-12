-- Crear la tabla de contactos
CREATE TABLE  IF NOT EXISTS contactos (
    email TEXT PRIMARY KEY,
    nombre TEXT,
    telefono TEXT
);

-- Insertar datos de ejemplo
INSERT INTO contactos (email, nombre, telefono)
VALUES ('juan@example.com', 'Juan Pérez', '555-123-4567');

INSERT INTO contactos (email, nombre, telefono)
VALUES ('maria@example.com', 'María García', '555-678-9012');



--tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    username VARCHAR(30) NOT NULL,
    password VARCHAR(20) NOT NULL,
    token VARCHAR(32) UNIQUE,
    TIMESTAMP DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO usuarios (username, password, token) VALUES ('usuario@gmail.com', '1234', 'yyyy');

