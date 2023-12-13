from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import sqlite3
import secrets
import hashlib
from fastapi.security import HTTPBasic,HTTPBearer,HTTPBasicCredentials, HTTPAuthorizationCredentials

app = FastAPI()

# Configuración CORS
origins = [
    "http://localhost:8080",
    "http://127.0.0.1:8000",
    "https://fron-token.onrender.com",
    #"https://contactos-frontend-6d58a4eb9f51.herokuapp.com",
    #"https://contactos-backen-b4d88f351253.herokuapp.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos
class Contacto(BaseModel):
    email: str
    nombre: str
    telefono: str

class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

security_basic = HTTPBasic()
security_bearer = HTTPBearer()

# Funciones de utilidad
def generate_token():
    return secrets.token_urlsafe(32)

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

# Función para obtener la conexión en cada solicitud
def get_db():
    db = sqlite3.connect("contactos.db")
    try:
        yield db
    finally:
        db.close()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security_bearer), conn: sqlite3.Connection = Depends(get_db)):
    usuario_token = credentials.credentials

    with conn:
        c = conn.cursor()
        c.execute("SELECT token FROM usuarios WHERE token = ?", (usuario_token,))
        result = c.fetchone()

    if result and usuario_token == result[0]:
        return True
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")

# Rutas para las operaciones CRUD

@app.get('/')
def root():
    return {"Esto es mas dificil de lo que creía"}

@app.post("/contactos")
def crear_contacto(contacto: Contacto, is_valid_token: bool = Depends(verify_token), conn: sqlite3.Connection = Depends(get_db)):
    # Verifica si el token es válido antes de insertar el contacto
    if is_valid_token:
        with conn:
            c = conn.cursor()
            c.execute('INSERT INTO contactos (email, nombre, telefono) VALUES (?, ?, ?)',
                      (contacto.email, contacto.nombre, contacto.telefono))
            conn.commit()
        return {"message": "Contacto insertado"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")

@app.get("/contactos")
def obtener_contactos(is_valid_token: bool = Depends(verify_token), conn: sqlite3.Connection = Depends(get_db)):
    """Obtiene todos los contactos."""
    # Verifica si el token es válido antes de obtener los contactos
    if is_valid_token:
        with conn:
            c = conn.cursor()
            c.execute('SELECT * FROM contactos')
            response = [{"email": row[0], "nombre": row[1], "telefono": row[2]} for row in c.fetchall()]
        return response
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")


@app.get("/contactos/{email}")
def obtener_contacto(email: str, is_valid_token: bool = Depends(verify_token), conn: sqlite3.Connection = Depends(get_db)):
    """Obtiene un contacto por su email."""
    # Verifica si el token es válido antes de consultar el contacto
    if is_valid_token:
        with conn:
            c = conn.cursor()
            c.execute('SELECT * FROM contactos WHERE email = ?', (email,))
            row = c.fetchone()
        if row:
            contacto = {"email": row[0], "nombre": row[1], "telefono": row[2]}
            return JSONResponse(content=contacto)
        else:
            return JSONResponse(content={}, status_code=404)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")

@app.put("/contactos/{email}")
def actualizar_contacto(email: str, contacto: Contacto, is_valid_token: bool = Depends(verify_token), conn: sqlite3.Connection = Depends(get_db)):
    """Actualiza un contacto."""
    # Verifica si el token es válido antes de actualizar el contacto
    if is_valid_token:
        try:
            with conn:
                c = conn.cursor()
                c.execute('UPDATE contactos SET nombre = ?, telefono = ? WHERE email = ?',
                          (contacto.nombre, contacto.telefono, email))
                conn.commit()

                if c.rowcount == 0:
                    raise HTTPException(status_code=404, detail="Contacto no encontrado")

            return contacto
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")

@app.delete("/contactos/{email}")
def eliminar_contacto(email: str, is_valid_token: bool = Depends(verify_token), conn: sqlite3.Connection = Depends(get_db)):
    """Elimina un contacto."""
    # Verifica si el token es válido antes de eliminar el contacto
    if is_valid_token:
        with conn:
            c = conn.cursor()
            c.execute('DELETE FROM contactos WHERE email = ?', (email,))
            conn.commit()
        return {"elemento borrado"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


@app.get("/root")
def verifica_token(credentials: HTTPAuthorizationCredentials = Depends(security_bearer), conn: sqlite3.Connection = Depends(get_db)):
    usuario_token = credentials.credentials

    with conn:
        c = conn.cursor()
        c.execute("SELECT token FROM usuarios WHERE token = ?", (usuario_token,))
        result = c.fetchone()

    if result and usuario_token == result[0]:
        return {"message": "TOKEN válido"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="TOKEN no válido")

@app.post("/token")
def obtener_token(credentials: HTTPBasicCredentials = Depends(security_basic), conn: sqlite3.Connection = Depends(get_db)):
    username = credentials.username
    password = credentials.password

    hashed_password = hash_password(password)

    with conn:
        c = conn.cursor()
        c.execute("SELECT token FROM usuarios WHERE username = ? AND password = ?", (username, hashed_password))
        result = c.fetchone()

        if result:
            existing_token = result[0]
            if existing_token:
                return {"access_token": existing_token, "token_type": "bearer"}
            else:
                # En este punto, las credenciales son correctas y aún no hay un token asociado
                new_token = generate_token()
                c.execute("UPDATE usuarios SET token = ? WHERE username = ?", (new_token, username))
                conn.commit()
                return {"access_token": new_token, "token_type": "bearer"}
        else:
            raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

@app.post("/register")
def registrar_paratoken(user: User, conn: sqlite3.Connection = Depends(get_db)):
    username = user.username
    password = user.password

    token = generate_token()
    hashed_password = hash_password(password)

    with conn:
        c = conn.cursor()
        c.execute("INSERT INTO usuarios (username, password, token) VALUES (?, ?, ?)", (username, hashed_password, token))
        conn.commit()

    return {"message": "Usuario registrado", "token": token}
