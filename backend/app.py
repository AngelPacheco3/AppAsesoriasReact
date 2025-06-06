from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
#from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from sqlalchemy import case
import os
import logging
from flask_cors import CORS
from bleach import clean
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from argon2 import PasswordHasher, exceptions as argon2_exceptions
# Agregar estas líneas después de las importaciones existentes
from werkzeug.utils import secure_filename
from flask import abort 
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps

# Configuración de la aplicación
# Para la prevencion de inyeccopnes SQL/JS ya teniamos SQLAlchemy que previene de inyecciones SQL y Flask-Login
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///asesorias.db'
app.config['SECRET_KEY'] = 'tu_clave_secreta'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['WTF_CSRF_ENABLED'] = True
app.config['JWT_SECRET_KEY'] = 'tu-clave-secreta-jwt-super-segura'  # Cambiar en producción
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Token válido por 24 horas
app.config['JWT_ALGORITHM'] = 'HS256'


# Se uso SESSION_COOKIE_SAMESITE para prevenir ataques CSRF y XSS, y SESSION_COOKIE_HTTPONLY para prevenir acceso a cookies desde JavaScript.

# Hash de contraseñas
ph = PasswordHasher()

# Si además deseas activar CSRF en la app:
csrf = CSRFProtect(app)

# Configuración específica para las imágenes (modificada)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB máximo

# Crear directorio de uploads si no existe
# Por esto:
import os
from flask import send_from_directory

# Configuración relativa y portable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Directorio del archivo Flask
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')  # Nueva carpeta para imágenes

# Crear directorio si no existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Inicializar extensiones
db = SQLAlchemy(app)
migrate = Migrate(app, db)
#login_manager = LoginManager(app)
CORS(app, supports_credentials=True)

@app.after_request
def set_security_headers(response):
    """
    Agrega encabezados de seguridad HTTP a todas las respuestas
    para proteger contra diversos tipos de ataques web.
    """
    
    # 1. Previene que la página sea embebida en frames (protege contra clickjacking)
    response.headers['X-Frame-Options'] = 'DENY'
    
    # 2. Previene que el navegador detecte automáticamente el tipo de contenido
    # (protege contra ataques MIME-type sniffing)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # 3. Habilita el filtro XSS del navegador (legacy, pero útil para navegadores antiguos)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # 4. Controla qué información se envía en el header Referer
    # 'strict-origin-when-cross-origin' envía el origen completo solo en mismo origen
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # 5. Content Security Policy - Controla qué recursos puede cargar la página
    # Esta es una política básica que permite recursos del mismo origen
    csp = (
        "default-src 'self'; "  # Por defecto, solo recursos del mismo origen
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com; "  # Scripts
        "style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com; "  # Estilos
        "font-src 'self' https://cdnjs.cloudflare.com; "  # Fuentes
        "img-src 'self' data: https: blob:; "  # Imágenes
        "connect-src 'self' http://localhost:* ws://localhost:*; "  # Conexiones AJAX/WebSocket
        "frame-ancestors 'none'; "  # Previene embedding
        "form-action 'self'; "  # Formularios solo al mismo origen
        "base-uri 'self';"  # Restricción de <base> tag
    )
    response.headers['Content-Security-Policy'] = csp
    
    # 6. Permissions Policy (antes Feature Policy) - Controla qué APIs del navegador puede usar
    permissions = (
        "accelerometer=(), "  # Desactiva acceso al acelerómetro
        "camera=(), "  # Desactiva acceso a la cámara
        "geolocation=(), "  # Desactiva geolocalización
        "microphone=(), "  # Desactiva micrófono
        "payment=(), "  # Desactiva API de pagos
        "usb=()"  # Desactiva acceso USB
    )
    response.headers['Permissions-Policy'] = permissions
    
    # 7. SOLO para producción con HTTPS (comentado para desarrollo local)
    # Descomenta esta línea cuando uses HTTPS en producción:
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # 8. Previene que el navegador haga MIME sniffing en las descargas
    response.headers['X-Download-Options'] = 'noopen'
    
    # 9. DNS Prefetch Control - Controla cuándo el navegador hace prefetch de DNS
    response.headers['X-DNS-Prefetch-Control'] = 'off'
    
    # 10. Previene que Adobe products abran el sitio
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    
    return response

# MODELOS
asesoria_alumno = db.Table('asesoria_alumno',
    db.Column('asesoria_id', db.Integer, db.ForeignKey('asesoria.id'), primary_key=True),
    db.Column('alumno_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(10), nullable=False)
    especializacion = db.Column(db.String(200), nullable=True)
    foto = db.Column(db.String(200), nullable=True)
    edad = db.Column(db.Integer, nullable=True)
    nivel = db.Column(db.String(50), nullable=True)
    asesorias = db.relationship('Asesoria', secondary=asesoria_alumno, back_populates='alumnos')

class Asesoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String(200), nullable=False)
    costo = db.Column(db.Float, nullable=False)
    max_alumnos = db.Column(db.Integer, nullable=False)
    temas = db.Column(db.String(200), nullable=False)
    maestro_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    alumnos = db.relationship('User', secondary=asesoria_alumno, back_populates='asesorias')
    total_pagado = db.Column(db.Float, default=0.0)
    meet_link = db.Column(db.String(200), nullable=True)

class RegistroAsesoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asesoria_id = db.Column(db.Integer, db.ForeignKey('asesoria.id'), nullable=False)
    alumno_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pagado = db.Column(db.Boolean, default=False)
    asesoria = db.relationship('Asesoria', backref=db.backref('registros', lazy=True))
    alumno = db.relationship('User', backref=db.backref('registro_asesorias', lazy=True))
# Ruta para servir archivos estáticos (fotos de perfil)

def generate_jwt_token(user):
    """Genera un token JWT para el usuario"""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'rol': user.rol,
        'nombre': user.nombre,
        'exp': datetime.now(timezone.utc) + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        'iat': datetime.now(timezone.utc)
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])
    return token

def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):  # ← IMPORTANTE:args, kwargs
        token = None

#Buscar token en headers,
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Formato esperado: "Bearer <token>"
                parts = auth_header.split(' ')
                if len(parts) == 2 and parts[0] == 'Bearer':
                    token = parts[1]
                else:
                    return jsonify({'error': 'Token format invalid. Use: Bearer <token>'}), 401
            except Exception as e:
                return jsonify({'error': 'Token format error'}), 401

        if not token:
            return jsonify({'error': 'Token missing. Authorization header required'}), 401

        try:
            # Decodificar token
            payload = jwt.decode(
                token, 
                app.config['JWT_SECRET_KEY'], 
                algorithms=[app.config['JWT_ALGORITHM']]
            )

#Obtener usuario de la DB,
            user = User.query.get(payload['user_id'])
            if not user:
                return jsonify({'error': 'User not found'}), 401

#Pasar usuario a la función a través del request,
            request.current_user = user

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired', 'code': 'TOKEN_EXPIRED'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
        except Exception as e:
            app.logger.error(f"JWT Error: {str(e)}")
            return jsonify({'error': 'Token validation error'}), 401

#Llamar a la función original con sus argumentos,
        return f(*args, **kwargs)  # ← IMPORTANTE: pasar los argumentos

    return decorated_function

@app.route('/images/<path:filename>')
def serve_image(filename):
    try:
        # Limpiar el nombre del archivo
        clean_filename = secure_filename(filename)
        
        # Verificar que el archivo existe
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], clean_filename)
        if not os.path.exists(file_path):
            app.logger.error(f"Archivo no encontrado: {clean_filename}")
            abort(404)
            
        return send_from_directory(app.config['UPLOAD_FOLDER'], clean_filename)
    except Exception as e:
        app.logger.error(f"Error al servir imagen: {str(e)}")
        abort(500)

# Función para verificar extensiones permitidas
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

#Login y registro de usuarios
#Se verifica que exista el usuario.
#Luego, en el bloque try/except, se usa ph.verify(user.password, password) para comparar la contraseña ingresada contra el hash almacenado.
#Si la verificación falla, se retorna un error.
#En caso exitoso, se continúa con el login habitual.
# ACTUALIZAR la ruta de login para devolver JWT
@app.route('/api/login', methods=['POST'])
def login_api():
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        if not data:
            return jsonify({"error": "Datos no proporcionados"}), 400
        
        email = data.get('email', '').strip()
        password = data.get('password', '')
        if not email or not password:
            return jsonify({"error": "Correo y contraseña son requeridos"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            app.logger.info(f"Login fallido: usuario {email} no existe")
            return jsonify({"error": "Credenciales inválidas"}), 401

        try:
            ph.verify(user.password_hash, password)
            if ph.check_needs_rehash(user.password_hash):
                user.password_hash = ph.hash(password)
                db.session.commit()
                app.logger.info(f"Contraseña actualizada para {email}")
        except argon2_exceptions.VerifyMismatchError:
            app.logger.info(f"Contraseña incorrecta para {email}")
            return jsonify({"error": "Credenciales inválidas"}), 401
        except argon2_exceptions.VerificationError as e:
            app.logger.error(f"Error de verificación: {str(e)}")
            return jsonify({"error": "Error en la verificación de credenciales"}), 500

        # NUEVO: Generar token JWT en lugar de usar login_user()
        token = generate_jwt_token(user)
        
        if user.rol == 'alumno':
            redirect_url = "/api/dashboard_alumno"
        elif user.rol == 'maestro':
            redirect_url = "/api/dashboard_maestro"
        else:
            redirect_url = "/"
            
        return jsonify({
            "message": "Inicio de sesión exitoso",
            "redirect": redirect_url,
            "token": token,  # NUEVO: Enviar el token
            "user": {
                "id": user.id,
                "nombre": user.nombre,
                "email": user.email,
                "rol": user.rol
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({"error": "Error en el servidor"}), 500

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

@app.route('/api/logout', methods=['POST'])
@jwt_required  # Cambiado de @login_required
def logout_api():
    # Con JWT, el logout se maneja en el cliente eliminando el token
    return jsonify({"message": "Sesión cerrada correctamente"})

@app.route('/api/verify-token', methods=['GET'])
@jwt_required
def verify_token():
    """Verifica si el token es válido y devuelve info del usuario"""
    user = request.current_user
    return jsonify({
        "valid": True,
        "user": {
            "id": user.id,
            "nombre": user.nombre,
            "email": user.email,
            "rol": user.rol
        }
    })

# Modificación del endpoint de registro de maestro
# Después de obtener los datos con data = request.form.to_dict(), usamos clean() de Bleach para eliminar cualquier etiqueta o script potencialmente malicioso de los campos nombre, email, especializacion y nivel.
@app.route('/api/registro_maestro', methods=['POST'])
def registro_maestro_api():
    try:
        # Para el registro de maestro con archivo, se asume el envío en multipart/form-data:
        data = request.get_json() if request.is_json else request.form.to_dict()
        if not data:
            return jsonify({"error": "Datos no proporcionados"}), 400
        
        # Validación básica de campos
        required_fields = ['nombre', 'email', 'password', 'confirm_password']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Faltan campos requeridos"}), 400

        # Sanitización
        nombre = clean(data.get('nombre', ''), strip=True)
        email = clean(data.get('email', ''), strip=True)
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')

        if password != confirm_password:
            return jsonify({"error": "Las contraseñas no coinciden"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"error": "El correo ya está registrado"}), 409

        # Crear hash de contraseña con Argon2
        hashed_password = ph.hash(password)

        # Crear nuevo maestro
        nuevo_maestro = User(
            nombre=nombre,
            email=email,
            password_hash=hashed_password,
            rol='maestro',
            especializacion=clean(data.get('especializacion', ''), strip=True),
            edad=int(data.get('edad', 0)) if data.get('edad', '').isdigit() else None,
            nivel=clean(data.get('nivel', ''), strip=True)
        )
        
        # Manejo del archivo, si está enviado
        foto_filename = None
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                safe_email = email.split('@')[0].replace('.', '_')
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{safe_email}_profile.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                foto_filename = filename
                nuevo_maestro.foto = foto_filename

        db.session.add(nuevo_maestro)
        db.session.commit()
        
        app.logger.info(f"Maestro registrado: {email}")
        return jsonify({
            "message": "Maestro registrado con éxito",
            "redirect": "/api/login"
        })
        
    except IntegrityError as e:
        db.session.rollback()
        app.logger.error(f"Error de integridad en registro: {str(e)}")
        return jsonify({"error": "Error en la base de datos"}), 500
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error en registro maestro: {str(e)}")
        app.logger.info(f"Request content type: {request.content_type}, data: {data}")
        return jsonify({"error": "Error en el servidor"}), 500


# Asegúrate de tener esta ruta en tu Flask app
# Después de obtener los datos con data = request.form.to_dict(), usamos clean() de Bleach para eliminar cualquier etiqueta o script potencialmente malicioso de los campos nombre, email, especializacion y nivel.
@app.route('/api/registro_alumno', methods=['POST'])
def registro_alumno_api():
    try:
        # Aceptar datos en JSON o form-data:
        data = request.get_json() if request.is_json else request.form.to_dict()
        if not data:
            return jsonify({"error": "Datos no proporcionados"}), 400
        
        required_fields = ['nombre', 'email', 'password', 'confirm_password']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Faltan campos requeridos"}), 400
        
        nombre = clean(data.get('nombre', ''), strip=True)
        email = clean(data.get('email', ''), strip=True)
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        if password != confirm_password:
            return jsonify({"error": "Las contraseñas no coinciden"}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "El correo ya está registrado"}), 409

        password_hash = ph.hash(password)
        nuevo_alumno = User(
            nombre=nombre,
            email=email,
            password_hash=password_hash,  # Guarda el hash en el campo password_hash
            rol='alumno'
        )
        
        db.session.add(nuevo_alumno)
        db.session.commit()
        app.logger.info(f"Alumno registrado: {email}")
        
        return jsonify({
            "message": "Alumno registrado con éxito",
            "redirect": "/api/login"
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error en registro alumno: {str(e)}")
        app.logger.info(f"Request content type: {request.content_type}, data: {data}")
        return jsonify({"error": "Error en el servidor"}), 500


@app.route('/api/dashboard_maestro')
@jwt_required  # Cambiado de @login_required
def dashboard_maestro_api():
    current_user = request.current_user  # NUEVO: obtener usuario del request
    asesorias = Asesoria.query.filter_by(maestro_id=current_user.id).all()
    asesorias_data = []
    for a in asesorias:
        registrados = RegistroAsesoria.query.filter_by(asesoria_id=a.id, pagado=True).count()
        total_pagado = db.session.query(
            db.func.sum(
                case((RegistroAsesoria.pagado == True, a.costo), else_=0.0)
            )
        ).filter(RegistroAsesoria.asesoria_id == a.id).scalar() or 0.0
        asesorias_data.append({
            "id": a.id,
            "descripcion": a.descripcion,
            "costo": a.costo,
            "max_alumnos": a.max_alumnos,
            "temas": a.temas,
            "meet_link": a.meet_link,
            "registrados": registrados,
            "total_pagado": total_pagado
        })
    return jsonify({"asesorias": asesorias_data})

@app.route('/api/dashboard_alumno')
@jwt_required  # Cambiado de @login_required
def dashboard_alumno_api():
    current_user = request.current_user  # NUEVO: obtener usuario del request
    results = db.session.query(Asesoria, User).join(User, Asesoria.maestro_id == User.id).all()
    data = []
    for a, m in results:
        data.append({
            "id": a.id,
            "descripcion": a.descripcion,
            "costo": a.costo,
            "max_alumnos": a.max_alumnos,
            "temas": a.temas,
            "meet_link": a.meet_link,
            "maestro": {
                "id": m.id,
                "nombre": m.nombre,
                "email": m.email
            }
        })
    return jsonify({"asesorias": data})

# Registro y pago de asesorías

@app.route('/api/validar_registro/<int:id>', methods=['POST'])
@jwt_required  # Cambiado de @login_required
def validar_registro_api(id):
    current_user = request.current_user  # NUEVO
    asesoria = Asesoria.query.get_or_404(id)
    if current_user in asesoria.alumnos:
        return jsonify({"error": "Ya estás registrado en esta asesoría."}), 400
    asesoria.alumnos.append(current_user)
    asesoria.total_pagado += asesoria.costo
    db.session.commit()
    return jsonify({"message": "Te has registrado en la asesoría con éxito.", "redirect": f"/api/ver_asesoria/{asesoria.id}"})

@app.route('/api/pago_asesoria/<int:id>', methods=['POST'])
@jwt_required  # Cambiado de @login_required
def pago_asesoria_api(id):
    current_user = request.current_user  # NUEVO
    asesoria = Asesoria.query.get_or_404(id)
    data = request.get_json() if request.is_json else request.form.to_dict()
    csrf_token = data.get('csrfToken')
    try:
        validate_csrf(csrf_token)
    except Exception as e:
        return jsonify({"error": "Invalid CSRF token."}), 403

    nombre = data.get('nombre')
    tarjeta = data.get('tarjeta')
    vencimiento = data.get('vencimiento')
    cvv = data.get('cvv')
    celular = data.get('celular')
    if not all([nombre, tarjeta, vencimiento, cvv, celular]):
        return jsonify({"error": "Todos los campos son obligatorios."}), 400
    registro = RegistroAsesoria.query.filter_by(asesoria_id=asesoria.id, alumno_id=current_user.id).first()
    if not registro:
        registro = RegistroAsesoria(asesoria_id=asesoria.id, alumno_id=current_user.id, pagado=False)
        db.session.add(registro)
    registro.pagado = True
    asesoria.total_pagado += asesoria.costo
    db.session.commit()
    return jsonify({"message": "Pago realizado y te has registrado en la asesoría con éxito.", "redirect": f"/api/ver_asesoria/{asesoria.id}"})

@app.route('/api/procesar_pago/<int:id>', methods=['POST'])
@jwt_required  # Cambiado de @login_required
def procesar_pago_api(id):
    current_user = request.current_user  # NUEVO
    asesoria = Asesoria.query.get_or_404(id)
    data = request.get_json() if request.is_json else request.form.to_dict()
    csrf_token = data.get('csrfToken')
    try:
        validate_csrf(csrf_token)
    except Exception as e:
        return jsonify({"error": "Invalid CSRF token."}), 403

    nombre = data.get('nombre')
    tarjeta = data.get('tarjeta')
    vencimiento = data.get('vencimiento')
    cvv = data.get('cvv')
    celular = data.get('celular')
    if not all([nombre, tarjeta, vencimiento, cvv, celular]):
        return jsonify({"error": "Todos los campos son obligatorios."}), 400
    registro = RegistroAsesoria.query.filter_by(asesoria_id=asesoria.id, alumno_id=current_user.id).first()
    if not registro:
        registro = RegistroAsesoria(asesoria_id=asesoria.id, alumno_id=current_user.id, pagado=False)
        db.session.add(registro)
    registro.pagado = True
    db.session.commit()
    return jsonify({"message": "Pago realizado y te has registrado en la asesoría con éxito.", "redirect": f"/api/ver_asesoria/{asesoria.id}"})

# Ruta para crear una nueva asesoría
# Después de obtener los datos con data = request.form.to_dict(), usamos clean() de Bleach para eliminar cualquier etiqueta o script potencialmente malicioso de los campos nombre, email, especializacion y nivel.
@app.route('/api/nueva_asesoria', methods=['POST'])
@jwt_required  # Cambiado de @login_required
def nueva_asesoria_api():
    current_user = request.current_user  # NUEVO
    data = request.get_json() if request.is_json else request.form.to_dict()
    
    # Sanitizar campos de texto
    data['descripcion'] = clean(data.get('descripcion', ''), strip=True)
    data['temas'] = clean(data.get('temas', ''), strip=True)
    
    nueva_asesoria = Asesoria(
        descripcion=data['descripcion'],
        costo=data.get('costo'),
        max_alumnos=data.get('max_alumnos'),
        temas=data['temas'],
        maestro_id=current_user.id,
        meet_link=data.get('meet_link')
    )
    db.session.add(nueva_asesoria)
    db.session.commit()
    return jsonify({"message": "Asesoría creada con éxito.", "redirect": "/api/dashboard_maestro"})

# Ruta para registrar a un alumno en una asesoría
@app.route('/api/registrar_asesoria/<int:id>', methods=['POST'])
@jwt_required  # Cambiado de @login_required
def registrar_asesoria_api(id):
    current_user = request.current_user  # NUEVO
    asesoria = Asesoria.query.get_or_404(id)

    # Verificar si la asesoría ya alcanzó el límite de alumnos
    if len(asesoria.registros) >= asesoria.max_alumnos:
        return jsonify({"error": "La asesoría ya alcanzó el máximo de alumnos."}), 400

    # Buscar si el alumno ya está registrado
    registro = RegistroAsesoria.query.filter_by(asesoria_id=asesoria.id, alumno_id=current_user.id).first()
    if registro:
        return jsonify({"error": "Ya estás registrado en esta asesoría."}), 400

    # Registrar al alumno correctamente
    nuevo_registro = RegistroAsesoria(asesoria_id=asesoria.id, alumno_id=current_user.id, pagado=False)
    db.session.add(nuevo_registro)
    db.session.commit()

    # Actualizar la relación para reflejar la inscripción
    db.session.refresh(asesoria)

    return jsonify({"message": "Te has registrado en la asesoría con éxito.", "redirect": f"/api/ver_asesoria/{asesoria.id}"})

# Ruta para ver los detalles de una asesoría
@app.route('/api/ver_asesoria/<int:id>', methods=['GET'])
@jwt_required  # Cambiado de @login_required
def ver_asesoria_api(id):
    current_user = request.current_user  # NUEVO
    asesoria = Asesoria.query.get_or_404(id)
    maestro = User.query.get(asesoria.maestro_id)
    alumnos = db.session.query(User).join(RegistroAsesoria)\
        .filter(RegistroAsesoria.asesoria_id == asesoria.id).all()
    total_pagado = db.session.query(
        db.func.sum(
            case((RegistroAsesoria.pagado == True, asesoria.costo))
        )
    ).filter(RegistroAsesoria.asesoria_id == asesoria.id).scalar()
    if total_pagado is None:
        total_pagado = 0.0
    registro = RegistroAsesoria.query.filter_by(asesoria_id=asesoria.id, alumno_id=current_user.id).first()
    if registro:
        registrado = True
        pagado = registro.pagado
    else:
        registrado = False
        pagado = False
    asesoria_dict = {
        "id": asesoria.id,
        "descripcion": asesoria.descripcion,
        "costo": asesoria.costo,
        "max_alumnos": asesoria.max_alumnos,
        "temas": asesoria.temas,
        "meet_link": asesoria.meet_link
    }
    maestro_dict = {
        "id": maestro.id,
        "nombre": maestro.nombre,
        "email": maestro.email,
        "foto": maestro.foto
    }
    alumnos_list = [{"id": a.id, "nombre": a.nombre, "email": a.email} for a in alumnos]
    context = {
        "asesoria": asesoria_dict,
        "maestro": maestro_dict,
        "alumnos": alumnos_list,
        "total_pagado": total_pagado,
        "registrado": registrado,
        "pagado": pagado
    }
    return jsonify(context)

# Modificación del endpoint para ver asesoría
# Modificación del endpoint para ver asesoría (CORREGIDO)
@app.route('/api/ver_detalle_asesoria/<int:id>', methods=['GET'])
@jwt_required  # Cambiado de @login_required
def ver_detalle_asesoria_api(id):
    current_user = request.current_user  # NUEVO
    try:
        asesoria = Asesoria.query.get_or_404(id)
        maestro = User.query.get(asesoria.maestro_id)
        
        # Construir la ruta relativa para el frontend
        foto_path = f"/images/{maestro.foto}" if maestro.foto else None
        
        alumnos = db.session.query(User).join(RegistroAsesoria)\
            .filter(RegistroAsesoria.asesoria_id == asesoria.id).all()

        total_pagado = db.session.query(
            db.func.sum(case((RegistroAsesoria.pagado == True, asesoria.costo)))
        ).filter(RegistroAsesoria.asesoria_id == asesoria.id).scalar() or 0.0

        registro = RegistroAsesoria.query.filter_by(asesoria_id=asesoria.id, alumno_id=current_user.id).first()
        
        data = {
            "asesoria": {
                "id": asesoria.id,
                "descripcion": asesoria.descripcion,
                "costo": asesoria.costo,
                "max_alumnos": asesoria.max_alumnos,
                "temas": asesoria.temas,
                "meet_link": asesoria.meet_link
            },
            "maestro": {
                "id": maestro.id,
                "nombre": maestro.nombre,
                "email": maestro.email,
                "foto": foto_path,
                "foto_filename": maestro.foto
            },
            "alumnos": [{"id": a.id, "nombre": a.nombre, "email": a.email} for a in alumnos],
            "total_pagado": total_pagado,
            "registrado": bool(registro),
            "pagado": registro.pagado if registro else False
        }
        return jsonify(data)
        
    except Exception as e:
        app.logger.error(f"Error al obtener detalles de asesoría: {str(e)}")
        return jsonify({"error": "Error al cargar los detalles"}), 500

@app.route('/api/ver_asesorias_totales')
@jwt_required  # Cambiado de @login_required
def ver_asesorias_totales_api():
    current_user = request.current_user  # NUEVO (aunque no se usa en esta ruta)
    results = db.session.query(Asesoria, User).join(User, Asesoria.maestro_id == User.id).all()
    asesorias_list = []
    for a, m in results:
        asesorias_list.append({
            "id": a.id,
            "descripcion": a.descripcion,
            "costo": a.costo,
            "max_alumnos": a.max_alumnos,
            "temas": a.temas,
            "meet_link": a.meet_link,
            "maestro": {
                "id": m.id,
                "nombre": m.nombre,
                "email": m.email
            }
        })
    return jsonify({"asesorias": asesorias_list})

@app.route('/api/borrar_asesoria/<int:id>', methods=['DELETE'])
@jwt_required  # Cambiado de @login_required
def borrar_asesoria_api(id):
    current_user = request.current_user  # NUEVO
    # Verificar token CSRF
    data = request.get_json() if request.is_json else request.args
    csrf_token = data.get('csrfToken')
    try:
        validate_csrf(csrf_token)
    except Exception as e:
        return jsonify({"error": "Invalid CSRF token."}), 403

    asesoria = Asesoria.query.get_or_404(id)
    try:
        RegistroAsesoria.query.filter_by(asesoria_id=asesoria.id).delete()
        db.session.delete(asesoria)
        db.session.commit()
        return jsonify({"message": "Asesoría eliminada con éxito."})
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Error al eliminar la asesoría. Intenta de nuevo."}), 500

# Ruta para editar una asesoría
# Después de obtener los datos con data = request.form.to_dict(), usamos clean() de Bleach para eliminar cualquier etiqueta o script potencialmente malicioso de los campos descripcion y temas.
@app.route('/api/editar_asesoria/<int:id>', methods=['GET', 'PUT'])
@jwt_required  # Cambiado de @login_required
def editar_asesoria_api(id):
    current_user = request.current_user  # NUEVO
    asesoria = Asesoria.query.get_or_404(id)
    if asesoria.maestro_id != current_user.id:
        return jsonify({"error": "No tienes permiso para editar esta asesoría."}), 403
    if request.method == 'GET':
        return jsonify({
            "asesoria": {
                "id": asesoria.id,
                "descripcion": asesoria.descripcion,
                "costo": asesoria.costo,
                "max_alumnos": asesoria.max_alumnos,
                "temas": asesoria.temas,
                "meet_link": asesoria.meet_link
            }
        })
    
    data = request.get_json() if request.is_json else request.form.to_dict()
    csrf_token = data.get('csrfToken')
    try:
        validate_csrf(csrf_token)
    except Exception as e:
        return jsonify({"error": "Invalid CSRF token."}), 403

    # Sanitizar campos antes de actualizar
    asesoria.descripcion = clean(data.get('descripcion', asesoria.descripcion), strip=True)
    asesoria.temas = clean(data.get('temas', asesoria.temas), strip=True)
    asesoria.costo = data.get('costo', asesoria.costo)
    asesoria.max_alumnos = data.get('max_alumnos', asesoria.max_alumnos)
    asesoria.meet_link = data.get('meet_link', asesoria.meet_link)
    db.session.commit()
    return jsonify({
        "message": "Asesoría actualizada con éxito.",
        "asesoria": {
            "id": asesoria.id,
            "descripcion": asesoria.descripcion,
            "costo": asesoria.costo,
            "max_alumnos": asesoria.max_alumnos,
            "temas": asesoria.temas,
            "meet_link": asesoria.meet_link
        }
    })

@app.route('/api/ver_detalle_asesoria_maestro_dup/<int:id>')
@jwt_required  # Cambiado de @login_required
def ver_detalle_asesoria_maestro_dup(id):
    return redirect(url_for('ver_detalle_asesoria_maestro_api', id=id))

@app.route('/api/ver_detalle_asesoria_maestro/<int:id>')
@jwt_required  # Cambiado de @login_required
def ver_detalle_asesoria_maestro_api(id):
    current_user = request.current_user  # NUEVO
    asesoria = Asesoria.query.get_or_404(id)
    maestro = User.query.get(asesoria.maestro_id)
    alumnos = db.session.query(User).join(RegistroAsesoria)\
        .filter(RegistroAsesoria.asesoria_id == asesoria.id).all()
    total_pagado = db.session.query(
        db.func.sum(
            case((RegistroAsesoria.pagado == True, asesoria.costo))
        )
    ).filter(RegistroAsesoria.asesoria_id == asesoria.id).scalar() or 0.0
    data = {
        "asesoria": {
            "id": asesoria.id,
            "descripcion": asesoria.descripcion,
            "costo": asesoria.costo,
            "max_alumnos": asesoria.max_alumnos,
            "temas": asesoria.temas,
            "meet_link": asesoria.meet_link,
            "total_pagado": total_pagado,
        },
        "maestro": {
            "id": maestro.id,
            "nombre": maestro.nombre,
            "email": maestro.email
        },
        "alumnos": [{"id": a.id, "nombre": a.nombre, "email": a.email} for a in alumnos]
    }
    return jsonify(data)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
