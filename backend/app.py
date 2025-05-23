from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from sqlalchemy import case
import os
import logging
from flask_cors import CORS

# Configuración de la aplicación
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///asesorias.db'
app.config['SECRET_KEY'] = 'tu_clave_secreta'

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
login_manager = LoginManager(app)
CORS(app, supports_credentials=True)

# MODELOS
asesoria_alumno = db.Table('asesoria_alumno',
    db.Column('asesoria_id', db.Integer, db.ForeignKey('asesoria.id'), primary_key=True),
    db.Column('alumno_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json() if request.is_json else request.form
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user is None or user.password != password:
        return jsonify({"error": "Correo o contraseña incorrectos"}), 400
    login_user(user)
    if user.rol == 'alumno':
        redirect_url = "/api/dashboard_alumno"
    elif user.rol == 'maestro':
        redirect_url = "/api/dashboard_maestro"
    else:
        redirect_url = "/"
    return jsonify({"message": "Inicio de sesión exitoso", "redirect": redirect_url})

@app.route('/api/logout', methods=['POST'])
@login_required
def logout_api():
    logout_user()
    return jsonify({"message": "Sesión cerrada correctamente"})

# Modificación del endpoint de registro de maestro
@app.route('/api/registro_maestro', methods=['POST'])
def registro_maestro_api():
    try:
        foto_filename = None
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                # Generar nombre único basado en email
                email = request.form.get('email')
                safe_email = email.split('@')[0].replace('.', '_')
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{safe_email}_profile.{ext}"
                
                # Guardar en la nueva ubicación
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                foto_filename = filename

        data = request.form.to_dict()

        # Validaciones
        if data['password'] != data['confirm_password']:
            return jsonify({"error": "Las contraseñas no coinciden."}), 400
            
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "El correo ya está registrado. Usa uno diferente."}), 400

        # Crear nuevo maestro
        nuevo_maestro = User(
            nombre=data['nombre'],
            email=data['email'],
            password=data['password'],
            rol='maestro',
            especializacion=data.get('especializacion'),
            foto=foto_filename,  # Solo guardamos el nombre del archivo
            edad=data.get('edad'),
            nivel=data.get('nivel')
        )
        
        db.session.add(nuevo_maestro)
        db.session.commit()
        
        return jsonify({
            "message": "Maestro registrado con éxito", 
            "redirect": "/api/login",
            "foto": foto_filename  # Devolver el nombre del archivo
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error en registro maestro: {str(e)}")
        return jsonify({"error": "Error en el servidor"}), 500


# Asegúrate de tener esta ruta en tu Flask app

@app.route('/api/registro_alumno', methods=['POST'])
def registro_alumno_api():
    data = request.get_json() if request.is_json else request.form
    nombre = data.get('nombre')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    if password != confirm_password:
        return jsonify({"error": "Las contraseñas no coinciden."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "El correo ya está registrado. Usa uno diferente."}), 400
    nuevo_alumno = User(nombre=nombre, email=email, password=password, rol='alumno')
    db.session.add(nuevo_alumno)
    db.session.commit()
    return jsonify({"message": "Alumno registrado con éxito", "redirect": "/api/login"})

@app.route('/api/dashboard_maestro')
@login_required
def dashboard_maestro_api():
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
@login_required
def dashboard_alumno_api():
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
@login_required
def validar_registro_api(id):
    asesoria = Asesoria.query.get_or_404(id)
    if current_user in asesoria.alumnos:
        return jsonify({"error": "Ya estás registrado en esta asesoría."}), 400
    asesoria.alumnos.append(current_user)
    asesoria.total_pagado += asesoria.costo
    db.session.commit()
    return jsonify({"message": "Te has registrado en la asesoría con éxito.", "redirect": f"/api/ver_asesoria/{asesoria.id}"})

@app.route('/api/pago_asesoria/<int:id>', methods=['POST'])
@login_required
def pago_asesoria_api(id):
    asesoria = Asesoria.query.get_or_404(id)
    data = request.get_json() if request.is_json else request.form
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
@login_required
def procesar_pago_api(id):
    asesoria = Asesoria.query.get_or_404(id)
    data = request.get_json() if request.is_json else request.form
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

@app.route('/api/nueva_asesoria', methods=['POST'])
@login_required
def nueva_asesoria_api():
    data = request.get_json() if request.is_json else request.form
    nueva_asesoria = Asesoria(
        descripcion=data.get('descripcion'),
        costo=data.get('costo'),
        max_alumnos=data.get('max_alumnos'),
        temas=data.get('temas'),
        maestro_id=current_user.id,
        meet_link=data.get('meet_link')
    )
    db.session.add(nueva_asesoria)
    db.session.commit()
    return jsonify({"message": "Asesoría creada con éxito.", "redirect": "/api/dashboard_maestro"})

@app.route('/api/registrar_asesoria/<int:id>', methods=['POST'])
@login_required
def registrar_asesoria_api(id):
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
@app.route('/api/ver_asesoria/<int:id>', methods=['GET'])
@login_required
def ver_asesoria_api(id):
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
@login_required
def ver_detalle_asesoria_api(id):
    try:
        asesoria = Asesoria.query.get_or_404(id)
        maestro = User.query.get(asesoria.maestro_id)
        
        # Construir la ruta relativa para el frontend (sintaxis Python correcta)
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
                "foto": foto_path,  # Ruta relativa para el frontend
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
@login_required
def ver_asesorias_totales_api():
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
@login_required
def borrar_asesoria_api(id):
    asesoria = Asesoria.query.get_or_404(id)
    try:
        RegistroAsesoria.query.filter_by(asesoria_id=asesoria.id).delete()
        db.session.delete(asesoria)
        db.session.commit()
        return jsonify({"message": "Asesoría eliminada con éxito."})
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Error al eliminar la asesoría. Intenta de nuevo."}), 500

@app.route('/api/editar_asesoria/<int:id>', methods=['GET', 'PUT'])
@login_required
def editar_asesoria_api(id):
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
    data = request.get_json() if request.is_json else request.form
    asesoria.descripcion = data.get('descripcion', asesoria.descripcion)
    asesoria.costo = data.get('costo', asesoria.costo)
    asesoria.max_alumnos = data.get('max_alumnos', asesoria.max_alumnos)
    asesoria.temas = data.get('temas', asesoria.temas)
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
@login_required
def ver_detalle_asesoria_maestro_dup(id):
    return redirect(url_for('ver_detalle_asesoria_maestro_api', id=id))

@app.route('/api/ver_detalle_asesoria_maestro/<int:id>')
@login_required
def ver_detalle_asesoria_maestro_api(id):
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
