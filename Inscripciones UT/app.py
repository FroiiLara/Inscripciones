import os
import re
import uuid
import json
from datetime import timedelta, datetime

MAX_INTENTOS = 3
TIEMPO_BLOQUEO_MINUTOS = 15

from dotenv import load_dotenv
from flask import (
    Flask, request, render_template,
    redirect, url_for, flash, abort
)
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
from werkzeug.utils import secure_filename

# ================= CLOUDINARY =================
import cloudinary
import cloudinary.uploader

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request
)

# ======================================================
# CONFIGURACIÓN INICIAL
# ======================================================

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

bcrypt = Bcrypt(app)

# ================= JWT CONFIG =================
app.config["JWT_SECRET_KEY"]          = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_TOKEN_LOCATION"]      = ["cookies"]
app.config["JWT_ACCESS_COOKIE_PATH"]  = "/"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False   # En producción activar: True
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

jwt = JWTManager(app)

# ================= MONGODB =================
MONGO_URI = os.environ.get("MONGO_URI")
client    = MongoClient(MONGO_URI)
db        = client["Users"]
collection         = db["Users"]
inscripciones_col  = db["Inscripciones"]
reinscripciones_col = db["Reinscripciones"]

# ================= CLOUDINARY CONFIG =================
cloudinary.config(
    cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key    = os.environ.get("CLOUDINARY_API_KEY"),
    api_secret = os.environ.get("CLOUDINARY_API_SECRET"),
    secure     = True
)

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def subir_a_cloudinary(archivo, carpeta="inscripciones"):
    """Sube un archivo a Cloudinary y devuelve la URL segura."""
    if archivo and allowed_file(archivo.filename):
        try:
            resultado = cloudinary.uploader.upload(
                archivo,
                folder=carpeta,
                resource_type="auto"   # acepta pdf, jpg, png
            )
            return resultado.get("secure_url")
        except Exception as e:
            print(f"Error al subir a Cloudinary: {e}")
    return None

# ================= SENDGRID =================
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL       = os.environ.get("FROM_EMAIL")

# ================= SERIALIZER =================
serializer = Serializer(app.secret_key, salt="password-reset-salt")

# ================= CARRERAS =================
CARRERAS = {
    'ITID': 'Ing. en Tecnologías de la Información e Innovación Digital',
    'II':   'Ingeniería Industrial',
    'IMI':  'Ing. en Mantenimiento Industrial',
    'IMT':  'Ingeniería Mecatrónica',
    'IE':   'Ingeniería en Electromovilidad',
    'LNM':  'Lic. en Negocios y Mercadotecnia',
    'LLI':  'Lic. en Educación (Enseñanza del Idioma Inglés)'
}

# ======================================================
# UTILIDADES DE SEGURIDAD
# ======================================================

def validar_no_sql_injection(dato):
    if isinstance(dato, dict): return False
    if "$" in str(dato): return False
    return True

# ======================================================
# CONTEXT PROCESSOR
# ======================================================

@app.context_processor
def inject_user():
    try:
        verify_jwt_in_request(optional=True)
        matricula = get_jwt_identity()
        if matricula:
            user = collection.find_one({"matricula": matricula})
            usuario = user["usuario"] if user else matricula
            es_admin = user.get("es_admin", False) if user else False
        else:
            usuario  = None
            es_admin = False
    except Exception:
        usuario  = None
        es_admin = False
    return dict(usuario=usuario, es_admin=es_admin)

# ======================================================
# FUNCIÓN PARA ENVIAR EMAIL
# ======================================================

def enviar_email(destinatario, asunto, cuerpo):
    mensaje = Mail(
        from_email=FROM_EMAIL,
        to_emails=destinatario,
        subject=asunto,
        html_content=cuerpo
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(mensaje)
        print(f"Correo enviado con éxito! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

def enviar_confirmacion_inscripcion(email, nombre, folio, carrera):
    asunto = f"Confirmación de Inscripción — Folio {folio}"
    cuerpo = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
        <div style="background:#1a5f5c;padding:20px;text-align:center;">
            <h2 style="color:white;margin:0;">Universidad Tecnológica de Santa Catarina</h2>
        </div>
        <div style="padding:30px;">
            <h3 style="color:#1a5f5c;">¡Tu inscripción fue recibida exitosamente!</h3>
            <p>Hola <strong>{nombre}</strong>,</p>
            <p>Hemos recibido tu solicitud de inscripción. Aquí está el resumen:</p>
            <table style="width:100%;border-collapse:collapse;margin:20px 0;">
                <tr style="background:#f5f5f5;">
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Folio</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">{folio}</td>
                </tr>
                <tr>
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Nombre</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">{nombre}</td>
                </tr>
                <tr style="background:#f5f5f5;">
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Carrera</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">{carrera}</td>
                </tr>
                <tr>
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Estatus</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">En revisión</td>
                </tr>
            </table>
            <p style="color:#555;">El área de Control Escolar revisará tus documentos en un plazo de <strong>3 a 5 días hábiles</strong>. Recibirás una notificación cuando cambie el estatus de tu solicitud.</p>
            <p style="color:#999;font-size:0.85rem;">Este correo es generado automáticamente, por favor no respondas a este mensaje.</p>
        </div>
        <div style="background:#f5f5f5;padding:15px;text-align:center;font-size:0.8rem;color:#999;">
            © 2026 UTSC — Secretaría de Educación de Nuevo León
        </div>
    </div>
    """
    enviar_email(email, asunto, cuerpo)

def enviar_confirmacion_reinscripcion(email, nombre, folio, carrera, cuatrimestre):
    asunto = f"Confirmación de Reinscripción — Folio {folio}"
    cuerpo = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
        <div style="background:#1a5f5c;padding:20px;text-align:center;">
            <h2 style="color:white;margin:0;">Universidad Tecnológica de Santa Catarina</h2>
        </div>
        <div style="padding:30px;">
            <h3 style="color:#1a5f5c;">¡Tu reinscripción fue recibida exitosamente!</h3>
            <p>Hola <strong>{nombre}</strong>,</p>
            <p>Hemos recibido tu solicitud de reinscripción. Aquí está el resumen:</p>
            <table style="width:100%;border-collapse:collapse;margin:20px 0;">
                <tr style="background:#f5f5f5;">
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Folio</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">{folio}</td>
                </tr>
                <tr>
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Nombre</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">{nombre}</td>
                </tr>
                <tr style="background:#f5f5f5;">
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Carrera</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">{carrera}</td>
                </tr>
                <tr>
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Cuatrimestre</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">{cuatrimestre}°</td>
                </tr>
                <tr style="background:#f5f5f5;">
                    <td style="padding:10px;border:1px solid #ddd;"><strong>Estatus</strong></td>
                    <td style="padding:10px;border:1px solid #ddd;">En revisión</td>
                </tr>
            </table>
            <p style="color:#555;">Control Escolar validará tu pago y materias en un plazo de <strong>2 a 3 días hábiles</strong>.</p>
            <p style="color:#999;font-size:0.85rem;">Este correo es generado automáticamente, por favor no respondas a este mensaje.</p>
        </div>
        <div style="background:#f5f5f5;padding:15px;text-align:center;font-size:0.8rem;color:#999;">
            © 2026 UTSC — Secretaría de Educación de Nuevo León
        </div>
    </div>
    """
    enviar_email(email, asunto, cuerpo)

def enviar_notificacion_estatus(email, nombre, folio, tipo, nuevo_estatus):
    color = "#2e7d32" if nuevo_estatus == "Aprobada" else "#c62828"
    icono = "✅" if nuevo_estatus == "Aprobada" else "❌"
    asunto = f"{icono} Tu {tipo} ha sido {nuevo_estatus} — Folio {folio}"
    cuerpo = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
        <div style="background:#1a5f5c;padding:20px;text-align:center;">
            <h2 style="color:white;margin:0;">Universidad Tecnológica de Santa Catarina</h2>
        </div>
        <div style="padding:30px;">
            <h3 style="color:{color};">{icono} Tu solicitud ha sido {nuevo_estatus}</h3>
            <p>Hola <strong>{nombre}</strong>,</p>
            <p>El estatus de tu <strong>{tipo}</strong> con folio <strong>{folio}</strong> ha sido actualizado a:</p>
            <div style="text-align:center;margin:20px 0;">
                <span style="background:{color};color:white;padding:10px 30px;border-radius:20px;font-size:1.1rem;font-weight:bold;">
                    {nuevo_estatus}
                </span>
            </div>
            <p style="color:#555;">Si tienes dudas, comunícate con Control Escolar.</p>
        </div>
        <div style="background:#f5f5f5;padding:15px;text-align:center;font-size:0.8rem;color:#999;">
            © 2026 UTSC — Secretaría de Educación de Nuevo León
        </div>
    </div>
    """
    enviar_email(email, asunto, cuerpo)

# ======================================================
# RUTAS PÚBLICAS
# ======================================================

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':

        matricula  = str(request.form.get('matricula', '')).strip()
        usuario    = str(request.form.get('usuario', '')).strip()
        email      = str(request.form.get('email', '')).lower().strip()
        contrasena = str(request.form.get('contrasena', ''))

        if not matricula or not usuario or not email or not contrasena:
            abort(400)

        if not matricula.isdigit():
            flash("La matrícula debe contener solo números.", "error")
            return redirect(url_for('registro'))

        if not validar_no_sql_injection(usuario):
            flash("Nombre inválido.", "error")
            return redirect(url_for('registro'))

        if not email.endswith("@virtual.utsc.edu.mx"):
            flash("Debe usar un correo institucional @virtual.utsc.edu.mx", "error")
            return redirect(url_for('registro'))

        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$'
        if not re.fullmatch(password_regex, contrasena):
            flash("La contraseña debe tener mínimo 8 caracteres, incluir mayúscula, minúscula, número y símbolo.", "error")
            return redirect(url_for('registro'))

        if collection.find_one({'matricula': matricula}):
            flash("La matrícula ya está registrada.", "error")
            return redirect(url_for('registro'))

        if collection.find_one({'email': email}):
            flash("El correo ya está registrado.", "error")
            return redirect(url_for('registro'))

        hashed = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        collection.insert_one({
            'matricula': matricula,
            'usuario': usuario,
            'email': email,
            'contrasena': hashed,
            'intentos_fallidos': 0,
            'bloqueado_hasta': None,
            'es_admin': False
        })

        flash("Registro exitoso. Inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        matricula  = str(request.form.get('matricula', '')).strip()
        contrasena = str(request.form.get('contrasena', ''))

        if not matricula or not contrasena:
            abort(400)

        user = collection.find_one({'matricula': matricula})

        if not user:
            flash("Matrícula o contraseña incorrectos.", "error")
            return render_template('login.html', matricula_guardada=matricula)

        bloqueado_hasta = user.get('bloqueado_hasta')
        if bloqueado_hasta and datetime.utcnow() < bloqueado_hasta:
            minutos_restantes = int((bloqueado_hasta - datetime.utcnow()).total_seconds() / 60)
            flash(f"Cuenta bloqueada temporalmente. Intente nuevamente en {minutos_restantes} minutos.", "error")
            return render_template('login.html', matricula_guardada=matricula)

        if bcrypt.check_password_hash(user['contrasena'], contrasena):

            collection.update_one(
                {'_id': user['_id']},
                {'$set': {'intentos_fallidos': 0, 'bloqueado_hasta': None}}
            )

            access_token = create_access_token(identity=user['matricula'])
            response = redirect(url_for('pagina_principal'))
            set_access_cookies(response, access_token)
            return response

        intentos = user.get('intentos_fallidos', 0) + 1

        if intentos >= MAX_INTENTOS:
            bloqueo = datetime.utcnow() + timedelta(minutes=TIEMPO_BLOQUEO_MINUTOS)
            collection.update_one(
                {'_id': user['_id']},
                {'$set': {'intentos_fallidos': intentos, 'bloqueado_hasta': bloqueo}}
            )
            flash("Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos.", "error")
        else:
            restantes = MAX_INTENTOS - intentos
            collection.update_one(
                {'_id': user['_id']},
                {'$set': {'intentos_fallidos': intentos}}
            )
            flash(f"Contraseña incorrecta. Te quedan {restantes} intentos.", "error")

        return render_template('login.html', matricula_guardada=matricula)

    return render_template('login.html')


@app.route('/logout')
@jwt_required()
def logout():
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)
    return response

# ======================================================
# PÁGINAS PROTEGIDAS
# ======================================================

@app.route('/pagina_principal')
@jwt_required()
def pagina_principal():
    matricula = get_jwt_identity()
    user = collection.find_one({"matricula": matricula})
    if not user:
        return redirect(url_for("login"))
    return render_template("index.html", usuario=user["usuario"])


@app.route('/mi_perfil')
@jwt_required()
def mi_perfil():
    matricula = get_jwt_identity()
    user_data = collection.find_one({'matricula': matricula})
    if not user_data:
        abort(404)
    return render_template(
        'mi_perfil.html',
        usuario=user_data['usuario'],
        email=user_data['email'],
        matricula=user_data['matricula']
    )


@app.route('/inscripcion')
@jwt_required()
def inscripcion():
    matricula = get_jwt_identity()
    user = collection.find_one({"matricula": matricula})
    nombre_usuario = user["usuario"] if user else matricula
    return render_template('inscripcion.html', usuario=nombre_usuario)


@app.route('/reinscripcion')
@jwt_required()
def reinscripcion():
    matricula = get_jwt_identity()
    user = collection.find_one({"matricula": matricula})
    nombre_usuario = user["usuario"] if user else matricula
    return render_template('reinscripcion.html', usuario=nombre_usuario)


@app.route('/soporte')
@jwt_required()
def soporte():
    matricula = get_jwt_identity()
    user = collection.find_one({"matricula": matricula})
    nombre_usuario = user["usuario"] if user else matricula
    return render_template('soporte.html', usuario=nombre_usuario)

# ======================================================
# HISTORIAL DEL ALUMNO  ← NUEVO
# ======================================================

@app.route('/mi_historial')
@jwt_required()
def mi_historial():
    matricula = get_jwt_identity()
    user = collection.find_one({"matricula": matricula})
    if not user:
        abort(404)

    inscripciones = list(inscripciones_col.find(
        {"usuario": matricula},
        {"_id": 0}
    ))

    reinscripciones = list(reinscripciones_col.find(
        {"usuario": matricula},
        {"_id": 0}
    ))

    return render_template(
        'mi_historial.html',
        usuario=user["usuario"],
        inscripciones=inscripciones,
        reinscripciones=reinscripciones
    )

# ======================================================
# PANEL DE ADMINISTRADOR  ← NUEVO
# ======================================================

def admin_required(f):
    """Decorador: verifica que el usuario tenga rol admin."""
    from functools import wraps
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        matricula = get_jwt_identity()
        user = collection.find_one({"matricula": matricula})
        if not user or not user.get("es_admin", False):
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route('/admin')
@admin_required
def admin_panel():
    inscripciones   = list(inscripciones_col.find({}, {"_id": 0}))
    reinscripciones = list(reinscripciones_col.find({}, {"_id": 0}))
    return render_template(
        'admin_panel.html',
        inscripciones=inscripciones,
        reinscripciones=reinscripciones
    )


@app.route('/admin/actualizar_estatus', methods=['POST'])
@admin_required
def actualizar_estatus():
    folio       = request.form.get('folio', '').strip()
    tipo        = request.form.get('tipo', '').strip()      # 'inscripcion' o 'reinscripcion'
    nuevo_estatus = request.form.get('estatus', '').strip()

    if nuevo_estatus not in ['Aprobada', 'Rechazada', 'En revisión']:
        flash("Estatus no válido.", "error")
        return redirect(url_for('admin_panel'))

    col = inscripciones_col if tipo == 'inscripcion' else reinscripciones_col

    doc = col.find_one({"folio": folio})
    if not doc:
        flash("Solicitud no encontrada.", "error")
        return redirect(url_for('admin_panel'))

    col.update_one({"folio": folio}, {"$set": {"estatus": nuevo_estatus}})

    # Notificar al alumno por correo si el estatus cambia a Aprobada o Rechazada
    if nuevo_estatus in ['Aprobada', 'Rechazada']:
        matricula_alumno = doc.get("usuario")
        alumno = collection.find_one({"matricula": matricula_alumno})
        if alumno:
            nombre_alumno = doc.get("nombre", alumno.get("usuario", "Alumno"))
            tipo_label = "inscripción" if tipo == "inscripcion" else "reinscripción"
            enviar_notificacion_estatus(
                alumno["email"],
                nombre_alumno,
                folio,
                tipo_label,
                nuevo_estatus
            )

    flash(f"Estatus del folio {folio} actualizado a '{nuevo_estatus}'.", "success")
    return redirect(url_for('admin_panel'))

# ======================================================
# INSCRIPCIÓN — PROCESAR FORMULARIO MULTI-PASO
# ======================================================

@app.route('/inscripcion_submit', methods=['POST'])
@jwt_required()
def inscripcion_submit():
    matricula_jwt = get_jwt_identity()
    user = collection.find_one({"matricula": matricula_jwt})

    nombre      = request.form.get('nombre', '').strip()
    curp        = request.form.get('curp', '').strip().upper()
    fecha_nac   = request.form.get('fecha_nacimiento', '').strip()
    telefono    = request.form.get('telefono', '').strip()
    carrera     = request.form.get('carrera', '').strip()
    cont_nombre = request.form.get('contacto_emergencia_nombre', '').strip()
    cont_tel    = request.form.get('contacto_emergencia_tel', '').strip()

    if not all([nombre, curp, fecha_nac, telefono, carrera, cont_nombre, cont_tel]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('inscripcion'))

    curp_regex = re.compile(r'^[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]{2}$')
    if not curp_regex.match(curp):
        flash("La CURP no tiene el formato correcto.", "error")
        return redirect(url_for('inscripcion'))

    # ===== SUBIR ARCHIVOS A CLOUDINARY =====
    foto        = subir_a_cloudinary(request.files.get('fotografia'),  carpeta="inscripciones/fotografias")
    doc_acta    = subir_a_cloudinary(request.files.get('doc_acta'),    carpeta="inscripciones/actas")
    doc_cert    = subir_a_cloudinary(request.files.get('doc_cert'),    carpeta="inscripciones/certificados")
    comprobante = subir_a_cloudinary(request.files.get('comprobante'), carpeta="inscripciones/comprobantes")

    if not all([foto, doc_acta, doc_cert, comprobante]):
        flash("Todos los documentos son obligatorios y deben ser PDF, JPG o PNG.", "error")
        return redirect(url_for('inscripcion'))

    folio = 'UTSC-' + uuid.uuid4().hex[:8].upper()

    inscripciones_col.insert_one({
        'usuario'                   : matricula_jwt,
        'folio'                     : folio,
        'nombre'                    : nombre,
        'curp'                      : curp,
        'fecha_nacimiento'          : fecha_nac,
        'telefono'                  : telefono,
        'carrera'                   : carrera,
        'contacto_emergencia_nombre': cont_nombre,
        'contacto_emergencia_tel'   : cont_tel,
        'fotografia'                : foto,
        'doc_acta'                  : doc_acta,
        'doc_cert'                  : doc_cert,
        'comprobante'               : comprobante,
        'estatus'                   : 'En revisión',
        'fecha_solicitud'           : datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    })

    # ===== ENVIAR CORREO DE CONFIRMACIÓN =====
    if user and user.get("email"):
        enviar_confirmacion_inscripcion(user["email"], nombre, folio, carrera)

    return render_template('exito_inscripcion.html',
        usuario                    = matricula_jwt,
        folio                      = folio,
        nombre                     = nombre,
        curp                       = curp,
        fecha_nacimiento           = fecha_nac,
        telefono                   = telefono,
        carrera                    = carrera,
        contacto_emergencia_nombre = cont_nombre,
        contacto_emergencia_tel    = cont_tel
    )

# ======================================================
# REINSCRIPCIÓN — PROCESAR FORMULARIO MULTI-PASO
# ======================================================

@app.route('/reinscripcion_submit', methods=['POST'])
@jwt_required()
def reinscripcion_submit():
    matricula_jwt = get_jwt_identity()
    user = collection.find_one({"matricula": matricula_jwt})

    matricula       = request.form.get('matricula', '').strip()
    nombre          = request.form.get('nombre', '').strip()
    correo          = request.form.get('correo', '').strip().lower()
    telefono        = request.form.get('telefono', '').strip()
    carrera_clave   = request.form.get('carrera_clave', '').strip()
    cuatrimestre    = request.form.get('cuatrimestre', '').strip()
    referencia_pago = request.form.get('referencia_pago', '').strip()
    fecha_pago      = request.form.get('fecha_pago', '').strip()
    es_estadia      = request.form.get('es_estadia', '0').strip() == '1'

    if not matricula or not matricula.isdigit():
        flash("La matrícula debe contener solo números.", "error")
        return redirect(url_for('reinscripcion'))

    carrera_nombre = CARRERAS.get(carrera_clave, carrera_clave)

    materias_raw = request.form.get('materias', '[]')
    try:
        materias_lista = json.loads(materias_raw)
        materias = [m.split('|')[1] if '|' in m else m for m in materias_lista]
    except Exception:
        materias = []

    if not all([nombre, correo, telefono, carrera_clave, cuatrimestre, referencia_pago, fecha_pago]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('reinscripcion'))

    if not es_estadia and not materias:
        flash("Debes seleccionar al menos una materia.", "error")
        return redirect(url_for('reinscripcion'))

    # ===== SUBIR COMPROBANTE A CLOUDINARY =====
    comprobante = subir_a_cloudinary(request.files.get('comprobante'), carpeta="reinscripciones/comprobantes")
    if not comprobante:
        flash("El comprobante de pago es obligatorio.", "error")
        return redirect(url_for('reinscripcion'))

    folio = 'REINSC-' + uuid.uuid4().hex[:8].upper()

    reinscripciones_col.insert_one({
        'usuario'        : matricula_jwt,
        'folio'          : folio,
        'matricula'      : matricula,
        'nombre'         : nombre,
        'correo'         : correo,
        'telefono'       : telefono,
        'carrera_clave'  : carrera_clave,
        'carrera'        : carrera_nombre,
        'cuatrimestre'   : cuatrimestre,
        'es_estadia'     : es_estadia,
        'materias'       : materias,
        'comprobante'    : comprobante,
        'fecha_pago'     : fecha_pago,
        'referencia_pago': referencia_pago,
        'estatus'        : 'En revisión',
        'fecha_solicitud': datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    })

    # ===== ENVIAR CORREO DE CONFIRMACIÓN =====
    if user and user.get("email"):
        enviar_confirmacion_reinscripcion(user["email"], nombre, folio, carrera_nombre, cuatrimestre)

    return render_template('exito_reinscripcion.html',
        usuario         = matricula_jwt,
        folio           = folio,
        matricula       = matricula,
        nombre          = nombre,
        correo          = correo,
        carrera         = carrera_nombre,
        cuatrimestre    = cuatrimestre,
        es_estadia      = es_estadia,
        materias        = materias,
        referencia_pago = referencia_pago,
        fecha_pago      = fecha_pago
    )

# ======================================================
# RECUPERACIÓN DE CONTRASEÑA
# ======================================================

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        email   = request.form['email']
        usuario = collection.find_one({'email': email})

        if usuario:
            token  = serializer.dumps(email, salt='password-reset-salt')
            enlace = url_for('restablecer_contrasena', token=token, _external=True)
            asunto = "Recuperación de contraseña"
            cuerpo = f"""
            <p>Hola, hemos recibido una solicitud para restablecer tu contraseña.</p>
            <p>Si no has solicitado este cambio, ignora este mensaje.</p>
            <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
            <a href="{enlace}">Restablecer contraseña</a>
            """
            enviar_email(email, asunto, cuerpo)
            flash("Te hemos enviado un correo para recuperar tu contraseña.", "success")
        else:
            flash("El correo electrónico no está registrado.", "error")

    return render_template('recuperar_contrasena.html')


@app.route('/restablecer_contrasena/<token>', methods=['GET', 'POST'])
def restablecer_contrasena(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash("El enlace de restablecimiento ha caducado o es inválido.", "error")
        return redirect(url_for('recuperar_contrasena'))

    if request.method == 'POST':
        nueva_contrasena = request.form['nueva_contrasena']
        hashed_password  = bcrypt.generate_password_hash(nueva_contrasena).decode('utf-8')
        collection.update_one({'email': email}, {'$set': {'contrasena': hashed_password}})
        flash("Tu contraseña ha sido restablecida con éxito.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')

# ======================================================
# MANEJADORES DE ERRORES
# ======================================================

@app.errorhandler(400)
def bad_request(e):      return render_template("400.html"), 400

@app.errorhandler(401)
def unauthorized(e):     return render_template("401.html"), 401

@app.errorhandler(403)
def forbidden(e):        return render_template("403.html"), 403

@app.errorhandler(404)
def not_found(e):        return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):   return render_template("500.html"), 500

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    print(f"Unexpected error: {e}")
    return render_template("500.html"), 500

if __name__ == '__main__':
    app.run(debug=True)
