import os
import re
import uuid
from datetime import timedelta
from datetime import datetime
MAX_INTENTOS = 5
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
app.config["JWT_COOKIE_CSRF_PROTECT"] = False   # En producción: True
app.config["JWT_ACCESS_TOKEN_EXPIRES"]= timedelta(hours=1)

jwt = JWTManager(app)

# ================= MONGODB =================
MONGO_URI = os.environ.get("MONGO_URI")
client    = MongoClient(MONGO_URI)
db        = client["Users"]
collection        = db["Users"]
inscripciones_col = db["Inscripciones"]   

# ================= UPLOADS =================
UPLOAD_FOLDER     = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)   
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ================= SENDGRID =================
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL       = os.environ.get("FROM_EMAIL")

# ================= SERIALIZER =================
serializer = Serializer(app.secret_key, salt="password-reset-salt")

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
        usuario = get_jwt_identity()
    except Exception:
        usuario = None
    return dict(usuario=usuario)

# ======================================================
# FUNCIÓN PARA ENVIAR EMAIL
# ======================================================

def enviar_email(destinatario, asunto, cuerpo):
    mensaje = Mail(
        from_email='fgrimaldo@corpsierramadre.com',
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

# ======================================================
# RUTAS PÚBLICAS
# ======================================================

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':

        matricula   = str(request.form.get('matricula', '')).strip()
        usuario     = str(request.form.get('usuario', '')).strip()
        email       = str(request.form.get('email', '')).lower().strip()
        contrasena  = str(request.form.get('contrasena', ''))

        if not matricula or not usuario or not email or not contrasena:
            abort(400)

        # validar matrícula solo números
        if not matricula.isdigit():
            flash("La matrícula debe contener solo números.", "error")
            return redirect(url_for('registro'))

        # validar nombre
        if not validar_no_sql_injection(usuario):
            flash("Nombre inválido.", "error")
            return redirect(url_for('registro'))

        # validar dominio
        if not email.endswith("@virtual.utsc.edu.mx"):
            flash("Debe usar un correo institucional @virtual.utsc.edu.mx", "error")
            return redirect(url_for('registro'))

        # validar contraseña segura
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$'

        if not re.fullmatch(password_regex, contrasena):
            flash("La contraseña debe tener mínimo 8 caracteres, incluir mayúscula, minúscula, número y símbolo.", "error")
            return redirect(url_for('registro'))

        # verificar si ya existe matrícula
        if collection.find_one({'matricula': matricula}):
            flash("La matrícula ya está registrada.", "error")
            return redirect(url_for('registro'))

        # verificar email
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
                'bloqueado_hasta': None
        })

        flash("Registro exitoso. Inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        matricula   = str(request.form.get('matricula', '')).strip()
        contrasena  = str(request.form.get('contrasena', ''))

        if not matricula or not contrasena:
            abort(400)

        user = collection.find_one({'matricula': matricula})

        if not user:
            flash("Matrícula o contraseña incorrectos.", "error")
            return render_template('login.html')

        # =========================
        # VERIFICAR SI ESTA BLOQUEADO
        # =========================

        bloqueado_hasta = user.get('bloqueado_hasta')

        if bloqueado_hasta and datetime.utcnow() < bloqueado_hasta:
            minutos_restantes = int((bloqueado_hasta - datetime.utcnow()).total_seconds() / 60)
            flash(f"Cuenta bloqueada temporalmente. Intente nuevamente en {minutos_restantes} minutos.", "error")
            return render_template('login.html')

        # =========================
        # VALIDAR CONTRASEÑA
        # =========================

        if bcrypt.check_password_hash(user['contrasena'], contrasena):

            # resetear intentos
            collection.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'intentos_fallidos': 0,
                        'bloqueado_hasta': None
                    }
                }
            )

            access_token = create_access_token(identity=user['matricula'])

            response = redirect(url_for('pagina_principal'))
            set_access_cookies(response, access_token)

            return response

        # =========================
        # CONTRASEÑA INCORRECTA
        # =========================

        intentos = user.get('intentos_fallidos', 0) + 1

        if intentos >= MAX_INTENTOS:

            bloqueo = datetime.utcnow() + timedelta(minutes=TIEMPO_BLOQUEO_MINUTOS)

            collection.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'intentos_fallidos': intentos,
                        'bloqueado_hasta': bloqueo
                    }
                }
            )

            flash("Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos.", "error")

        else:

            restantes = MAX_INTENTOS - intentos

            collection.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'intentos_fallidos': intentos
                    }
                }
            )

            flash(f"Contraseña incorrecta. Te quedan {restantes} intentos.", "error")

        return render_template('login.html')

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
    return render_template(
        "index.html",
        usuario=user["usuario"]  
    )


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
    usuario = get_jwt_identity()
    return render_template('inscripcion.html', usuario=usuario)


@app.route('/reinscripcion')
@jwt_required()
def reinscripcion():
    usuario = get_jwt_identity()
    return render_template('reinscripcion.html', usuario=usuario)


@app.route('/soporte')
@jwt_required()
def soporte():
    usuario = get_jwt_identity()
    return render_template('soporte.html', usuario=usuario)

# ======================================================
# INSCRIPCIÓN — PROCESAR FORMULARIO MULTI-PASO
# ======================================================

@app.route('/inscripcion_submit', methods=['POST'])
@jwt_required()
def inscripcion_submit():
    usuario = get_jwt_identity()

    # ===== LEER CAMPOS =====
    nombre      = request.form.get('nombre', '').strip()
    curp        = request.form.get('curp', '').strip().upper()
    fecha_nac   = request.form.get('fecha_nacimiento', '').strip()
    telefono    = request.form.get('telefono', '').strip()
    carrera     = request.form.get('carrera', '').strip()
    cont_nombre = request.form.get('contacto_emergencia_nombre', '').strip()
    cont_tel    = request.form.get('contacto_emergencia_tel', '').strip()

    # ===== VALIDACIÓN BACKEND =====
    if not all([nombre, curp, fecha_nac, telefono, carrera, cont_nombre, cont_tel]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('inscripcion'))

    # ===== GUARDAR ARCHIVOS =====
    def guardar_archivo(campo):
        archivo = request.files.get(campo)
        if archivo and allowed_file(archivo.filename):
            nombre_seguro = secure_filename(archivo.filename)
            nombre_unico  = f"{uuid.uuid4().hex}_{nombre_seguro}"
            archivo.save(os.path.join(UPLOAD_FOLDER, nombre_unico))
            return nombre_unico
        return None

    foto        = guardar_archivo('fotografia')
    doc_acta    = guardar_archivo('doc_acta')
    doc_cert    = guardar_archivo('doc_cert')
    comprobante = guardar_archivo('comprobante')

    if not all([foto, doc_acta, doc_cert, comprobante]):
        flash("Todos los documentos son obligatorios.", "error")
        return redirect(url_for('inscripcion'))

    # ===== GENERAR FOLIO =====
    folio = 'UTSC-' + uuid.uuid4().hex[:8].upper()

    # ===== GUARDAR EN MONGODB =====
    inscripciones_col.insert_one({
        'usuario'                   : usuario,
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
        'estatus'                   : 'En revisión'
    })

    return render_template('exito_inscripcion.html',
        usuario                    = usuario,
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
    import json
    usuario = get_jwt_identity()

    # ===== LEER CAMPOS =====
    matricula       = request.form.get('matricula', '').strip()
    nombre          = request.form.get('nombre', '').strip()
    correo          = request.form.get('correo', '').strip().lower()
    telefono        = request.form.get('telefono', '').strip()
    carrera_clave   = request.form.get('carrera_clave', '').strip()
    cuatrimestre    = request.form.get('cuatrimestre', '').strip()
    referencia_pago = request.form.get('referencia_pago', '').strip()
    fecha_pago      = request.form.get('fecha_pago', '').strip()
    es_estadia      = request.form.get('es_estadia', '0').strip() == '1'

    # Matrícula: solo números, sin restricción de longitud
    if not matricula or not matricula.isdigit():
        flash("La matrícula debe contener solo números.", "error")
        return redirect(url_for('reinscripcion'))

    # Nombre completo de carrera
    CARRERAS = {
        'ITID': 'Ing. en Tecnologías de la Información e Innovación Digital',
        'II':   'Ingeniería Industrial',
        'IMI':  'Ing. en Mantenimiento Industrial',
        'IMT':  'Ingeniería Mecatrónica',
        'IE':   'Ingeniería en Electromovilidad',
        'LNM':  'Lic. en Negocios y Mercadotecnia',
        'LLI':  'Lic. en Educación (Enseñanza del Idioma Inglés)'
    }
    carrera_nombre = CARRERAS.get(carrera_clave, carrera_clave)

    # Materias vienen como JSON: ["CLAVE|Nombre", ...]
    materias_raw = request.form.get('materias', '[]')
    try:
        materias_lista = json.loads(materias_raw)
        materias = [m.split('|')[1] if '|' in m else m for m in materias_lista]
    except Exception:
        materias = []

    # ===== VALIDACIÓN BACKEND =====
    if not all([nombre, correo, telefono, carrera_clave, cuatrimestre, referencia_pago, fecha_pago]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('reinscripcion'))

    # Solo exigir materias si NO es estadía
    if not es_estadia and not materias:
        flash("Debes seleccionar al menos una materia.", "error")
        return redirect(url_for('reinscripcion'))

    # ===== GUARDAR COMPROBANTE =====
    def guardar_archivo(campo):
        archivo = request.files.get(campo)
        if archivo and allowed_file(archivo.filename):
            nombre_seguro = secure_filename(archivo.filename)
            nombre_unico  = f"{uuid.uuid4().hex}_{nombre_seguro}"
            archivo.save(os.path.join(UPLOAD_FOLDER, nombre_unico))
            return nombre_unico
        return None

    comprobante = guardar_archivo('comprobante')
    if not comprobante:
        flash("El comprobante de pago es obligatorio.", "error")
        return redirect(url_for('reinscripcion'))

    # ===== GENERAR FOLIO =====
    folio = 'REINSC-' + uuid.uuid4().hex[:8].upper()

    # ===== GUARDAR EN MONGODB =====
    reinscripciones_col = db["Reinscripciones"]
    reinscripciones_col.insert_one({
        'usuario'        : usuario,
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
        'estatus'        : 'En revisión'
    })

    return render_template('exito_reinscripcion.html',
        usuario         = usuario,
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