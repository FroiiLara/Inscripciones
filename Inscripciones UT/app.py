import os
import re
import uuid
import json
import calendar
from datetime import timedelta, datetime

# Bloqueo por intentos fallidos de inicio de sesión (ver sección "CONTROL DE INTENTOS")
MAX_INTENTOS_IP        = 5     # fallos por pareja (matrícula + dirección IP) antes de bloquear
MAX_INTENTOS_CUENTA    = 15    # fallos desde cualquier IP antes de bloquear la cuenta completa
TIEMPO_BLOQUEO_MINUTOS = 15

from dotenv import load_dotenv
from flask import (
    Flask, request, render_template,
    redirect, url_for, flash, abort, jsonify,
    send_from_directory, send_file
)
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
from werkzeug.utils import secure_filename
from markupsafe import escape
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from pymongo.errors import DuplicateKeyError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import reportes   # estadísticas del dashboard y exportación a Excel

# ================= CLOUDINARY =================
import cloudinary
import cloudinary.uploader

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt,
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

# Render (y cualquier proxy inverso) envía la IP real del cliente en X-Forwarded-For.
# Sin esto, el límite de intentos vería siempre la IP del proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

ES_PRODUCCION = (os.environ.get('FLASK_ENV', 'production') != 'development'
                 and os.environ.get('DEBUG', '').lower() != 'true')

# Las claves deben existir y ser largas; si no, cualquiera podría falsificar sesiones.
for _nombre in ("SECRET_KEY", "JWT_SECRET_KEY"):
    _valor = os.environ.get(_nombre) or ""
    if not _valor:
        raise RuntimeError(f"Falta la variable de entorno {_nombre}.")
    if len(_valor) < 32:
        print(f"ADVERTENCIA: {_nombre} tiene menos de 32 caracteres; genera una más larga "
              f"(python -c \"import secrets; print(secrets.token_hex(32))\").")

# ── CORS ──────────────────────────────────────────────────
# La app móvil no usa CORS (no es un navegador) y la web llama a /api desde el mismo
# origen, así que por defecto NO se permite ningún origen externo.
# Si algún día hay otro sitio web que deba consumir la API: CORS_ORIGINS="https://sitio1,https://sitio2"
_cors_origenes = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
CORS(app, resources={
    r"/api/*": {
        "origins": _cors_origenes,
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

bcrypt = Bcrypt(app)

# ── Límite de tamaño de las peticiones (tope total; cada archivo se limita aparte) ──
MAX_ARCHIVO_BYTES = 5 * 1024 * 1024            # 5 MB por documento
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

# ── Cookie de sesión de Flask (la usan los mensajes flash) ──
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"]   = ES_PRODUCCION

# ================= JWT CONFIG =================
app.config["JWT_SECRET_KEY"]            = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_TOKEN_LOCATION"]        = ["cookies", "headers"]
app.config["JWT_ACCESS_COOKIE_PATH"]    = "/"
# Cookies del navegador: solo HTTPS, no accesibles desde JavaScript y nunca enviadas
# desde otro sitio (SameSite=Strict) + token CSRF obligatorio en cada formulario POST.
app.config["JWT_COOKIE_SECURE"]         = ES_PRODUCCION
app.config["JWT_COOKIE_SAMESITE"]       = "Strict"
app.config["JWT_COOKIE_CSRF_PROTECT"]   = True
app.config["JWT_CSRF_CHECK_FORM"]       = True
app.config["JWT_ACCESS_CSRF_FIELD_NAME"] = "csrf_token"
# Vida de los tokens: la app móvil usa un access token corto + refresh token que rota;
# el navegador usa un access token más largo en cookie.
ACCESS_MOVIL_MINUTOS = 15
ACCESS_WEB_MINUTOS   = 60
REFRESH_DIAS         = 14
app.config["JWT_ACCESS_TOKEN_EXPIRES"]  = timedelta(minutes=ACCESS_MOVIL_MINUTOS)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=REFRESH_DIAS)

jwt = JWTManager(app)

# ================= LÍMITE DE PETICIONES =================
# Almacén en memoria: suficiente para una sola instancia (Render con un proceso).
# Si se escala a varias instancias, usar RATELIMIT_STORAGE_URI=redis://...
app.config["RATELIMIT_ENABLED"] = os.environ.get("RATELIMIT_ENABLED", "true").lower() != "false"
limiter = Limiter(
    get_remote_address, app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    default_limits=[], headers_enabled=False,
)
# Límites por IP. Ojo: en la universidad muchos alumnos comparten la misma IP (Wi-Fi del
# plantel), por eso son holgados; el freno real a adivinar contraseñas es el bloqueo por
# matrícula + IP de verificar_credenciales().
LIMITE_LOGIN      = os.environ.get("LIMITE_LOGIN",      "30 per minute; 400 per hour")
LIMITE_REGISTRO   = os.environ.get("LIMITE_REGISTRO",   "30 per hour")
LIMITE_RECUPERAR  = os.environ.get("LIMITE_RECUPERAR",  "10 per hour")
LIMITE_TRAMITES   = os.environ.get("LIMITE_TRAMITES",   "60 per hour")
LIMITE_REFRESH    = os.environ.get("LIMITE_REFRESH",    "60 per hour")

# ======================================================
# SECURITY HEADERS — Correcciones del escáner de vulnerabilidades
# ======================================================

@app.after_request
def set_security_headers(response):
    # 1. Previene que el navegador adivine el tipo de contenido (anti-XSS)
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # 2. Fuerza HTTPS por 1 año e incluye subdominios (HSTS)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # 3. Política de seguridad de contenido — actualizada para resolver hallazgos del escáner
    #    base-uri 'self'   → previene inyección de etiquetas <base> maliciosas
    #    object-src 'none' → bloquea plugins Flash/Java obsoletos
    #    Dominios hCaptcha y Cloudinary incluidos explícitamente
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "script-src 'self' 'unsafe-inline' "
        "https://cdnjs.cloudflare.com "
        "https://js.hcaptcha.com "
        "https://newassets.hcaptcha.com; "
        "style-src 'self' 'unsafe-inline' "
        "https://cdnjs.cloudflare.com "
        "https://newassets.hcaptcha.com; "
        "font-src 'self' "
        "https://cdnjs.cloudflare.com "
        "https://newassets.hcaptcha.com; "
        "img-src 'self' data: "
        "https://res.cloudinary.com "
        "https://newassets.hcaptcha.com; "
        "frame-src https://newassets.hcaptcha.com; "
        "connect-src 'self' "
        "https://hcaptcha.com "
        "https://newassets.hcaptcha.com;"
    )

    # 4. Controla qué información de referencia se envía en peticiones externas
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # 5. Previene que la página sea embebida en iframes (anti-clickjacking)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # 6. Bloquear método OPTIONS — retorna 405 en lugar de 200
    #    Evita revelar métodos disponibles del servidor al escáner
    if request.method == 'OPTIONS':
        response.status_code = 405
        response.headers['Allow'] = 'GET, POST, HEAD'

    return response


@app.route('/.well-known/security.txt')
def security_txt():
    contenido = (
        "Contact: mailto:utsc@utsc.edu.mx\n"
        "Expires: 2027-01-01T00:00:00.000Z\n"
        "Preferred-Languages: es, en\n"
    )
    return contenido, 200, {'Content-Type': 'text/plain'}

# ======================================================
# API 1 — VALIDACIÓN CURP (RENAPO via consultacurp.com.mx)
# ======================================================

# PRIVACIDAD: esta consulta envía la CURP del alumno a un servicio de terceros
# (api.consultacurp.com.mx). Por eso (1) el formulario web y la app solo la hacen si el
# alumno lo autoriza con una casilla, (2) solo se envía la CURP, nunca otros datos, y
# (3) se puede desactivar por completo con CURP_VALIDACION_EXTERNA=false.
CURP_VALIDACION_EXTERNA = os.environ.get("CURP_VALIDACION_EXTERNA", "true").lower() != "false"


@app.route('/api/validar_curp/<curp>', methods=['GET'])
@limiter.limit(LIMITE_TRAMITES)
@jwt_required()
def api_validar_curp(curp):
    """Valida que una CURP exista en el registro nacional (RENAPO)."""
    import urllib.request

    if not CURP_VALIDACION_EXTERNA:
        return {'valida': None, 'mensaje': 'La verificación externa de la CURP está desactivada.'}, 503

    curp = curp.strip().upper()

    # Primero validar formato antes de consultar API externa
    curp_regex = re.compile(r'^[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]{2}$')
    if not curp_regex.match(curp):
        return {'valida': False, 'mensaje': 'Formato de CURP incorrecto.'}, 400

    try:
        url = f"https://api.consultacurp.com.mx/curp/{curp}"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'UTSC-Inscripciones/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())

        if data.get('registros') and len(data['registros']) > 0:
            registro = data['registros'][0]
            return {
                'valida'    : True,
                'nombre'    : registro.get('nombres', ''),
                'paterno'   : registro.get('primerApellido', ''),
                'materno'   : registro.get('segundoApellido', ''),
                'sexo'      : registro.get('sexo', ''),
                'nacimiento': registro.get('fechaNacimiento', ''),
                'estado'    : registro.get('claveEntidadRegistro', ''),
                'mensaje'   : 'CURP válida y encontrada en RENAPO.'
            }, 200
        else:
            return {'valida': False, 'mensaje': 'CURP no encontrada en RENAPO.'}, 404

    except Exception as e:
        print(f"Error consultando CURP API: {type(e).__name__}")   # sin imprimir la CURP
        return {'valida': None, 'mensaje': 'No fue posible verificar la CURP en este momento.'}, 503


# ======================================================
# API 2 — HCAPTCHA — verificación servidor
# ======================================================

HCAPTCHA_SECRET  = os.environ.get('HCAPTCHA_SECRET_KEY', '')
HCAPTCHA_SITEKEY = os.environ.get('HCAPTCHA_SITE_KEY', '')

def verificar_hcaptcha(token):
    """Verifica el token hCaptcha con el servidor de hCaptcha.
    En desarrollo local (FLASK_ENV=development o DEBUG=True) se omite la verificación.
    """
    import urllib.request
    import urllib.parse

    # Omitir verificación en desarrollo local
    entorno = os.environ.get('FLASK_ENV', 'production')
    es_local = entorno == 'development' or os.environ.get('DEBUG', '').lower() == 'true'
    if es_local:
        return True

    if not token or not HCAPTCHA_SECRET:
        return False
    try:
        data = urllib.parse.urlencode({
            'secret'  : HCAPTCHA_SECRET,
            'response': token
        }).encode()
        req = urllib.request.Request(
            'https://hcaptcha.com/siteverify',
            data=data, method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resultado = json.loads(resp.read().decode())
        return resultado.get('success', False)
    except Exception as e:
        print(f"Error verificando hCaptcha: {e}")
        return False


# ======================================================
# API 3 — GEOAPIFY — clave de entorno
# ======================================================

GEOAPIFY_KEY = os.environ.get('GEOAPIFY_API_KEY', '')

# ================= MONGODB =================
MONGO_URI = os.environ.get("MONGO_URI")
client    = MongoClient(MONGO_URI)
db        = client["Users"]
collection         = db["Users"]
inscripciones_col  = db["Inscripciones"]
reinscripciones_col = db["Reinscripciones"]
revocados_col      = db["tokens_revocados"]    # tokens JWT cerrados (logout / rotación)
reportes_usados_col = db["reportes_usados"]    # enlaces de descarga de reportes ya usados
login_intentos_col = db["login_intentos"]      # intentos fallidos por matrícula + IP


def asegurar_indices():
    """Índices TTL: MongoDB borra solo los registros de seguridad cuando ya no sirven."""
    try:
        revocados_col.create_index("expira", expireAfterSeconds=0)
        reportes_usados_col.create_index("expira", expireAfterSeconds=0)
        login_intentos_col.create_index("actualizado", expireAfterSeconds=24 * 3600)
    except Exception as e:                                   # no impedir el arranque
        print(f"No se pudieron crear los índices TTL: {e}")

asegurar_indices()

# ================= CLOUDINARY CONFIG =================
cloudinary.config(
    cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key    = os.environ.get("CLOUDINARY_API_KEY"),
    api_secret = os.environ.get("CLOUDINARY_API_SECRET"),
    secure     = True
)

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

# Firma ("magic bytes") con la que empieza cada tipo de archivo. Se comprueba el CONTENIDO real,
# no solo la extensión, para que no se pueda subir un .exe o .html renombrado a .pdf.
FIRMAS_ARCHIVO = {
    'pdf' : (b'%PDF-',),
    'jpg' : (b'\xff\xd8\xff',),
    'jpeg': (b'\xff\xd8\xff',),
    'png' : (b'\x89PNG\r\n\x1a\n',),
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validar_archivo(archivo, etiqueta, solo_imagen=False):
    """Valida un archivo subido. Devuelve None si es correcto o el mensaje de error."""
    if not archivo or not archivo.filename:
        return f"Falta el archivo: {etiqueta}."
    nombre = archivo.filename
    if not allowed_file(nombre):
        return f"{etiqueta}: solo se permiten archivos PDF, JPG o PNG."
    ext = nombre.rsplit('.', 1)[1].lower()
    if solo_imagen and ext == 'pdf':
        return f"{etiqueta}: debe ser una imagen JPG o PNG."

    flujo = archivo.stream
    flujo.seek(0, os.SEEK_END)
    tam = flujo.tell()
    flujo.seek(0)
    if tam == 0:
        return f"{etiqueta}: el archivo está vacío."
    if tam > MAX_ARCHIVO_BYTES:
        return f"{etiqueta}: el archivo supera el máximo de {MAX_ARCHIVO_BYTES // (1024 * 1024)} MB."

    cabecera = flujo.read(16)
    flujo.seek(0)
    if not any(cabecera.startswith(f) for f in FIRMAS_ARCHIVO[ext]):
        return f"{etiqueta}: el contenido no corresponde a un archivo {ext.upper()} válido."
    return None


def subir_documento(archivo, carpeta, etiqueta, solo_imagen=False):
    """Valida y sube un documento a Cloudinary. Devuelve (url, None) o (None, mensaje_de_error)."""
    error = validar_archivo(archivo, etiqueta, solo_imagen)
    if error:
        return None, error
    try:
        resultado = cloudinary.uploader.upload(
            archivo,
            folder=carpeta,
            resource_type="auto",                      # acepta pdf, jpg, png
            allowed_formats=["pdf", "jpg", "jpeg", "png"]   # Cloudinary rechaza cualquier otro
        )
        return resultado.get("secure_url"), None
    except Exception as e:
        print(f"Error al subir a Cloudinary: {e}")
        return None, f"{etiqueta}: no se pudo subir el archivo. Intenta de nuevo."

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

# ================= REGLAS DE NEGOCIO =================
EDAD_MINIMA      = 18
EDAD_MAXIMA      = 100
ESTATUS_VALIDOS  = ['Aprobada', 'Rechazada', 'En revisión']
MOTIVO_MIN       = 5
MOTIVO_MAX       = 500


def validar_fecha_nacimiento(texto, hoy=None):
    """Valida la fecha de nacimiento (formato AAAA-MM-DD) de una inscripción.
    Devuelve (True, date) o (False, mensaje_de_error).
    Reglas: formato válido, no futura y edad cumplida entre EDAD_MINIMA y EDAD_MAXIMA."""
    hoy = hoy or datetime.utcnow().date()
    try:
        fn = datetime.strptime(str(texto).strip(), "%Y-%m-%d").date()
    except ValueError:
        return False, "La fecha de nacimiento no tiene un formato válido."
    if fn > hoy:
        return False, "La fecha de nacimiento no puede ser futura."
    edad = reportes.calcular_edad(fn, hoy)
    if edad < EDAD_MINIMA:
        return False, f"Debes tener al menos {EDAD_MINIMA} años cumplidos para inscribirte."
    if edad > EDAD_MAXIMA:
        return False, "La fecha de nacimiento no es válida."
    return True, fn


def validar_motivo_rechazo(texto):
    """Devuelve (True, motivo_limpio) o (False, mensaje_de_error)."""
    motivo = " ".join(str(texto or "").split())      # quita saltos y espacios repetidos
    if len(motivo) < MOTIVO_MIN:
        return False, f"Escribe el motivo del rechazo (mínimo {MOTIVO_MIN} caracteres)."
    if len(motivo) > MOTIVO_MAX:
        return False, f"El motivo no puede exceder {MOTIVO_MAX} caracteres."
    return True, motivo

# ======================================================
# UTILIDADES DE SEGURIDAD
# ======================================================

def validar_no_sql_injection(dato):
    if isinstance(dato, dict): return False
    if "$" in str(dato): return False
    return True

PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,72}$'
PASSWORD_MENSAJE = ("La contraseña debe tener entre 8 y 72 caracteres e incluir mayúscula, "
                    "minúscula, número y símbolo.")

def password_valida(contrasena):
    """Política única de contraseñas (registro y restablecimiento).
    El máximo de 72 es el límite real de bcrypt: más caracteres se ignorarían."""
    return bool(re.fullmatch(PASSWORD_REGEX, contrasena or ""))


def ip_cliente():
    return get_remote_address() or "desconocida"


# ======================================================
# RESPUESTAS DE ERROR Y TOKENS JWT (sesiones revocables)
# ======================================================

def es_ruta_api():
    return request.path.startswith('/api/')


def respuesta_no_autenticado(codigo, mensaje):
    """JSON para la app móvil (con un 'codigo' que la app usa para renovar el token);
    para el navegador, volver al inicio de sesión."""
    if es_ruta_api():
        return jsonify(ok=False, codigo=codigo, mensaje=mensaje), 401
    respuesta = redirect(url_for('login'))
    unset_jwt_cookies(respuesta)
    return respuesta


def respuesta_csrf():
    """Formulario sin token CSRF válido (página vieja o petición falsificada desde otro sitio).
    La sesión NO se cierra: solo se rechaza esta petición."""
    mensaje = "El formulario expiró o no es válido. Recarga la página e intenta de nuevo."
    if es_ruta_api():
        return jsonify(ok=False, codigo="csrf", mensaje=mensaje), 403
    flash(mensaje, "error")
    return redirect(request.referrer or url_for('pagina_principal'))


@jwt.unauthorized_loader
def jwt_falta_token(motivo):
    # flask-jwt-extended reporta los fallos de CSRF (falta el token o no coincide) por aquí.
    if "CSRF" in str(motivo):
        return respuesta_csrf()
    return respuesta_no_autenticado("sin_token", "Inicia sesión para continuar.")

@jwt.invalid_token_loader
def jwt_token_invalido(motivo):
    if "CSRF" in str(motivo):
        return respuesta_csrf()
    return respuesta_no_autenticado("token_invalido", "Sesión inválida. Inicia sesión de nuevo.")

@jwt.expired_token_loader
def jwt_token_expirado(header, payload):
    return respuesta_no_autenticado("token_expirado", "Tu sesión expiró. Inicia sesión de nuevo.")

@jwt.revoked_token_loader
def jwt_token_revocado(header, payload):
    return respuesta_no_autenticado("token_revocado", "Tu sesión fue cerrada. Inicia sesión de nuevo.")


@jwt.token_in_blocklist_loader
def token_revocado(header, payload):
    """True si el token ya se cerró (logout/rotación) o si es anterior a un cambio de contraseña."""
    if revocados_col.find_one({"_id": payload["jti"]}):
        return True
    user = collection.find_one({"matricula": payload["sub"]}, {"sesiones_desde": 1})
    if not user:
        return True                      # cuenta eliminada: ningún token sigue siendo válido
    desde = user.get("sesiones_desde")
    # "<=": los tokens guardan la hora en segundos; así también cae el emitido en el mismo segundo.
    if desde and payload.get("iat", 0) <= calendar.timegm(desde.utctimetuple()):
        return True
    return False


def revocar_payload(payload):
    """Agrega un token (su jti) a la lista de revocados hasta que expire."""
    try:
        revocados_col.insert_one({
            "_id": payload["jti"],
            "expira": datetime.utcfromtimestamp(payload["exp"]),
        })
    except DuplicateKeyError:
        pass


def cerrar_todas_las_sesiones(matricula):
    """Invalida todos los tokens emitidos hasta este momento (p. ej. tras cambiar la contraseña)."""
    collection.update_one({"matricula": matricula},
                          {"$set": {"sesiones_desde": datetime.utcnow()}})


def emitir_tokens_movil(user):
    identidad = user['matricula']
    return (create_access_token(identity=identidad),
            create_refresh_token(identity=identidad))


# ======================================================
# CONTROL DE INTENTOS DE INICIO DE SESIÓN
# ======================================================
# Antes: 3 fallos bloqueaban la CUENTA completa, así que cualquiera podía dejar fuera a otro
# alumno solo escribiendo su matrícula mal tres veces. Ahora el bloqueo es por pareja
# (matrícula + IP): el atacante se bloquea a sí mismo, no al dueño de la cuenta.
# Además hay un tope global por cuenta (muy alto) contra ataques desde muchas IP, y un
# límite de peticiones por IP (Flask-Limiter) en las rutas de login.

MENSAJE_LOGIN_FALLIDO = "Matrícula o contraseña incorrectos."
# Hash falso: se compara también cuando la matrícula no existe, para que el tiempo de
# respuesta no delate qué matrículas están registradas.
_HASH_FALSO = bcrypt.generate_password_hash("contraseña-falsa-no-valida").decode('utf-8')


def _minutos_restantes(fecha):
    return max(1, int((fecha - datetime.utcnow()).total_seconds() // 60) + 1)


def verificar_credenciales(matricula, contrasena):
    """Devuelve (usuario, None) si las credenciales son correctas o (None, mensaje) si no.
    El mensaje es siempre genérico para no revelar si la matrícula existe."""
    ip    = ip_cliente()
    clave = f"{matricula[:40]}|{ip}"
    ahora = datetime.utcnow()

    registro = login_intentos_col.find_one({"_id": clave}) or {}
    if registro.get("bloqueado_hasta") and ahora < registro["bloqueado_hasta"]:
        return None, (f"Demasiados intentos fallidos. Intenta de nuevo en "
                      f"{_minutos_restantes(registro['bloqueado_hasta'])} minutos.")

    user = collection.find_one({"matricula": matricula})
    if user and user.get("bloqueado_hasta") and ahora < user["bloqueado_hasta"]:
        return None, (f"Cuenta bloqueada temporalmente por actividad sospechosa. "
                      f"Intenta de nuevo en {_minutos_restantes(user['bloqueado_hasta'])} minutos.")

    hash_guardado = user['contrasena'] if user else _HASH_FALSO
    correcta = bcrypt.check_password_hash(hash_guardado, contrasena)

    if user and correcta:
        login_intentos_col.delete_one({"_id": clave})
        collection.update_one({"_id": user["_id"]},
                              {"$set": {"intentos_fallidos": 0, "bloqueado_hasta": None}})
        return user, None

    # ── Fallo: contar por (matrícula + IP) ──
    intentos = registro.get("intentos", 0) + 1
    cambios = {"intentos": intentos, "actualizado": ahora}
    if intentos >= MAX_INTENTOS_IP:
        cambios["bloqueado_hasta"] = ahora + timedelta(minutes=TIEMPO_BLOQUEO_MINUTOS)
        cambios["intentos"] = 0
    login_intentos_col.update_one({"_id": clave}, {"$set": cambios}, upsert=True)

    # ── ... y contar el total de la cuenta (todas las IP) ──
    if user:
        total = user.get("intentos_fallidos", 0) + 1
        datos = {"intentos_fallidos": total}
        if total >= MAX_INTENTOS_CUENTA:
            datos["bloqueado_hasta"] = ahora + timedelta(minutes=TIEMPO_BLOQUEO_MINUTOS)
            datos["intentos_fallidos"] = 0
        collection.update_one({"_id": user["_id"]}, {"$set": datos})

    if "bloqueado_hasta" in cambios:
        return None, (f"Demasiados intentos fallidos. Intenta de nuevo en "
                      f"{TIEMPO_BLOQUEO_MINUTOS} minutos.")
    return None, MENSAJE_LOGIN_FALLIDO


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
    # Token CSRF (cookie "csrf_access_token" que crea flask-jwt-extended); los formularios
    # POST lo envían en el campo oculto "csrf_token".
    return dict(usuario=usuario, es_admin=es_admin,
                csrf_token=request.cookies.get('csrf_access_token', ''))

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

def enviar_notificacion_estatus(email, nombre, folio, tipo, nuevo_estatus, motivo=None):
    color = "#2e7d32" if nuevo_estatus == "Aprobada" else "#c62828"
    icono = "✅" if nuevo_estatus == "Aprobada" else "❌"
    asunto = f"{icono} Tu {tipo} ha sido {nuevo_estatus} — Folio {folio}"
    bloque_motivo = ""
    if nuevo_estatus == "Rechazada" and motivo:
        bloque_motivo = (
            '<div style="background:#ffebee;border-left:4px solid #c62828;padding:12px 16px;margin:20px 0;">'
            '<strong style="color:#c62828;">Motivo del rechazo:</strong><br>'
            f'{escape(motivo)}</div>'
            '<p style="color:#555;">Corrige lo indicado y vuelve a enviar tu solicitud.</p>'
        )
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
            {bloque_motivo}
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


@app.route('/service-worker.js')
def service_worker():
    """Sirve el Service Worker desde la raíz (no desde /static/) para que
    su 'scope' cubra todo el sitio y no solo la carpeta static."""
    response = send_from_directory('static', 'service-worker.js')
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Cache-Control'] = 'no-cache'
    return response


MENSAJE_REGISTRO_NO_COMPLETADO = ("No fue posible completar el registro. Verifica tus datos; "
                                  "si ya tienes cuenta, inicia sesión o recupera tu contraseña.")


@app.route('/registro', methods=['GET', 'POST'])
@limiter.limit(LIMITE_REGISTRO, methods=["POST"])
def registro():
    if request.method == 'POST':

        # ── hCaptcha verification ──
        hcaptcha_token = request.form.get('h-captcha-response', '')
        if HCAPTCHA_SECRET and not verificar_hcaptcha(hcaptcha_token):
            flash("Por favor completa el captcha de seguridad.", "error")
            return redirect(url_for('registro'))

        matricula  = str(request.form.get('matricula', '')).strip()
        usuario    = str(request.form.get('usuario', '')).strip()
        email      = str(request.form.get('email', '')).lower().strip()
        contrasena = str(request.form.get('contrasena', ''))

        if not matricula or not usuario or not email or not contrasena:
            abort(400)

        if not matricula.isdigit() or len(matricula) > 15:
            flash("La matrícula debe contener solo números.", "error")
            return redirect(url_for('registro'))

        if not validar_no_sql_injection(usuario) or len(usuario) > 100:
            flash("Nombre inválido.", "error")
            return redirect(url_for('registro'))

        if not email.endswith("@virtual.utsc.edu.mx") or len(email) > 100:
            flash("Debe usar un correo institucional @virtual.utsc.edu.mx", "error")
            return redirect(url_for('registro'))

        if not password_valida(contrasena):
            flash(PASSWORD_MENSAJE, "error")
            return redirect(url_for('registro'))

        # Mensaje único para "matrícula repetida" y "correo repetido": así nadie puede
        # usar este formulario para averiguar qué matrículas o correos ya están registrados.
        if collection.find_one({'$or': [{'matricula': matricula}, {'email': email}]}):
            flash(MENSAJE_REGISTRO_NO_COMPLETADO, "error")
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

    return render_template('register.html', hcaptcha_sitekey=HCAPTCHA_SITEKEY)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(LIMITE_LOGIN, methods=["POST"])
def login():

    if request.method == 'POST':

        # ── hCaptcha verification ──
        hcaptcha_token = request.form.get('h-captcha-response', '')
        if HCAPTCHA_SECRET and not verificar_hcaptcha(hcaptcha_token):
            flash("Por favor completa el captcha de seguridad.", "error")
            return render_template('login.html', hcaptcha_sitekey=HCAPTCHA_SITEKEY)

        matricula  = str(request.form.get('matricula', '')).strip()
        contrasena = str(request.form.get('contrasena', ''))

        if not matricula or not contrasena:
            abort(400)

        user, error = verificar_credenciales(matricula, contrasena)
        if error:
            flash(error, "error")
            return render_template('login.html', matricula_guardada=matricula,
                                   hcaptcha_sitekey=HCAPTCHA_SITEKEY)

        access_token = create_access_token(identity=user['matricula'],
                                           expires_delta=timedelta(minutes=ACCESS_WEB_MINUTOS))
        response = redirect(url_for('pagina_principal'))
        set_access_cookies(response, access_token)
        return response

    return render_template('login.html', hcaptcha_sitekey=HCAPTCHA_SITEKEY)


@app.route('/logout')
@jwt_required()
def logout():
    revocar_payload(get_jwt())          # el token queda inservible aunque alguien lo haya copiado
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
    return render_template('soporte.html', usuario=nombre_usuario, geoapify_key=GEOAPIFY_KEY)

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


def aplicar_cambio_estatus(tipo, folio, nuevo_estatus, motivo, admin_matricula):
    """Lógica compartida por el panel web y la API móvil.
    Devuelve (ok, mensaje, codigo_http)."""
    if tipo not in ('inscripcion', 'reinscripcion'):
        return False, "Tipo de solicitud no válido.", 400
    if nuevo_estatus not in ESTATUS_VALIDOS:
        return False, "Estatus no válido.", 400

    motivo_limpio = None
    if nuevo_estatus == 'Rechazada':
        ok, resultado = validar_motivo_rechazo(motivo)
        if not ok:
            return False, resultado, 400
        motivo_limpio = resultado

    col = inscripciones_col if tipo == 'inscripcion' else reinscripciones_col
    doc = col.find_one({"folio": folio})
    if not doc:
        return False, "Solicitud no encontrada.", 404

    cambios = {"$set": {
        "estatus"       : nuevo_estatus,
        "fecha_revision": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        "revisado_por"  : admin_matricula,
    }}
    if motivo_limpio:
        cambios["$set"]["motivo_rechazo"] = motivo_limpio
    else:
        cambios["$unset"] = {"motivo_rechazo": ""}      # al aprobar / reabrir se borra el motivo previo
    col.update_one({"folio": folio}, cambios)

    # Notificar al alumno por correo si el estatus cambia a Aprobada o Rechazada
    if nuevo_estatus in ('Aprobada', 'Rechazada'):
        alumno = collection.find_one({"matricula": doc.get("usuario")})
        if alumno and alumno.get("email"):
            enviar_notificacion_estatus(
                alumno["email"],
                doc.get("nombre", alumno.get("usuario", "Alumno")),
                folio,
                "inscripción" if tipo == "inscripcion" else "reinscripción",
                nuevo_estatus,
                motivo_limpio
            )

    return True, f"Estatus del folio {folio} actualizado a '{nuevo_estatus}'.", 200


@app.route('/admin/actualizar_estatus', methods=['POST'])
@admin_required
def actualizar_estatus():
    ok, mensaje, _ = aplicar_cambio_estatus(
        tipo            = request.form.get('tipo', '').strip(),
        folio           = request.form.get('folio', '').strip(),
        nuevo_estatus   = request.form.get('estatus', '').strip(),
        motivo          = request.form.get('motivo', ''),
        admin_matricula = get_jwt_identity()
    )
    flash(mensaje, "success" if ok else "error")
    return redirect(url_for('admin_panel'))

# ======================================================
# DASHBOARD Y REPORTES DEL ADMINISTRADOR
# ======================================================

CAMPOS_DASHBOARD = {"_id": 0, "usuario": 1, "carrera": 1, "carrera_clave": 1, "cuatrimestre": 1,
                    "fecha_solicitud": 1, "fecha_nacimiento": 1, "estatus": 1, "es_estadia": 1}


def estadisticas_dashboard(estatus='Todas'):
    """Lee las solicitudes, aplica el filtro de estatus y calcula las estadísticas."""
    if estatus not in ESTATUS_VALIDOS:
        estatus = 'Todas'
    inscs  = list(inscripciones_col.find({}, CAMPOS_DASHBOARD))
    reincs = list(reinscripciones_col.find({}, CAMPOS_DASHBOARD))
    inscs  = reportes.filtrar_solicitudes(inscs,  CARRERAS, estatus=estatus)
    reincs = reportes.filtrar_solicitudes(reincs, CARRERAS, estatus=estatus)
    stats = reportes.construir_estadisticas(inscs, reincs, CARRERAS)
    stats['filtro_estatus'] = estatus
    return stats


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    estatus = request.args.get('estatus', 'Todas')
    stats = estadisticas_dashboard(estatus)
    return render_template('admin_dashboard.html', stats=stats,
                           estatus_sel=stats['filtro_estatus'], estatus_opciones=ESTATUS_VALIDOS)


def leer_filtros_reporte(datos):
    """Lee y valida tipo / estatus / carrera / fechas (de request.args o de un JSON).
    Devuelve (filtros_dict, None) o (None, mensaje_de_error)."""
    tipo    = str(datos.get('tipo') or 'general').strip()
    estatus = str(datos.get('estatus') or 'Todas').strip()
    carrera = str(datos.get('carrera') or 'Todas').strip()
    if tipo not in reportes.TIPOS_REPORTE:
        return None, "Tipo de reporte no válido."
    if estatus != 'Todas' and estatus not in ESTATUS_VALIDOS:
        return None, "Estatus no válido."
    if carrera != 'Todas' and carrera not in CARRERAS:
        return None, "Carrera no válida."
    desde = hasta = None
    for nombre in ('desde', 'hasta'):
        crudo = str(datos.get(nombre) or '').strip()
        if crudo:
            valor = reportes.parsear_fecha_iso(crudo)
            if valor is None:
                return None, f"La fecha '{nombre}' no es válida (usa AAAA-MM-DD)."
            if nombre == 'desde':
                desde = valor
            else:
                hasta = valor
    if desde and hasta and desde > hasta:
        return None, "La fecha 'desde' no puede ser posterior a 'hasta'."
    return {"tipo": tipo, "estatus": estatus, "carrera": carrera, "desde": desde, "hasta": hasta}, None


def datos_reporte(f):
    """Aplica los filtros a las solicitudes. Devuelve (inscripciones, reinscripciones)."""
    inscs  = list(inscripciones_col.find({}, {"_id": 0}))
    reincs = list(reinscripciones_col.find({}, {"_id": 0}))
    args = dict(estatus=f["estatus"], carrera=f["carrera"], desde=f["desde"], hasta=f["hasta"])
    return (reportes.filtrar_solicitudes(inscs, CARRERAS, **args),
            reportes.filtrar_solicitudes(reincs, CARRERAS, **args))


def respuesta_excel(f):
    """Construye la respuesta HTTP con el archivo .xlsx del reporte pedido."""
    inscs, reincs = datos_reporte(f)
    filtros_txt = reportes.descripcion_filtros(f["estatus"], f["carrera"], f["desde"], f["hasta"], CARRERAS)
    archivo = reportes.generar_excel(f["tipo"], inscs, reincs, CARRERAS, filtros_txt)
    nombre = f"reporte_{f['tipo']}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
    respuesta = send_file(
        archivo, as_attachment=True, download_name=nombre,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    respuesta.headers['Cache-Control'] = 'no-store'
    return respuesta


@app.route('/admin/reportes')
@admin_required
def admin_reportes():
    return render_template('admin_reportes.html', carreras=CARRERAS,
                           tipos=reportes.TIPOS_REPORTE, estatus_opciones=ESTATUS_VALIDOS)


@app.route('/admin/reportes/exportar')
@admin_required
def admin_reportes_exportar():
    filtros, error = leer_filtros_reporte(request.args)
    if error:
        flash(error, "error")
        return redirect(url_for('admin_reportes'))
    return respuesta_excel(filtros)


# Enlaces firmados y temporales: permiten que la app móvil abra la descarga en el
# navegador del teléfono (que no puede enviar el token JWT en la cabecera).
reporte_serializer = Serializer(app.secret_key, salt="reporte-xlsx")
REPORTE_ENLACE_SEGUNDOS = 600


def url_externa(endpoint, **valores):
    """url_for(_external=True) pero respetando HTTPS detrás del proxy de Render."""
    url = url_for(endpoint, _external=True, **valores)
    proto = request.headers.get('X-Forwarded-Proto', '').split(',')[0].strip()
    if proto == 'https' and url.startswith('http://'):
        url = 'https://' + url[len('http://'):]
    return url


@app.route('/descargar_reporte/<token>')
def descargar_reporte(token):
    try:
        datos = reporte_serializer.loads(token, max_age=REPORTE_ENLACE_SEGUNDOS)
    except SignatureExpired:
        return render_template("403.html"), 403
    except BadSignature:
        abort(403)
    admin = collection.find_one({"matricula": datos.get("admin")})
    if not admin or not admin.get("es_admin", False):
        abort(403)
    filtros, error = leer_filtros_reporte(datos)
    if error:
        abort(400)
    # Un solo uso: se registra el jti; si ya existe, el enlace ya se descargó (o se filtró).
    jti = datos.get("jti")
    if not jti:
        abort(403)
    try:
        reportes_usados_col.insert_one({
            "_id": jti,
            "expira": datetime.utcnow() + timedelta(seconds=REPORTE_ENLACE_SEGUNDOS + 60),
        })
    except DuplicateKeyError:
        return render_template("403.html"), 403
    return respuesta_excel(filtros)

# ======================================================
# INSCRIPCIÓN Y REINSCRIPCIÓN — LÓGICA COMPARTIDA (web y app móvil)
# Toda la validación vive aquí, en el servidor: la app y el navegador solo la repiten
# por comodidad del usuario, pero nunca se confía en ellas.
# ======================================================

CURP_REGEX         = re.compile(r'^[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]{2}$')
NOMBRE_REGEX       = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ][A-Za-zÁÉÍÓÚÜÑáéíóúüñ .'-]{3,99}$")
TELEFONO_REGEX     = re.compile(r'^\d{10}$')
CORREO_REGEX       = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$')
REFERENCIA_REGEX   = re.compile(r'^[A-Za-z0-9._/\- ]{3,30}$')
CUATRIMESTRE_REGEX = re.compile(r'^(\d{1,2}|\d{4}-[ABCabc])$')
MAX_MATERIAS       = 15


def leer_materias(crudo):
    """Convierte el JSON de materias en una lista de nombres. Devuelve None si es inválido."""
    try:
        lista = json.loads(crudo or '[]')
    except ValueError:
        return None
    if not isinstance(lista, list) or len(lista) > MAX_MATERIAS:
        return None
    materias = []
    for m in lista:
        if not isinstance(m, str) or not m.strip() or len(m) > 150:
            return None
        materias.append((m.split('|', 1)[1] if '|' in m else m).strip())
    return materias


def procesar_inscripcion(matricula_jwt, user, form, files):
    """Valida los datos, sube los documentos y guarda la inscripción.
    Devuelve (True, documento_guardado) o (False, mensaje_de_error)."""
    nombre      = " ".join(form.get('nombre', '').split())
    curp        = form.get('curp', '').strip().upper()
    fecha_nac   = form.get('fecha_nacimiento', '').strip()
    telefono    = form.get('telefono', '').strip()
    carrera     = form.get('carrera', '').strip()
    cont_nombre = " ".join(form.get('contacto_emergencia_nombre', '').split())
    cont_tel    = form.get('contacto_emergencia_tel', '').strip()

    if not all([nombre, curp, fecha_nac, telefono, carrera, cont_nombre, cont_tel]):
        return False, "Todos los campos son obligatorios."
    if not NOMBRE_REGEX.match(nombre):
        return False, "El nombre solo puede contener letras y espacios (mínimo 4 caracteres)."
    if not CURP_REGEX.match(curp):
        return False, "La CURP no tiene el formato correcto."

    fecha_ok, resultado = validar_fecha_nacimiento(fecha_nac)
    if not fecha_ok:
        return False, resultado

    if not TELEFONO_REGEX.match(telefono):
        return False, "El teléfono debe tener 10 dígitos."
    if carrera not in CARRERAS:
        return False, "Selecciona una carrera válida."
    if not NOMBRE_REGEX.match(cont_nombre):
        return False, "El nombre del contacto de emergencia no es válido."
    if not TELEFONO_REGEX.match(cont_tel):
        return False, "El teléfono del contacto de emergencia debe tener 10 dígitos."

    # ===== VALIDAR Y SUBIR ARCHIVOS A CLOUDINARY =====
    documentos = (
        ('fotografia',  'Fotografía',               'inscripciones/fotografias',  True),
        ('doc_acta',    'Acta de nacimiento',        'inscripciones/actas',        False),
        ('doc_cert',    'Certificado de bachillerato', 'inscripciones/certificados', False),
        ('comprobante', 'Comprobante de pago',       'inscripciones/comprobantes', False),
    )
    # Primero se validan TODOS (sin subir nada), para no dejar archivos huérfanos en la nube.
    for campo, etiqueta, _, solo_img in documentos:
        error = validar_archivo(files.get(campo), etiqueta, solo_img)
        if error:
            return False, error
    urls = {}
    for campo, etiqueta, carpeta, solo_img in documentos:
        urls[campo], error = subir_documento(files.get(campo), carpeta, etiqueta, solo_img)
        if error:
            return False, error

    folio = 'UTSC-' + uuid.uuid4().hex[:8].upper()
    doc = {
        'usuario'                   : matricula_jwt,
        'folio'                     : folio,
        'nombre'                    : nombre,
        'curp'                      : curp,
        'fecha_nacimiento'          : fecha_nac,
        'telefono'                  : telefono,
        'carrera'                   : carrera,
        'contacto_emergencia_nombre': cont_nombre,
        'contacto_emergencia_tel'   : cont_tel,
        'fotografia'                : urls['fotografia'],
        'doc_acta'                  : urls['doc_acta'],
        'doc_cert'                  : urls['doc_cert'],
        'comprobante'               : urls['comprobante'],
        'estatus'                   : 'En revisión',
        'fecha_solicitud'           : datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    }
    inscripciones_col.insert_one(dict(doc))

    # ===== ENVIAR CORREO DE CONFIRMACIÓN =====
    if user and user.get("email"):
        enviar_confirmacion_inscripcion(user["email"], nombre, folio, carrera)
    return True, doc


def procesar_reinscripcion(matricula_jwt, user, form, files, exigir_contacto=True):
    """Valida, sube el comprobante y guarda la reinscripción.
    exigir_contacto=False (app móvil): correo y teléfono son opcionales; el correo
    se toma de la cuenta. Devuelve (True, documento_guardado) o (False, mensaje)."""
    matricula       = form.get('matricula', '').strip()
    nombre          = " ".join(form.get('nombre', '').split())
    correo          = form.get('correo', '').strip().lower()
    telefono        = form.get('telefono', '').strip()
    carrera_clave   = form.get('carrera_clave', '').strip()
    cuatrimestre    = form.get('cuatrimestre', '').strip()
    referencia_pago = form.get('referencia_pago', '').strip()
    fecha_pago      = form.get('fecha_pago', '').strip()
    es_estadia      = form.get('es_estadia', '0').strip().lower() in ('1', 'true')

    if not correo and not exigir_contacto and user:
        correo = user.get('email', '')

    obligatorios = [matricula, nombre, carrera_clave, cuatrimestre, referencia_pago, fecha_pago]
    if exigir_contacto:
        obligatorios += [correo, telefono]
    if not all(obligatorios):
        return False, "Todos los campos son obligatorios."

    if not matricula.isdigit():
        return False, "La matrícula debe contener solo números."
    if matricula != matricula_jwt:
        return False, "La matrícula debe coincidir con la de tu cuenta."
    if not NOMBRE_REGEX.match(nombre):
        return False, "El nombre solo puede contener letras y espacios (mínimo 4 caracteres)."
    if correo and not CORREO_REGEX.match(correo):
        return False, "El correo electrónico no es válido."
    if telefono and not TELEFONO_REGEX.match(telefono):
        return False, "El teléfono debe tener 10 dígitos."
    if carrera_clave not in CARRERAS:
        return False, "Selecciona una carrera válida."
    if not CUATRIMESTRE_REGEX.match(cuatrimestre) or (cuatrimestre.isdigit() and not 1 <= int(cuatrimestre) <= 10):
        return False, "El cuatrimestre no es válido."
    if not REFERENCIA_REGEX.match(referencia_pago):
        return False, "La referencia de pago no es válida (3 a 30 letras, números o guiones)."
    try:
        f_pago = datetime.strptime(fecha_pago, "%Y-%m-%d").date()
    except ValueError:
        return False, "La fecha de pago no tiene un formato válido."
    if f_pago > datetime.utcnow().date() + timedelta(days=1):
        return False, "La fecha de pago no puede ser futura."

    materias = leer_materias(form.get('materias', '[]'))
    if materias is None:
        return False, "La lista de materias no es válida."
    if not es_estadia and not materias:
        return False, "Debes seleccionar al menos una materia."

    comprobante, error = subir_documento(files.get('comprobante'),
                                         "reinscripciones/comprobantes", "Comprobante de pago")
    if error:
        return False, error

    carrera_nombre = CARRERAS[carrera_clave]
    folio = 'REINSC-' + uuid.uuid4().hex[:8].upper()
    doc = {
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
    }
    reinscripciones_col.insert_one(dict(doc))

    if user and user.get("email"):
        enviar_confirmacion_reinscripcion(user["email"], nombre, folio, carrera_nombre, cuatrimestre)
    return True, doc


# ======================================================
# INSCRIPCIÓN — PROCESAR FORMULARIO MULTI-PASO (web)
# ======================================================

@app.route('/inscripcion_submit', methods=['POST'])
@limiter.limit(LIMITE_TRAMITES)
@jwt_required()
def inscripcion_submit():
    matricula_jwt = get_jwt_identity()
    user = collection.find_one({"matricula": matricula_jwt})

    ok, resultado = procesar_inscripcion(matricula_jwt, user, request.form, request.files)
    if not ok:
        flash(resultado, "error")
        return redirect(url_for('inscripcion'))

    return render_template('exito_inscripcion.html',
        usuario                    = matricula_jwt,
        folio                      = resultado['folio'],
        nombre                     = resultado['nombre'],
        curp                       = resultado['curp'],
        fecha_nacimiento           = resultado['fecha_nacimiento'],
        telefono                   = resultado['telefono'],
        carrera                    = resultado['carrera'],
        contacto_emergencia_nombre = resultado['contacto_emergencia_nombre'],
        contacto_emergencia_tel    = resultado['contacto_emergencia_tel']
    )

# ======================================================
# REINSCRIPCIÓN — PROCESAR FORMULARIO MULTI-PASO (web)
# ======================================================

@app.route('/reinscripcion_submit', methods=['POST'])
@limiter.limit(LIMITE_TRAMITES)
@jwt_required()
def reinscripcion_submit():
    matricula_jwt = get_jwt_identity()
    user = collection.find_one({"matricula": matricula_jwt})

    ok, resultado = procesar_reinscripcion(matricula_jwt, user, request.form, request.files)
    if not ok:
        flash(resultado, "error")
        return redirect(url_for('reinscripcion'))

    return render_template('exito_reinscripcion.html',
        usuario         = matricula_jwt,
        folio           = resultado['folio'],
        matricula       = resultado['matricula'],
        nombre          = resultado['nombre'],
        correo          = resultado['correo'],
        carrera         = resultado['carrera'],
        cuatrimestre    = resultado['cuatrimestre'],
        es_estadia      = resultado['es_estadia'],
        materias        = resultado['materias'],
        referencia_pago = resultado['referencia_pago'],
        fecha_pago      = resultado['fecha_pago']
    )

# ======================================================
# RECUPERACIÓN DE CONTRASEÑA
# ======================================================
# El enlace del correo es de UN SOLO USO: el token incluye el final del hash de la contraseña
# actual, así que en cuanto la contraseña cambia, el enlace deja de ser válido.

RESET_SEGUNDOS = 3600
MENSAJE_RECUPERAR = "Si el correo está registrado, te enviamos un enlace para restablecer tu contraseña."


def generar_token_reset(user):
    return serializer.dumps({"email": user["email"], "h": user["contrasena"][-12:]},
                            salt='password-reset-salt')


def usuario_de_token_reset(token):
    """Devuelve el usuario dueño del token o None si es inválido, caducó o ya se usó."""
    try:
        datos = serializer.loads(token, salt='password-reset-salt', max_age=RESET_SEGUNDOS)
    except (SignatureExpired, BadSignature):
        return None
    if not isinstance(datos, dict):
        return None
    user = collection.find_one({"email": datos.get("email")})
    if not user or user["contrasena"][-12:] != datos.get("h"):
        return None
    return user


def enviar_enlace_reset(user):
    token  = generar_token_reset(user)
    enlace = url_externa('restablecer_contrasena', token=token)
    asunto = "Recuperación de contraseña — UTSC"
    cuerpo = f"""
        <p>Hola <strong>{escape(user.get('usuario', ''))}</strong>,</p>
        <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
        <p>Haz clic en el siguiente enlace para crear una nueva contraseña:</p>
        <p><a href="{enlace}" style="background:#1A5F5C;color:white;padding:10px 20px;border-radius:5px;text-decoration:none;">
            Restablecer contraseña
        </a></p>
        <p>Este enlace expirará en <strong>1 hora</strong> y solo se puede usar una vez.</p>
        <p>Si no solicitaste este cambio, ignora este mensaje.</p>
        <p>Saludos,<br>Control Escolar UTSC</p>
    """
    enviar_email(user["email"], asunto, cuerpo)


@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
@limiter.limit(LIMITE_RECUPERAR, methods=["POST"])
def recuperar_contrasena():
    if request.method == 'POST':
        email   = str(request.form.get('email', '')).lower().strip()
        usuario = collection.find_one({'email': email}) if email else None

        if usuario:
            try:
                enviar_enlace_reset(usuario)
            except Exception as e:
                print(f"Error enviando correo de recuperación: {e}")
        # Misma respuesta exista o no el correo: no se puede usar para descubrir cuentas.
        flash(MENSAJE_RECUPERAR, "success")

    return render_template('recuperar_contrasena.html')


@app.route('/restablecer_contrasena/<token>', methods=['GET', 'POST'])
@limiter.limit(LIMITE_RECUPERAR, methods=["POST"])
def restablecer_contrasena(token):
    user = usuario_de_token_reset(token)
    if not user:
        flash("El enlace de restablecimiento ha caducado, ya fue utilizado o es inválido.", "error")
        return redirect(url_for('recuperar_contrasena'))

    if request.method == 'POST':
        nueva     = str(request.form.get('nueva_contrasena', ''))
        confirmar = str(request.form.get('confirmar_contrasena', nueva))
        if nueva != confirmar:
            flash("Las contraseñas no coinciden.", "error")
            return render_template('restablecer_contrasena.html')
        if not password_valida(nueva):
            flash(PASSWORD_MENSAJE, "error")
            return render_template('restablecer_contrasena.html')

        hashed = bcrypt.generate_password_hash(nueva).decode('utf-8')
        collection.update_one({'_id': user['_id']}, {'$set': {
            'contrasena': hashed, 'intentos_fallidos': 0, 'bloqueado_hasta': None}})
        login_intentos_col.delete_many({"_id": {"$regex": f"^{re.escape(user['matricula'])}\\|"}})
        cerrar_todas_las_sesiones(user['matricula'])      # las sesiones abiertas dejan de servir
        flash("Tu contraseña ha sido restablecida con éxito. Inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')

# ======================================================
# MANEJADORES DE ERRORES
# ======================================================

def error_http(codigo, mensaje, plantilla):
    """Respuesta de error: JSON para /api/, página HTML para el navegador."""
    if es_ruta_api():
        return jsonify(ok=False, mensaje=mensaje), codigo
    return render_template(plantilla), codigo

@app.errorhandler(400)
def bad_request(e):      return error_http(400, "Solicitud inválida.", "400.html")

@app.errorhandler(401)
def unauthorized(e):     return error_http(401, "No autorizado.", "401.html")

@app.errorhandler(403)
def forbidden(e):        return error_http(403, "Acceso denegado.", "403.html")

@app.errorhandler(404)
def not_found(e):        return error_http(404, "Recurso no encontrado.", "404.html")

@app.errorhandler(413)
def demasiado_grande(e):
    mensaje = "Los archivos enviados superan el tamaño máximo permitido."
    if es_ruta_api():
        return jsonify(ok=False, mensaje=mensaje), 413
    flash(mensaje, "error")
    destino = request.referrer or url_for('login')
    return redirect(destino)

@app.errorhandler(429)
def demasiadas_peticiones(e):
    mensaje = "Demasiadas solicitudes. Espera un momento e intenta de nuevo."
    if es_ruta_api():
        return jsonify(ok=False, mensaje=mensaje), 429
    flash(mensaje, "error")
    return redirect(request.referrer or url_for('login'))

@app.errorhandler(500)
def internal_error(e):   return error_http(500, "Error interno del servidor.", "500.html")

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    if isinstance(e, HTTPException):          # 405, 408, etc.: conservar su código real
        return e
    print(f"Unexpected error: {e}")
    return error_http(500, "Error interno del servidor.", "500.html")


# ======================================================
# API JSON — ENDPOINTS PARA APP MÓVIL FLUTTER
# ======================================================

@app.route('/api/login', methods=['POST'])
@limiter.limit(LIMITE_LOGIN)
def api_login():
    data       = request.get_json(silent=True) or {}
    matricula  = str(data.get('matricula', '')).strip()
    contrasena = str(data.get('contrasena', ''))

    if not matricula or not contrasena:
        return jsonify(ok=False, mensaje="Matrícula y contraseña son requeridos."), 400

    user, error = verificar_credenciales(matricula, contrasena)
    if error:
        return jsonify(ok=False, mensaje=error), 401

    access, refresh = emitir_tokens_movil(user)
    return jsonify(
        ok=True,
        access_token=access,
        refresh_token=refresh,
        expires_in=ACCESS_MOVIL_MINUTOS * 60,
        usuario=user['usuario'],
        matricula=user['matricula'],
        es_admin=user.get('es_admin', False)
    ), 200


@app.route('/api/refresh', methods=['POST'])
@limiter.limit(LIMITE_REFRESH)
@jwt_required(refresh=True)
def api_refresh():
    """Canjea un refresh token por un access token nuevo. El refresh token se ROTA:
    el anterior queda revocado y se entrega uno nuevo."""
    payload = get_jwt()
    user = collection.find_one({'matricula': payload['sub']})
    if not user:
        return jsonify(ok=False, codigo="token_revocado", mensaje="Cuenta no encontrada."), 401
    revocar_payload(payload)
    access, refresh = emitir_tokens_movil(user)
    return jsonify(ok=True, access_token=access, refresh_token=refresh,
                   expires_in=ACCESS_MOVIL_MINUTOS * 60,
                   usuario=user['usuario'], es_admin=user.get('es_admin', False)), 200


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def api_logout():
    """Cierra la sesión en el servidor: revoca el access token y, si se envía, el refresh token."""
    revocar_payload(get_jwt())
    data = request.get_json(silent=True) or {}
    refresh = data.get('refresh_token')
    if refresh:
        try:
            payload = decode_token(refresh)
            if payload.get('type') == 'refresh' and payload.get('sub') == get_jwt_identity():
                revocar_payload(payload)
        except Exception:
            pass                                  # un refresh inválido no impide cerrar sesión
    return jsonify(ok=True, mensaje="Sesión cerrada."), 200


@app.route('/api/registro', methods=['POST'])
@limiter.limit(LIMITE_REGISTRO)
def api_registro():
    data       = request.get_json(silent=True) or {}
    matricula  = str(data.get('matricula', '')).strip()
    usuario    = str(data.get('usuario', '')).strip()
    email      = str(data.get('email', '')).lower().strip()
    contrasena = str(data.get('contrasena', ''))

    if not matricula or not usuario or not email or not contrasena:
        return jsonify(ok=False, mensaje="Todos los campos son requeridos."), 400
    if not matricula.isdigit() or len(matricula) > 15:
        return jsonify(ok=False, mensaje="La matrícula debe contener solo números."), 400
    if not validar_no_sql_injection(usuario) or len(usuario) > 100:
        return jsonify(ok=False, mensaje="Nombre inválido."), 400
    if not email.endswith("@virtual.utsc.edu.mx") or len(email) > 100:
        return jsonify(ok=False, mensaje="Debe usar un correo @virtual.utsc.edu.mx"), 400
    if not password_valida(contrasena):
        return jsonify(ok=False, mensaje=PASSWORD_MENSAJE), 400

    # Misma respuesta para matrícula repetida y correo repetido (no revelar qué existe).
    if collection.find_one({'$or': [{'matricula': matricula}, {'email': email}]}):
        return jsonify(ok=False, mensaje=MENSAJE_REGISTRO_NO_COMPLETADO), 409

    hashed = bcrypt.generate_password_hash(contrasena).decode('utf-8')
    collection.insert_one({
        'matricula': matricula, 'usuario': usuario,
        'email': email, 'contrasena': hashed,
        'intentos_fallidos': 0, 'bloqueado_hasta': None, 'es_admin': False
    })
    return jsonify(ok=True, mensaje="Registro exitoso. Inicia sesión."), 201


@app.route('/api/perfil', methods=['GET'])
@jwt_required()
def api_perfil():
    matricula = get_jwt_identity()
    # Lista blanca: solo los campos que la app necesita (nunca contraseña, contadores de
    # intentos, fechas de bloqueo ni cualquier campo interno que se agregue en el futuro).
    user = collection.find_one({'matricula': matricula},
                               {'_id': 0, 'matricula': 1, 'usuario': 1, 'email': 1, 'es_admin': 1})
    if not user:
        return jsonify(ok=False, mensaje="Usuario no encontrado."), 404
    return jsonify(ok=True, **user), 200


@app.route('/api/inscripcion', methods=['POST'])
@limiter.limit(LIMITE_TRAMITES)
@jwt_required()
def api_inscripcion():
    """Inscripción desde la app móvil (multipart/form-data con los mismos campos y
    archivos que el formulario web). Aplica las mismas validaciones del servidor."""
    matricula = get_jwt_identity()
    user = collection.find_one({"matricula": matricula})
    ok, resultado = procesar_inscripcion(matricula, user, request.form, request.files)
    if not ok:
        return jsonify(ok=False, mensaje=resultado), 400
    return jsonify(ok=True, folio=resultado['folio'],
                   mensaje="Solicitud recibida. Recibirás un correo con tu folio."), 201


@app.route('/api/reinscripcion', methods=['POST'])
@limiter.limit(LIMITE_TRAMITES)
@jwt_required()
def api_reinscripcion():
    matricula = get_jwt_identity()
    user = collection.find_one({"matricula": matricula})
    ok, resultado = procesar_reinscripcion(matricula, user, request.form, request.files,
                                           exigir_contacto=False)
    if not ok:
        return jsonify(ok=False, mensaje=resultado), 400
    return jsonify(ok=True, folio=resultado['folio'],
                   mensaje="Reinscripción recibida. Recibirás un correo con tu folio."), 201


@app.route('/api/historial', methods=['GET'])
@jwt_required()
def api_historial():
    matricula = get_jwt_identity()
    inscs  = list(inscripciones_col.find({'usuario': matricula}, {'_id': 0}))
    reincs = list(reinscripciones_col.find({'usuario': matricula}, {'_id': 0}))
    return jsonify(ok=True, inscripciones=inscs, reinscripciones=reincs), 200


def api_usuario_admin():
    """Devuelve el usuario admin del token JWT, o None si no es administrador."""
    user = collection.find_one({'matricula': get_jwt_identity()})
    if not user or not user.get('es_admin'):
        return None
    return user


@app.route('/api/admin/solicitudes', methods=['GET'])
@jwt_required()
def api_admin_solicitudes():
    if not api_usuario_admin():
        return jsonify(ok=False, mensaje="Acceso denegado."), 403
    inscs  = list(inscripciones_col.find({}, {'_id': 0}))
    reincs = list(reinscripciones_col.find({}, {'_id': 0}))
    return jsonify(ok=True, inscripciones=inscs, reinscripciones=reincs), 200


@app.route('/api/admin/actualizar_estatus', methods=['POST'])
@jwt_required()
def api_admin_actualizar_estatus():
    admin = api_usuario_admin()
    if not admin:
        return jsonify(ok=False, mensaje="Acceso denegado."), 403

    data    = request.get_json(silent=True) or {}
    folio   = str(data.get('folio', '')).strip()
    tipo    = str(data.get('tipo', '')).strip()
    estatus = str(data.get('estatus', '')).strip()

    if not folio or not tipo or not estatus:
        return jsonify(ok=False, mensaje="Datos incompletos."), 400

    ok, mensaje, codigo = aplicar_cambio_estatus(
        tipo, folio, estatus, data.get('motivo', ''), admin['matricula'])
    return jsonify(ok=ok, mensaje=mensaje), codigo


@app.route('/api/admin/dashboard', methods=['GET'])
@jwt_required()
def api_admin_dashboard():
    if not api_usuario_admin():
        return jsonify(ok=False, mensaje="Acceso denegado."), 403
    stats = estadisticas_dashboard(request.args.get('estatus', 'Todas'))
    return jsonify(ok=True, **stats), 200


@app.route('/api/admin/reportes/enlace', methods=['POST'])
@jwt_required()
def api_admin_reporte_enlace():
    admin = api_usuario_admin()
    if not admin:
        return jsonify(ok=False, mensaje="Acceso denegado."), 403
    filtros, error = leer_filtros_reporte(request.get_json(silent=True) or {})
    if error:
        return jsonify(ok=False, mensaje=error), 400

    inscs, reincs = datos_reporte(filtros)
    payload = {
        "jti"    : uuid.uuid4().hex,          # identificador único: el enlace se puede usar una sola vez
        "admin"  : admin['matricula'],
        "tipo"   : filtros["tipo"],
        "estatus": filtros["estatus"],
        "carrera": filtros["carrera"],
        "desde"  : filtros["desde"].isoformat() if filtros["desde"] else "",
        "hasta"  : filtros["hasta"].isoformat() if filtros["hasta"] else "",
    }
    token = reporte_serializer.dumps(payload)
    return jsonify(
        ok=True,
        url=url_externa('descargar_reporte', token=token),
        expira_minutos=REPORTE_ENLACE_SEGUNDOS // 60,
        inscripciones=len(inscs),
        reinscripciones=len(reincs),
    ), 200


@app.route('/api/recuperar_contrasena', methods=['POST'])
@limiter.limit(LIMITE_RECUPERAR)
def api_recuperar_contrasena():
    data  = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).lower().strip()

    if not email:
        return jsonify(ok=False, mensaje="El correo es requerido."), 400

    if not email.endswith('@virtual.utsc.edu.mx'):
        return jsonify(ok=False, mensaje="Debe ser un correo @virtual.utsc.edu.mx"), 400

    usuario = collection.find_one({'email': email})
    if usuario:
        try:
            enviar_enlace_reset(usuario)
        except Exception as e:
            # Se registra, pero la respuesta es la misma: un error de envío solo ocurre
            # para correos existentes y delataría que la cuenta existe.
            print(f"Error enviando correo: {e}")

    return jsonify(ok=True, mensaje=MENSAJE_RECUPERAR), 200


@app.route('/ping')
def ping():
    return jsonify(ok=True, mensaje="pong"), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
