import os
import re
from datetime import timedelta
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
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # En producción poner True
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

jwt = JWTManager(app)

# ================= MONGODB =================
MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["Users"]
collection = db["Users"]

# ================= SENDGRID =================
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL = os.environ.get("FROM_EMAIL")

# ================= SERIALIZER =================
serializer = Serializer(app.secret_key, salt="password-reset-salt")

# ======================================================
# UTILIDADES DE SEGURIDAD (PREVENCIÓN DE INYECCIÓN)
# ======================================================

def validar_no_sql_injection(dato):
    """
    Bloquea el uso de diccionarios u operadores de MongoDB ($) 
    en campos de texto para prevenir NoSQL Injection.
    """
    if isinstance(dato, dict): return False
    # Evita que el usuario envíe operadores de consulta de MongoDB
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
    try:
        mensaje = Mail(
            from_email=FROM_EMAIL,
            to_emails=destinatario,
            subject=asunto,
            html_content=cuerpo
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(mensaje)
        return True # Indica que se envió
    except Exception as e:
        print(f"Error detallado de SendGrid: {e}")
        return False


# ======================================================
# RUTAS
# ======================================================

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        # SANITIZACIÓN Y PREVENCIÓN DE INYECCIÓN
        usuario = str(request.form.get('usuario', '')).strip()
        email = str(request.form.get('email', '')).lower().strip()
        contrasena = str(request.form.get('contrasena', ''))

        # Validación de integridad de datos
        if not usuario or not email or not contrasena:
            abort(400)
        
        if not validar_no_sql_injection(usuario) or not validar_no_sql_injection(email):
            flash("Caracteres no permitidos detectados.", "error")
            return redirect(url_for('registro'))

        # Validación de lógica de negocio (Email Institucional)
        if not email.endswith("@virtual.utsc.edu.mx"):
            flash("Debe usar un correo institucional @virtual.utsc.edu.mx", "error")
            return redirect(url_for('registro'))

        if collection.find_one({'email': email}):
            flash("El correo ya está registrado.", "error")
            return redirect(url_for('registro'))

        hashed = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        collection.insert_one({
            'usuario': usuario,
            'email': email,
            'contrasena': hashed
        })

        flash("Registro exitoso. Inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # SANITIZACIÓN
        usuario = str(request.form.get('usuario', '')).strip()
        contrasena = str(request.form.get('contrasena', ''))

        if not usuario or not contrasena:
            abort(400)

        # Seguridad NoSQL: Forzamos búsqueda por string exacto
        user = collection.find_one({'usuario': {"$eq": usuario}})

        if user and bcrypt.check_password_hash(user['contrasena'], contrasena):
            access_token = create_access_token(identity=usuario)
            response = redirect(url_for('pagina_principal'))
            set_access_cookies(response, access_token)
            return response

        flash("Usuario o contraseña incorrectos.", "error")
        return render_template('login.html'), 401

    return render_template('login.html')


@app.route('/logout')
@jwt_required()
def logout():
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)
    return response


# ================= PÁGINAS PROTEGIDAS =================

@app.route('/pagina_principal')
@jwt_required()
def pagina_principal():
    usuario = get_jwt_identity()
    return render_template('index.html', usuario=usuario)


@app.route('/mi_perfil')
@jwt_required()
def mi_perfil():
    usuario = get_jwt_identity()
    user_data = collection.find_one({'usuario': usuario})
    if not user_data:
        abort(404)
    return render_template('mi_perfil.html', usuario=usuario, email=user_data['email'])


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


# ================= RECUPERACIÓN =================

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        email = str(request.form.get('email', '')).lower().strip()

        # 1. Validaciones básicas de seguridad y presencia
        if not email or not validar_no_sql_injection(email):
            flash("Correo electrónico no válido.", "error")
            return redirect(url_for('recuperar_contrasena'))

        # 2. Buscar al usuario en MongoDB
        user = collection.find_one({'email': email})

        if user:
            try:
                # 3. Generar token seguro
                token = serializer.dumps(email, salt="password-reset-salt")
                enlace = url_for('restablecer_contrasena', token=token, _external=True)
                
                # 4. Preparar el cuerpo del mensaje
                cuerpo = f"""
                <div style="font-family: sans-serif; border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
                    <h2 style="color: #333;">Restablecer Contraseña</h2>
                    <p>Has solicitado restablecer tu contraseña para tu cuenta institucional.</p>
                    <p>Haz clic en el siguiente botón para continuar (el enlace expira en 1 hora):</p>
                    <a href='{enlace}' style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Restablecer contraseña
                    </a>
                    <p style="margin-top: 20px; font-size: 12px; color: #777;">Si no solicitaste este cambio, puedes ignorar este correo.</p>
                </div>
                """
                
                # 5. Intentar enviar el email
                if enviar_email(email, "Recuperación de contraseña", cuerpo):
                    flash("Se han enviado las instrucciones a tu correo institucional.", "success")
                else:
                    # Si enviar_email devuelve False (Error 401, etc.)
                    flash("Error al conectar con el servicio de correos. Verifica tu configuración de SendGrid.", "error")
            
            except Exception as e:
                print(f"Error en el proceso de recuperación: {e}")
                flash("Ocurrió un error inesperado. Inténtalo de nuevo.", "error")
        else:
            # Por seguridad, algunos prefieren decir "Si el correo existe, se envió...", 
            # pero aquí lo mantendremos como lo tenías:
            flash("El correo ingresado no está registrado en el sistema.", "error")
            
        return redirect(url_for('recuperar_contrasena'))

    return render_template('recuperar_contrasena.html')


@app.route('/restablecer_contrasena/<token>', methods=['GET', 'POST'])
def restablecer_contrasena(token):
    try:
        email = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        flash("El enlace ha expirado.", "error")
        return redirect(url_for('recuperar_contrasena'))
    except BadSignature:
        abort(400)

    if request.method == 'POST':
        nueva = str(request.form.get('nueva_contrasena', ''))

        if not nueva or len(nueva) < 8:
            flash("Contraseña inválida (mínimo 8 caracteres).", "error")
            return redirect(request.url)

        hashed = bcrypt.generate_password_hash(nueva).decode('utf-8')
        collection.update_one({'email': email}, {'$set': {'contrasena': hashed}})

        flash("Contraseña actualizada correctamente.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')


# ================= ERRORES =================

@app.errorhandler(400)
def bad_request(e): return render_template("400.html"), 400

@app.errorhandler(401)
def unauthorized(e): return render_template("401.html"), 401

@app.errorhandler(404)
def not_found(e): return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e): return render_template("500.html"), 500

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    print(f"Unexpected error: {e}")
    return render_template("500.html"), 500

if __name__ == '__main__':
    app.run(debug=True)