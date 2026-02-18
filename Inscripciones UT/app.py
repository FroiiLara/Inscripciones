import os
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
# CONTEXT PROCESSOR CORREGIDO
# ======================================================

@app.context_processor
def inject_user():
    verify_jwt_in_request(optional=True)
    return dict(usuario=get_jwt_identity())


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
        sg.send(mensaje)
    except Exception as e:
        print(f"Error enviando email: {e}")
        abort(500)


# ======================================================
# RUTA HOME
# ======================================================

@app.route('/')
def home():
    return redirect(url_for('login'))


# ======================================================
# REGISTRO
# ======================================================

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':

        usuario = request.form.get('usuario')
        email = request.form.get('email')
        contrasena = request.form.get('contrasena')

        if not usuario or not email or not contrasena:
            abort(400)

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


# ======================================================
# LOGIN (GENERA JWT)
# ======================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        usuario = request.form.get('usuario')
        contrasena = request.form.get('contrasena')

        if not usuario or not contrasena:
            abort(400)

        user = collection.find_one({'usuario': usuario})

        if user and bcrypt.check_password_hash(user['contrasena'], contrasena):

            access_token = create_access_token(identity=usuario)

            response = redirect(url_for('pagina_principal'))
            set_access_cookies(response, access_token)

            return response

        flash("Usuario o contraseña incorrectos.", "error")
        return render_template('login.html'), 401

    return render_template('login.html')


# ======================================================
# LOGOUT
# ======================================================

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
    usuario = get_jwt_identity()
    return render_template('index.html', usuario=usuario)


@app.route('/mi_perfil')
@jwt_required()
def mi_perfil():
    usuario = get_jwt_identity()
    user_data = collection.find_one({'usuario': usuario})

    if not user_data:
        abort(404)

    return render_template(
        'mi_perfil.html',
        usuario=usuario,
        email=user_data['email']
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
# RECUPERAR CONTRASEÑA
# ======================================================

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':

        email = request.form.get('email')

        if not email:
            abort(400)

        user = collection.find_one({'email': email})

        if user:
            token = serializer.dumps(email)
            enlace = url_for('restablecer_contrasena', token=token, _external=True)

            cuerpo = f"""
            <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
            <a href="{enlace}">Restablecer contraseña</a>
            """

            enviar_email(email, "Recuperación de contraseña", cuerpo)
            flash("Correo enviado correctamente.", "success")
        else:
            flash("Correo no registrado.", "error")

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
        nueva = request.form.get('nueva_contrasena')

        if not nueva:
            abort(400)

        hashed = bcrypt.generate_password_hash(nueva).decode('utf-8')
        collection.update_one({'email': email}, {'$set': {'contrasena': hashed}})

        flash("Contraseña actualizada correctamente.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')


# ======================================================
# MANEJO GLOBAL DE ERRORES
# ======================================================

@app.errorhandler(400)
def bad_request(e):
    return render_template("400.html"), 400


@app.errorhandler(401)
def unauthorized(e):
    return render_template("401.html"), 401


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    print(f"Unexpected error: {e}")
    return render_template("500.html"), 500


# ======================================================
# EJECUCIÓN
# ======================================================

if __name__ == '__main__':
    app.run(debug=True)


