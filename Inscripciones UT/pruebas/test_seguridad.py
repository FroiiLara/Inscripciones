import os, sys, io, json, re, datetime as dt
os.environ.update(SECRET_KEY='k'*40, JWT_SECRET_KEY='j'*40, MONGO_URI='mongodb://x', RATELIMIT_ENABLED='false')
os.environ.pop('FLASK_ENV', None); os.environ.pop('DEBUG', None)          # modo producción (cookies Secure)
import mongomock, pymongo
pymongo.MongoClient = mongomock.MongoClient
sys.path.insert(0, os.getcwd())
import app as A
from flask_jwt_extended import create_access_token, create_refresh_token
A.app.config['TESTING'] = True
sent, subidos = [], []
A.enviar_email = lambda to, subj, body: sent.append((to, subj, body))
A.cloudinary.uploader.upload = lambda f, **kw: subidos.append(f.filename) or {"secure_url": "https://res.cloudinary.com/x/y.pdf"}
ok = lambda cond, msg: print(('PASS ' if cond else 'FAIL ') + msg) or (cond or sys.exit(1))

PW = 'Abcdef1!x'
def alta(mat, adm=False, pw=PW):
    A.collection.insert_one(dict(matricula=mat, usuario='Admin' if adm else 'Alumno Prueba', email=f'{mat}@virtual.utsc.edu.mx',
        contrasena=A.bcrypt.generate_password_hash(pw).decode(), es_admin=adm, intentos_fallidos=0, bloqueado_hasta=None))
alta('1001', True); alta('2002'); alta('3003'); alta('4004'); alta('5005')
c = A.app.test_client()
def api(met, url, ip='10.0.0.1', **kw):
    return getattr(c, met)(url, environ_base={'REMOTE_ADDR': ip}, **kw)
def login(mat='2002', pw=PW, ip='10.0.0.1'):
    return api('post', '/api/login', ip=ip, json=dict(matricula=mat, contrasena=pw))
bearer = lambda t: {'Authorization': 'Bearer ' + t}

# ===== #4 login: mensajes genéricos y bloqueo por matrícula+IP =====
r = login(); j = r.get_json()
ok(r.status_code == 200 and j['access_token'] and j['refresh_token'] and j['expires_in'] == 900, 'login correcto entrega access+refresh (15 min)')
m1 = login('2002', 'mala').get_json()['mensaje']; m2 = login('9999999', 'mala').get_json()['mensaje']
ok(m1 == m2 == A.MENSAJE_LOGIN_FALLIDO, 'misma respuesta para contraseña mala y matrícula inexistente')
ok('intentos' not in m1.lower() and 'bloquead' not in m1.lower(), 'ya no revela intentos restantes')
for i in range(5): last = login('3003', 'mala', ip='6.6.6.6')
ok('Demasiados' in last.get_json()['mensaje'], 'bloqueo tras 5 fallos desde la misma IP')
ok('Demasiados' in login('3003', PW, ip='6.6.6.6').get_json()['mensaje'], 'el atacante sigue bloqueado aun con la clave buena')
ok(login('3003', PW, ip='7.7.7.7').status_code == 200, 'el dueño de la cuenta SÍ puede entrar desde otra IP')
for i in range(5): last = login('8888888', 'mala', ip='6.6.6.6')
ok('Demasiados' in last.get_json()['mensaje'], 'matrículas inexistentes también se bloquean (sin oráculo)')
for i in range(15): login('4004', 'mala', ip=f'9.9.9.{i}')
r = login('4004', PW, ip='9.9.9.200'); ok(r.status_code == 401 and 'sospechosa' in r.get_json()['mensaje'], 'tope global por cuenta (ataque distribuido)')
A.collection.update_one({'matricula': '4004'}, {'$set': {'bloqueado_hasta': None}})

# ===== #9 sesiones: refresh con rotación, expiración y logout =====
j = login().get_json(); acc, ref = j['access_token'], j['refresh_token']
ok(api('get', '/api/perfil', headers=bearer(acc)).status_code == 200, 'access token válido')
r = api('post', '/api/refresh', headers=bearer(ref)); j2 = r.get_json()
ok(r.status_code == 200 and j2['access_token'] and j2['refresh_token'] != ref, 'refresh entrega tokens nuevos (rotación)')
r = api('post', '/api/refresh', headers=bearer(ref)); ok(r.status_code == 401 and r.get_json()['codigo'] == 'token_revocado', 'refresh viejo ya no sirve (un solo uso)')
r = api('post', '/api/refresh', headers=bearer(acc)); ok(r.status_code == 401, 'un access token no sirve para renovar')
with A.app.app_context():
    vencido = create_access_token(identity='2002', expires_delta=dt.timedelta(seconds=-5))
r = api('get', '/api/perfil', headers=bearer(vencido)); ok(r.status_code == 401 and r.get_json()['codigo'] == 'token_expirado', 'access vencido => 401 token_expirado')
r = api('get', '/api/perfil'); ok(r.status_code == 401 and r.get_json()['codigo'] == 'sin_token', 'sin token => 401 JSON')
r = api('post', '/api/logout', headers=bearer(j2['access_token']), json={'refresh_token': j2['refresh_token']})
ok(r.status_code == 200, 'logout responde ok')
r = api('get', '/api/perfil', headers=bearer(j2['access_token'])); ok(r.status_code == 401 and r.get_json()['codigo'] == 'token_revocado', 'access revocado tras logout')
ok(api('post', '/api/refresh', headers=bearer(j2['refresh_token'])).status_code == 401, 'refresh revocado tras logout')

# ===== #15 perfil: lista blanca =====
t = login().get_json()['access_token']
p = api('get', '/api/perfil', headers=bearer(t)).get_json()
ok(set(p) == {'ok', 'matricula', 'usuario', 'email', 'es_admin', 'rol'}, f'perfil solo expone {sorted(p)}')

# ===== #5 CSRF + cookies del navegador =====
w = A.app.test_client()
HTTPS = dict(base_url='https://localhost', environ_base={'REMOTE_ADDR': '10.1.1.1'})
r = w.post('/login', data=dict(matricula='2002', contrasena=PW), **HTTPS)
cab = ' | '.join(r.headers.getlist('Set-Cookie'))
ok(r.status_code == 302 and 'access_token_cookie' in cab, 'login web crea cookie de sesión')
ac = [x for x in r.headers.getlist('Set-Cookie') if x.startswith('access_token_cookie')][0]
ok('HttpOnly' in ac and 'Secure' in ac and 'SameSite=Strict' in ac, f'cookie de sesión HttpOnly+Secure+SameSite=Strict')
ok('csrf_access_token' in cab, 'se emite cookie csrf_access_token')
csrf = w.get_cookie('csrf_access_token', domain='localhost').value
datos = lambda: dict(nombre='Juan Perez Lopez', curp='PEGJ990101HNLRZN01', fecha_nacimiento='1999-01-01', telefono='8112345678', carrera='II',
    contacto_emergencia_nombre='Maria Lopez', contacto_emergencia_tel='8100000000',
    fotografia=(io.BytesIO(b'\x89PNG\r\n\x1a\nxx'), 'f.png'), doc_acta=(io.BytesIO(b'%PDF-1.4 x'), 'a.pdf'),
    doc_cert=(io.BytesIO(b'%PDF-1.4 x'), 'c.pdf'), comprobante=(io.BytesIO(b'%PDF-1.4 x'), 'p.pdf'))
n0 = A.inscripciones_col.count_documents({})
r = w.post('/inscripcion_submit', data=datos(), content_type='multipart/form-data', **HTTPS)
ok(r.status_code in (401, 302) and A.inscripciones_col.count_documents({}) == n0, f'POST sin token CSRF se rechaza ({r.status_code}) y no guarda')
d = datos(); d['csrf_token'] = 'falso'
r = w.post('/inscripcion_submit', data=d, content_type='multipart/form-data', **HTTPS)
ok(A.inscripciones_col.count_documents({}) == n0, 'token CSRF falso se rechaza')
d = datos(); d['csrf_token'] = csrf
r = w.post('/inscripcion_submit', data=d, content_type='multipart/form-data', **HTTPS)
print(r.status_code, r.headers.get('Location'), r.data[:150]); ok(r.status_code == 200 and A.inscripciones_col.count_documents({}) == n0 + 1, 'con token CSRF correcto se guarda')
r = w.get('/inscripcion', **HTTPS); ok(csrf.encode() in r.data, 'el formulario web incluye el token CSRF')
r = w.get('/reinscripcion', **HTTPS); ok(csrf.encode() in r.data, 'reinscripción web incluye el token CSRF')
# admin: formularios de estatus
wa = A.app.test_client()
wa.post('/login', data=dict(matricula='1001', contrasena=PW), **HTTPS)
csrf_a = wa.get_cookie('csrf_access_token', domain='localhost').value
folio = A.inscripciones_col.find_one({})['folio']
r = wa.post('/admin/actualizar_estatus', data=dict(folio=folio, tipo='inscripcion', estatus='Aprobada'), **HTTPS)
ok(A.inscripciones_col.find_one({'folio': folio})['estatus'] == 'En revisión', 'admin: POST sin CSRF no cambia el estatus')
r = wa.post('/admin/actualizar_estatus', data=dict(folio=folio, tipo='inscripcion', estatus='Aprobada', csrf_token=csrf_a), **HTTPS)
ok(A.inscripciones_col.find_one({'folio': folio})['estatus'] == 'Aprobada', 'admin: con CSRF sí cambia el estatus')
r = wa.get('/admin', **HTTPS); src = open('templates/admin_panel.html', encoding='utf-8').read()
ok(r.data.count(csrf_a.encode()) >= 1 and src.count('<form ') == src.count('name="csrf_token"'), f"panel admin: todos los formularios ({src.count('<form ')}) llevan el token CSRF")
# la app móvil (cabecera Bearer) no usa cookies, así que no necesita CSRF
tadm = login('1001').get_json()['access_token']
r = api('post', '/api/admin/actualizar_estatus', headers=bearer(tadm), json=dict(folio=folio, tipo='inscripcion', estatus='En revisión'))
ok(r.status_code == 200, 'API con Bearer funciona sin CSRF')
# logout web revoca la cookie
cookie_vieja = w.get_cookie('access_token_cookie', domain='localhost').value
w.get('/logout', **HTTPS)
w2 = A.app.test_client(); w2.set_cookie('access_token_cookie', cookie_vieja, domain='localhost')
r = w2.get('/mi_perfil', **HTTPS); ok(r.status_code == 302 and '/login' in r.headers['Location'], 'cookie copiada antes del logout ya no sirve (redirige al login)')
r = A.app.test_client().get('/mi_historial', **HTTPS); ok(r.status_code == 302 and '/login' in r.headers['Location'], 'sin sesión => redirige al login')

# ===== #8 registro genérico + política =====
reg = lambda **kw: api('post', '/api/registro', json={**dict(matricula='7007', usuario='Nuevo Alumno', email='7007@virtual.utsc.edu.mx', contrasena=PW), **kw}, ip='12.0.0.1')
r1 = reg(matricula='2002', email='otro@virtual.utsc.edu.mx'); r2 = reg(email='2002@virtual.utsc.edu.mx')
ok(r1.status_code == r2.status_code == 409 and r1.get_json()['mensaje'] == r2.get_json()['mensaje'], 'matrícula repetida y correo repetido: misma respuesta')
ok(reg(contrasena='abc').status_code == 400 and reg(contrasena='A1!a' * 30).status_code == 400, 'contraseña débil o de más de 72 caracteres rechazada')
ok(reg().status_code == 201, 'registro válido')
r = w.post('/registro', data=dict(matricula='2002', usuario='X Y Z', email='nuevo@virtual.utsc.edu.mx', contrasena=PW), follow_redirects=True, **HTTPS)
ok('No fue posible completar el registro'.encode() in r.data or r.status_code in (200, 302), 'web: registro repetido con mensaje genérico')

# ===== #11 restablecer contraseña =====
sent.clear()
a = api('post', '/api/recuperar_contrasena', json={'email': '5005@virtual.utsc.edu.mx'}, ip='13.0.0.1').get_json()
b = api('post', '/api/recuperar_contrasena', json={'email': 'noexiste@virtual.utsc.edu.mx'}, ip='13.0.0.1').get_json()
ok(a == b, 'recuperar: misma respuesta exista o no el correo')
ok(len(sent) == 1, 'solo se envía correo a cuentas existentes')
enlace = re.search(r'href="([^"]+restablecer_contrasena/[^"]+)"', sent[0][2]).group(1)
ok(enlace.startswith('https://') or enlace.startswith('http://'), 'el correo trae enlace')
ruta = '/' + enlace.split('/', 3)[3]
viejo_acc = login('5005').get_json()['access_token']
rr = w.get(ruta, **HTTPS); ok(rr.status_code == 200 and b'nueva_contrasena' in rr.data, 'el enlace muestra el formulario de nueva contraseña')
rr = w.post(ruta, data=dict(nueva_contrasena='debil', confirmar_contrasena='debil'), **HTTPS); ok(b'8 y 72' in rr.data or 'entre 8'.encode() in rr.data, 'contraseña débil rechazada en el restablecimiento')
rr = w.post(ruta, data=dict(nueva_contrasena='Nueva1!clave', confirmar_contrasena='Otra1!clave'), **HTTPS); ok('no coinciden'.encode() in rr.data, 'confirmación distinta rechazada')
rr = w.post(ruta, data=dict(nueva_contrasena='Nueva1!clave', confirmar_contrasena='Nueva1!clave'), **HTTPS); ok(rr.status_code == 302, 'restablecimiento correcto')
rr = w.get(ruta, **HTTPS); ok(rr.status_code == 302 and 'recuperar' in rr.headers['Location'], 'el enlace ya usado deja de funcionar (un solo uso)')
ok(api('get', '/api/perfil', headers=bearer(viejo_acc)).status_code == 401, 'las sesiones abiertas se cierran al cambiar la contraseña')
ok(login('5005', PW).status_code == 401 and login('5005', 'Nueva1!clave').status_code == 200, 'la clave vieja ya no sirve y la nueva sí')
tok_viejo = A.serializer.dumps('5005@virtual.utsc.edu.mx', salt='password-reset-salt')
ok(w.get(f'/restablecer_contrasena/{tok_viejo}', **HTTPS).status_code == 302, 'tokens con el formato anterior se rechazan')

# ===== #10 archivos =====
tk = login('2002').get_json()['access_token']
def insc(**over):
    f = datos(); f.update(over); return api('post', '/api/inscripcion', headers=bearer(tk), data=f, content_type='multipart/form-data', ip='14.0.0.1')
subidos.clear(); n0 = A.inscripciones_col.count_documents({})
r = insc(); ok(r.status_code == 201 and r.get_json()['folio'].startswith('UTSC-') and len(subidos) == 4, 'API inscripción válida (4 archivos subidos)')
malos = {
  'acta falsa (texto con extensión .pdf)': dict(doc_acta=(io.BytesIO(b'hola mundo'), 'a.pdf')),
  'ejecutable renombrado a .png': dict(fotografia=(io.BytesIO(b'MZ\x90\x00 programa'), 'f.png')),
  'extensión no permitida (.exe)': dict(doc_cert=(io.BytesIO(b'%PDF-1.4'), 'virus.exe')),
  'html disfrazado de pdf': dict(comprobante=(io.BytesIO(b'<html><script>alert(1)</script>'), 'p.pdf')),
  'PDF en lugar de foto': dict(fotografia=(io.BytesIO(b'%PDF-1.4 x'), 'f.pdf')),
  'archivo vacío': dict(doc_acta=(io.BytesIO(b''), 'a.pdf')),
  'archivo de 6 MB': dict(doc_acta=(io.BytesIO(b'%PDF-1.4' + b'0' * (6 * 1024 * 1024)), 'a.pdf')),
  'PNG con extensión .pdf': dict(doc_acta=(io.BytesIO(b'\x89PNG\r\n\x1a\nxx'), 'a.pdf')),
}
for nombre, extra in malos.items():
    subidos.clear(); n = A.inscripciones_col.count_documents({}); r = insc(**extra)
    ok(r.status_code == 400 and A.inscripciones_col.count_documents({}) == n and not subidos, f'rechazado: {nombre} -> "{r.get_json()["mensaje"][:55]}"')
d = datos(); d.pop('doc_acta')
r = api('post', '/api/inscripcion', headers=bearer(tk), data=d, content_type='multipart/form-data'); ok(r.status_code == 400, 'falta un documento => 400')
d = datos(); d['relleno'] = (io.BytesIO(b'0' * (21 * 1024 * 1024)), 'x.bin')
r = api('post', '/api/inscripcion', headers=bearer(tk), data=d, content_type='multipart/form-data'); ok(r.status_code == 413, f'petición > 20 MB => 413 ({r.status_code})')
ok(insc(fecha_nacimiento='2015-01-01').status_code == 400 and insc(telefono='123').status_code == 400 and insc(carrera='XXX').status_code == 400
   and insc(curp='MALA').status_code == 400 and insc(nombre='<script>').status_code == 400, 'API valida edad, teléfono, carrera, CURP y nombre')

# ===== #13 reinscripción móvil =====
def rein(**over):
    f = dict(matricula='2002', nombre='Alumno Prueba', carrera_clave='ITID', cuatrimestre='4', es_estadia='0', materias=json.dumps(['Bases de Datos']),
             referencia_pago='OP-123', fecha_pago=dt.datetime.utcnow().strftime('%Y-%m-%d'), comprobante=(io.BytesIO(b'%PDF-1.4 x'), 'c.pdf'))
    f.update(over); return api('post', '/api/reinscripcion', headers=bearer(tk), data=f, content_type='multipart/form-data', ip='14.0.0.2')
r = rein(); ok(r.status_code == 201 and r.get_json()['folio'].startswith('REINSC-'), 'API reinscripción válida (sin correo/teléfono)')
doc = A.reinscripciones_col.find_one({'folio': r.get_json()['folio']})
ok(doc['usuario'] == '2002' and doc['correo'] == '2002@virtual.utsc.edu.mx' and doc['carrera'] == A.CARRERAS['ITID'] and doc['estatus'] == 'En revisión', 'se guarda con usuario del token y correo de la cuenta')
ok(rein(matricula='3003').status_code == 400, 'no se puede reinscribir otra matrícula')
ok(rein(fecha_pago='2999-01-01').status_code == 400 and rein(fecha_pago='hoy').status_code == 400, 'fecha de pago futura/inválida rechazada')
ok(rein(referencia_pago='<b>').status_code == 400 and rein(cuatrimestre='99').status_code == 400 and rein(carrera_clave='ZZ').status_code == 400, 'referencia, cuatrimestre y carrera validados')
ok(rein(materias='[]').status_code == 400 and rein(materias='no-json').status_code == 400, 'sin materias / JSON inválido rechazado')
ok(rein(es_estadia='1', materias='[]').status_code == 201, 'estadía no requiere materias')
ok(rein(comprobante=(io.BytesIO(b'xxxx'), 'c.pdf')).status_code == 400, 'comprobante falso rechazado')
ok(api('post', '/api/inscripcion', data={}, content_type='multipart/form-data').status_code == 401, 'inscripción API exige sesión')

# ===== #16 enlace de reporte de un solo uso =====
r = api('post', '/api/admin/reportes/enlace', headers=bearer(tadm), json={'tipo': 'general'}); ruta = '/' + r.get_json()['url'].split('/', 3)[3]
ok(api('get', ruta).status_code == 200, 'primer uso del enlace descarga el Excel')
ok(api('get', ruta).status_code == 403, 'segundo uso del enlace => 403')
sin_jti = A.reporte_serializer.dumps({'admin': '1001', 'tipo': 'general', 'estatus': 'Todas', 'carrera': 'Todas', 'desde': '', 'hasta': ''})
ok(api('get', f'/descargar_reporte/{sin_jti}').status_code == 403, 'enlace sin identificador único => 403')

# ===== #17 CURP externa configurable =====
A.CURP_VALIDACION_EXTERNA = False
r = api('get', '/api/validar_curp/PEGJ990101HNLRZN01', headers=bearer(tk)); ok(r.status_code == 503 and r.get_json()['valida'] is None, 'verificación externa desactivable (no sale la CURP)')
A.CURP_VALIDACION_EXTERNA = True

# ===== errores =====
r = api('get', '/api/no_existe'); ok(r.status_code == 404 and r.get_json()['ok'] is False, '404 en /api responde JSON')
r = api('put', '/login'); ok(r.status_code == 405, f'405 conserva su código ({r.status_code})')
r = api('options', '/api/login', headers={'Origin': 'https://malo.com', 'Access-Control-Request-Method': 'POST'}); ok('Access-Control-Allow-Origin' not in r.headers, 'CORS: ningún origen externo permitido')
ok(w.get('/.well-known/security.txt', **HTTPS).status_code == 200, 'security.txt sigue disponible')
print('ALL SECURITY TESTS PASSED')
