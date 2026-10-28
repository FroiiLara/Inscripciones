import os, sys
os.environ.update(SECRET_KEY='k'*40, JWT_SECRET_KEY='j'*40, MONGO_URI='mongodb://x', RATELIMIT_ENABLED='false',
                  SUPER_ADMIN_MATRICULAS='9999')
os.environ.pop('FLASK_ENV', None); os.environ.pop('DEBUG', None)
import mongomock, pymongo
pymongo.MongoClient = mongomock.MongoClient
sys.path.insert(0, os.getcwd())
import app as A
from flask_jwt_extended import create_access_token, get_csrf_token
A.app.config['TESTING'] = True
ok = lambda cond, msg: print(('PASS ' if cond else 'FAIL ') + msg) or (cond or sys.exit(1))

def alta(mat, **extra):
    A.collection.insert_one(dict(matricula=mat, usuario=f'U{mat}', email=f'{mat}@x.mx', contrasena='x',
                                 intentos_fallidos=0, bloqueado_hasta=None, **extra))
alta('12345', es_admin="false")          # ← el caso de Monse: texto "false"
alta('1001', es_admin=True)              # admin antiguo
alta('1002', es_admin=False, rol='admin')
alta('2002')                             # sin campos
alta('3003', rol='alumno', es_admin=False)
alta('9999')                             # super por variable de entorno
alta('8888', rol='super_admin')          # super por base de datos

ROL = {m: A.rol_de(A.collection.find_one({'matricula': m})) for m in ('12345','1001','1002','2002','3003','9999','8888')}
ok(ROL['12345'] == 'alumno', 'es_admin="false" (texto) => alumno, NO admin')
ok(ROL['1001'] == 'admin' and ROL['1002'] == 'admin', 'es_admin=True o rol=admin => admin')
ok(ROL['2002'] == 'alumno' and ROL['3003'] == 'alumno', 'sin campo / rol alumno => alumno')
ok(ROL['9999'] == 'super_admin' and ROL['8888'] == 'super_admin', 'super admin por env y por base de datos')

c = A.app.test_client()
def entrar(mat):
    c.cookie_jar.clear() if hasattr(c, 'cookie_jar') else c.delete_cookie('access_token_cookie')
    with A.app.app_context():
        t = create_access_token(identity=mat)
    c.set_cookie('access_token_cookie', t)
    with A.app.app_context():
        c.set_cookie('csrf_access_token', get_csrf_token(t))
def get(path):
    return c.get(path, follow_redirects=False)

# ---- alumno (Monse)
entrar('12345')
ok(get('/admin').status_code == 403, 'alumno => /admin 403')
ok(get('/admin/dashboard').status_code == 403 and get('/admin/reportes').status_code == 403, 'alumno => dashboard/reportes 403')
ok(get('/superadmin/usuarios').status_code == 403, 'alumno => /superadmin 403')
r = get('/pagina_principal'); h = r.get_data(as_text=True)
ok(r.status_code == 200 and 'Panel Admin' not in h and 'Mi Historial' in h and 'Iniciar Inscripción' in h, 'alumno: sin "Panel Admin", con Historial y botones de trámites')
ok(get('/inscripcion').status_code == 200 and get('/reinscripcion').status_code == 200 and get('/mi_historial').status_code == 200, 'alumno: inscripción, reinscripción e historial OK')

# ---- admin
entrar('1001')
ok(get('/admin').status_code == 200 and get('/admin/dashboard').status_code == 200 and get('/admin/reportes').status_code == 200, 'admin: solicitudes, dashboard y reportes OK')
ok(get('/superadmin/usuarios').status_code == 403, 'admin => /superadmin 403')
for ruta in ('/inscripcion', '/reinscripcion', '/mi_historial'):
    r = get(ruta); ok(r.status_code == 302 and r.headers['Location'].endswith('/admin'), f'admin => {ruta} redirige a /admin (no se inscribe)')
h = get('/pagina_principal').get_data(as_text=True)
ok('Iniciar Inscripción' not in h and 'Panel Admin' in h, 'admin: inicio sin botones de trámites, con Panel Admin')
r = c.post('/inscripcion_submit', data={}); ok(r.status_code in (302, 401, 403), 'admin no puede enviar inscripción')

# ---- super admin
entrar('9999')
r = get('/superadmin/usuarios'); h = r.get_data(as_text=True)
ok(r.status_code == 200 and 'U12345' in h and 'Super Administrador' in h, 'super: ve la lista de usuarios')
ok(get('/admin').status_code == 403 and get('/admin/dashboard').status_code == 403 and get('/admin/reportes').status_code == 403,
   'super NO ve solicitudes/dashboard/reportes')
for ruta in ('/inscripcion', '/reinscripcion', '/mi_historial'):
    r = get(ruta); ok(r.status_code == 302 and r.headers['Location'].endswith('/superadmin/usuarios'), f'super => {ruta} redirige a su panel')
ok('Administración' in get('/pagina_principal').get_data(as_text=True), 'super: inicio con enlace a Administración')
r = get('/superadmin/usuarios?q=2002'); ok('U2002' in r.get_data(as_text=True) and 'U12345' not in r.get_data(as_text=True), 'búsqueda por matrícula')
r = get('/superadmin/usuarios?rol=admin'); h = r.get_data(as_text=True); ok('U1001' in h and 'U12345' not in h, 'filtro por rol')

csrf = c.get_cookie('csrf_access_token').value
def post(path, **d):
    return c.post(path, data=dict(csrf_token=csrf, **d))
r = post('/superadmin/usuarios/rol', matricula='3003', rol='admin')
ok(A.rol_de(A.collection.find_one({'matricula': '3003'})) == 'admin' and A.collection.find_one({'matricula': '3003'})['es_admin'] is True, 'super cambia alumno -> admin')
ok(A.collection.find_one({'matricula': '3003'}).get('sesiones_desde'), 'cambio de rol cierra las sesiones del usuario')
post('/superadmin/usuarios/rol', matricula='9999', rol='alumno')
ok(A.rol_de(A.collection.find_one({'matricula': '9999'})) == 'super_admin', 'no puede cambiarse a sí mismo')
post('/superadmin/usuarios/rol', matricula='3003', rol='root')
ok(A.rol_de(A.collection.find_one({'matricula': '3003'})) == 'admin', 'rol inválido se rechaza')
post('/superadmin/usuarios/rol', matricula='8888', rol='alumno')
ok(A.rol_de(A.collection.find_one({'matricula': '8888'})) == 'alumno', 'puede degradar a otro super admin de base de datos')
A.collection.update_one({'matricula': '2002'}, {'$set': {'intentos_fallidos': 5, 'bloqueado_hasta': A.datetime.utcnow() + A.timedelta(hours=1)}})
post('/superadmin/usuarios/desbloquear', matricula='2002')
u = A.collection.find_one({'matricula': '2002'}); ok(u['intentos_fallidos'] == 0 and u['bloqueado_hasta'] is None, 'desbloquear cuenta')
post('/superadmin/usuarios/eliminar', matricula='9999'); ok(A.collection.find_one({'matricula': '9999'}), 'no puede eliminarse a sí mismo')
post('/superadmin/usuarios/eliminar', matricula='2002'); ok(not A.collection.find_one({'matricula': '2002'}), 'elimina una cuenta')
r = c.post('/superadmin/usuarios/eliminar', data=dict(matricula='3003'))
ok(A.collection.find_one({'matricula': '3003'}), 'sin token CSRF no se puede eliminar')

# ---- API móvil
cm = A.app.test_client()
def bearer(mat):
    with A.app.app_context():
        return {'Authorization': 'Bearer ' + create_access_token(identity=mat)}
r = cm.get('/api/perfil', headers=bearer('12345')); j = r.get_json()
ok(j['es_admin'] is False and j['rol'] == 'alumno', 'API perfil: es_admin booleano False para alumno')
ok(cm.get('/api/admin/solicitudes', headers=bearer('12345')).status_code == 403, 'API admin: alumno 403')
ok(cm.get('/api/admin/solicitudes', headers=bearer('1001')).status_code == 200, 'API admin: admin 200')
ok(cm.get('/api/admin/solicitudes', headers=bearer('9999')).status_code == 403, 'API admin: super admin 403')
ok(cm.post('/api/inscripcion', headers=bearer('1001'), data={}).status_code == 403, 'API inscripción: admin 403')
print("ROLES OK")
