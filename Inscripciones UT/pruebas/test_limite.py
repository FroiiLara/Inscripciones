import os, sys
os.environ.update(SECRET_KEY='k'*40, JWT_SECRET_KEY='j'*40, MONGO_URI='mongodb://x', RATELIMIT_ENABLED='true',
                  LIMITE_LOGIN='3 per minute', LIMITE_REGISTRO='2 per hour', LIMITE_RECUPERAR='2 per hour')
os.environ.pop('FLASK_ENV', None)
import mongomock, pymongo
pymongo.MongoClient = mongomock.MongoClient
sys.path.insert(0, os.getcwd())
import app as A
A.app.config['TESTING'] = True
A.enviar_email = lambda *a: None
ok = lambda cond, msg: print(('PASS ' if cond else 'FAIL ') + msg) or (cond or sys.exit(1))
c = A.app.test_client()
post = lambda url, ip, **kw: c.post(url, headers={'X-Forwarded-For': ip}, **kw)
cods = [post('/api/login', '1.1.1.1', json=dict(matricula='1', contrasena='x')).status_code for _ in range(5)]
ok(cods == [401, 401, 401, 429, 429], f'/api/login: 3 por minuto y luego 429 {cods}')
r = post('/api/login', '1.1.1.1', json={}); ok(r.status_code == 429 and r.get_json()['ok'] is False, '429 en JSON para la app')
ok(post('/api/login', '2.2.2.2', json=dict(matricula='1', contrasena='x')).status_code == 401, 'otra IP (X-Forwarded-For) no se ve afectada')
cods = [post('/login', '3.3.3.3', data=dict(matricula='1', contrasena='x')).status_code for _ in range(4)]
ok(cods[:3] == [200, 200, 200] and cods[3] == 302, f'/login web: el 4.º intento es redirigido con aviso {cods}')
cods = [post('/api/recuperar_contrasena', '4.4.4.4', json={'email': 'a@virtual.utsc.edu.mx'}).status_code for _ in range(3)]
ok(cods == [200, 200, 429], f'recuperar contraseña limitado {cods}')
cods = [post('/api/registro', '5.5.5.5', json={}).status_code for _ in range(3)]
ok(cods == [400, 400, 429], f'registro limitado {cods}')
print('LIMITES OK')
