# Seguridad — Sistema de Inscripciones UTSC

Documento de las correcciones aplicadas al plan de vulnerabilidades (17 puntos) y de lo que
queda por hacer manualmente. Última actualización: 26/10/2026.

## 1. Qué cambió (resumen por punto del plan)

| # | Vulnerabilidad | Corrección |
|---|---|---|
| 1 | Token JWT en texto plano (app) | `flutter_secure_storage`: tokens cifrados con Keystore/Keychain. |
| 2 | Huella guardaba la contraseña | Ya no se guarda. La huella solo desbloquea el *refresh token* cifrado. |
| 3 | `print()` en login | `logDebug()` (solo imprime en modo debug). |
| 4 | Bloqueo de cuentas ajenas / sin límite por IP | Bloqueo por **matrícula + IP**, tope global por cuenta, límite por IP (Flask-Limiter), mensajes genéricos. |
| 5 | Sin CSRF en el panel web | CSRF activo (`csrf_token` en los formularios) + cookies `HttpOnly`, `Secure`, `SameSite=Strict`. |
| 6 | `allowBackup` | `allowBackup=false` + reglas de exclusión de respaldo. |
| 7 | APK sin ofuscación | R8 (minify/shrink) + `build_release.bat` / `.sh` con `--obfuscate`. |
| 8 | Enumeración de usuarios | Respuestas idénticas en registro y recuperación; límites por IP. |
| 9 | Sesión sin revocación | Access token 15 min (app) / 60 min (web), refresh 14 días con rotación, `/api/refresh`, `/api/logout`, lista de revocados. |
| 10 | Validación débil de archivos | 5 MB por archivo, 20 MB por petición, validación del contenido real (firma PDF/JPG/PNG). |
| 11 | Restablecer contraseña | Política de contraseña, enlace de un solo uso, cierre de sesiones abiertas. |
| 12 | Posibles secretos en el repo | Ver sección 3 (requiere acción manual). |
| 13 | Inscripción móvil simulada | `/api/inscripcion` y `/api/reinscripcion` con validación en servidor; la app ya envía de verdad. |
| 14 | Sin *certificate pinning* | **Pendiente a propósito** (ver sección 4). |
| 15 | `/api/perfil` devolvía de más | Lista blanca: matrícula, usuario, email, es_admin. |
| 16 | Enlace de reporte reutilizable | Un solo uso (identificador único en MongoDB con caducidad). |
| 17 | CURP a servicio externo | Solo con autorización explícita del alumno (casilla); apagable con `CURP_VALIDACION_EXTERNA=false`. |

## 2. Cómo desplegar

**Servidor (Render)**

1. `pip install -r requirements.txt` (se agregó `Flask-Limiter`).
2. En Render → *Environment*: `SECRET_KEY` y `JWT_SECRET_KEY` de **32 caracteres o más**
   (la app ya no arranca sin ellas). **No definas** `FLASK_ENV` en Render (en producción las
   cookies exigen HTTPS). En tu computadora pon `FLASK_ENV=development` en tu `.env`.
3. Sube los cambios a GitHub (Render redepliega solo).
4. Las sesiones web y móviles abiertas **se cerrarán una vez** (cambió el formato de los tokens).

**App móvil**

1. `flutter pub get`
2. Desinstala la versión anterior o abre la nueva una vez: se borran los datos antiguos en texto plano.
3. Los alumnos deberán **volver a activar la huella** una vez.
4. Para el APK final usa `build_release.bat` (Windows) y **guarda la carpeta `build/symbols`**.

## 3. Secretos en el repositorio (punto 12) — pasos manuales

El `.gitignore` ya ignora `.env`, pero si alguna vez se subió, sigue en el historial.

```bash
git log --all --full-history -- .env "*.env"
git log --all -p -S"mongodb+srv" --oneline | head
git log --all -p -S"SG." --oneline | head          # claves de SendGrid empiezan con SG.
```

Si aparece algo: **rota** esas claves (genera nuevas y cambia las de Render):
MongoDB Atlas (usuario/contraseña), Cloudinary (API secret), SendGrid (API key), hCaptcha (secret),
y `SECRET_KEY` / `JWT_SECRET_KEY`. Después, si quieres, limpia el historial con `git filter-repo`.
También revisa que el repo de la app (`InscripcionesUT-AppMovil`) no tenga claves ni `key.properties`.

## 4. Certificate pinning (punto 14) — decisión pendiente

Fijar el certificado de `onrender.com` puede dejar la app inservible el día que Render lo renueve
o cambie de autoridad certificadora. Recomendación: hacerlo **cuando exista un dominio propio**
y fijar la clave pública (SPKI) de la CA con una segunda clave de respaldo. Mientras tanto la app
solo usa HTTPS (`usesCleartextTraffic=false`).

## 5. Qué deberás notar al usar el sistema

* Tras 5 intentos fallidos desde un mismo dispositivo/red, ese dispositivo espera 15 minutos;
  el dueño real de la cuenta puede entrar desde otro lugar.
* El navegador puede mostrar «El formulario expiró» si una página se dejó abierta mucho tiempo: basta recargar.
* La reinscripción exige que la matrícula sea la de la cuenta que inició sesión.
* El cuatrimestre de la app móvil usa periodos (p. ej. `2025-A`) y la web usa 1–10: conviene unificarlo.

## 6. Pruebas automáticas

```bash
pip install mongomock
python pruebas/test_regresion.py     # dashboard, reportes, motivo de rechazo, edad ≥ 18
python pruebas/test_seguridad.py     # puntos 4, 5, 8, 9, 10, 11, 13, 15, 16, 17
python pruebas/test_limite.py        # límites de peticiones (429)
```

Ejecútalas desde la carpeta `Inscripciones UT`. La app Flutter no se pudo compilar en el entorno de
desarrollo: ejecuta `flutter analyze` y prueba en un teléfono real (login, huella, inscripción, cerrar sesión).
