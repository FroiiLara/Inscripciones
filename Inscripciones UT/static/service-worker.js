// ======================================================
// Service Worker — Inscripciones UTSC
// Controla el ciclo de vida de la PWA: install, activate, fetch
// ======================================================

// Cambia este número cada vez que actualices los archivos
// estáticos que quieres cachear. Al cambiar, el activate()
// borra automáticamente la versión anterior del caché.
const CACHE_VERSION = 'utsc-inscripciones-v1';

// Recursos estáticos mínimos que sí tiene sentido cachear
// (no se cachean rutas dinámicas como /login, /pagina_principal, etc.
// porque su contenido depende de la sesión del usuario).
const ARCHIVOS_ESTATICOS = [
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
];

// ── INSTALL ────────────────────────────────────────────
// Se dispara una sola vez, cuando el navegador descarga el
// Service Worker por primera vez (o detecta una versión nueva).
// Aquí precargamos el caché con los archivos estáticos base.
self.addEventListener('install', (event) => {
  console.log('[SW] Instalando y precargando caché:', CACHE_VERSION);
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(ARCHIVOS_ESTATICOS))
  );
  self.skipWaiting(); // activa la nueva versión sin esperar a cerrar pestañas
});

// ── ACTIVATE ───────────────────────────────────────────
// Se dispara cuando el Service Worker pasa a estar "activo".
// Aquí es donde se hace la LIMPIEZA DE CACHÉ: se eliminan
// todas las versiones de caché anteriores a la actual.
self.addEventListener('activate', (event) => {
  console.log('[SW] Activando y limpiando cachés viejos');
  event.waitUntil(
    caches.keys().then((nombres) =>
      Promise.all(
        nombres
          .filter((nombre) => nombre !== CACHE_VERSION)
          .map((nombre) => {
            console.log('[SW] Eliminando caché obsoleto:', nombre);
            return caches.delete(nombre);
          })
      )
    )
  );
  self.clients.claim(); // toma control de las pestañas abiertas de inmediato
});

// ── FETCH ──────────────────────────────────────────────
// Se dispara en cada petición que hace la página.
// Estrategia: "cache first, network fallback" solo para los
// archivos estáticos; todo lo demás (rutas dinámicas, API)
// siempre va a la red para no mostrar datos desactualizados.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  const esEstatico = ARCHIVOS_ESTATICOS.some((ruta) => url.pathname === ruta);

  if (esEstatico) {
    event.respondWith(
      caches.match(event.request).then((respuestaCache) => {
        return respuestaCache || fetch(event.request);
      })
    );
  }
  // Si no es un archivo estático, no se intercepta: se deja pasar a la red normalmente.
});
