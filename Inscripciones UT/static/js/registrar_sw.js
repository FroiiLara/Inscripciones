// Registro del Service Worker — incluir antes de </body> en base.html
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/service-worker.js')
      .then((reg) => console.log('[SW] Registrado correctamente, scope:', reg.scope))
      .catch((err) => console.error('[SW] Error al registrar:', err));
  });
}
