// ================================================================
// ARCHIVO: static/js/hcaptcha_curp.js
// Incluir en inscripcion.html y register.html con:
//   <script src="{{ url_for('static', filename='js/hcaptcha_curp.js') }}"></script>
// ================================================================

// ── VALIDACIÓN CURP EN TIEMPO REAL ───────────────────────────────
function iniciarValidacionCURP() {
    const campoCURP   = document.getElementById('curp');
    const indicador   = document.getElementById('curp-status');
    if (!campoCURP || !indicador) return;

    let timer = null;

    campoCURP.addEventListener('input', function () {
        const curp = this.value.trim().toUpperCase();
        this.value = curp;

        // Limpiar estado
        indicador.innerHTML = '';
        clearTimeout(timer);

        if (curp.length < 18) {
            indicador.innerHTML = '<span style="color:#999;font-size:0.82rem;">Ingresa los 18 caracteres de tu CURP</span>';
            return;
        }

        if (curp.length === 18) {
            indicador.innerHTML = '<span style="color:#f39c12;font-size:0.82rem;"><i class="fas fa-circle-notch fa-spin"></i> Verificando CURP en RENAPO...</span>';

            // Esperar 800ms antes de consultar (evitar llamadas por cada tecla)
            timer = setTimeout(() => validarCURPenAPI(curp, indicador), 800);
        }
    });
}

async function validarCURPenAPI(curp, indicador) {
    try {
        const resp = await fetch(`/api/validar_curp/${curp}`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        });

        const data = await resp.json();

        if (data.valida === true) {
            indicador.innerHTML = `
                <span style="color:#27ae60;font-size:0.82rem;">
                    <i class="fas fa-check-circle"></i> CURP válida — ${data.nombre} ${data.paterno} ${data.materno}
                </span>`;

            // Autocompletar nombre si el campo está vacío
            const campoNombre = document.getElementById('nombre');
            if (campoNombre && !campoNombre.value.trim()) {
                const nombreCompleto = `${data.nombre} ${data.paterno} ${data.materno}`.trim();
                campoNombre.value = nombreCompleto;
                campoNombre.style.background = '#e8f5e9';
            }

            // Autocompletar fecha de nacimiento si está disponible
            const campoFecha = document.getElementById('fecha_nacimiento');
            if (campoFecha && !campoFecha.value && data.nacimiento) {
                // Convertir formato RENAPO (DD/MM/YYYY) → (YYYY-MM-DD) para input date
                const partes = data.nacimiento.split('/');
                if (partes.length === 3) {
                    campoFecha.value = `${partes[2]}-${partes[1].padStart(2,'0')}-${partes[0].padStart(2,'0')}`;
                    campoFecha.style.background = '#e8f5e9';
                }
            }

        } else if (data.valida === false) {
            indicador.innerHTML = `
                <span style="color:#c0392b;font-size:0.82rem;">
                    <i class="fas fa-times-circle"></i> ${data.mensaje}
                </span>`;
        } else {
            // valida === null → API no disponible en este momento
            indicador.innerHTML = `
                <span style="color:#f39c12;font-size:0.82rem;">
                    <i class="fas fa-exclamation-triangle"></i> ${data.mensaje}
                </span>`;
        }

    } catch (err) {
        indicador.innerHTML = `
            <span style="color:#999;font-size:0.82rem;">
                <i class="fas fa-exclamation-circle"></i> No se pudo verificar la CURP en este momento.
            </span>`;
    }
}

// ── INICIALIZAR AL CARGAR EL DOM ──────────────────────────────────
document.addEventListener('DOMContentLoaded', iniciarValidacionCURP);
