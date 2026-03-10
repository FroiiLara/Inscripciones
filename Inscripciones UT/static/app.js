document.addEventListener("DOMContentLoaded", function () {
    const togglePassword = document.getElementById("togglePassword");
    const passwordField  = document.getElementById("password");

    if (togglePassword && passwordField) {
        togglePassword.addEventListener("click", function () {
            const isPasswordHidden = passwordField.type === "password";
            passwordField.type = isPasswordHidden ? "text" : "password";
            this.classList.toggle("active", isPasswordHidden);

            // Cambiar ícono entre ojo abierto y cerrado
            const icon = this.querySelector("i");
            if (icon) {
                icon.classList.toggle("fa-eye",      !isPasswordHidden);
                icon.classList.toggle("fa-eye-slash", isPasswordHidden);
            }
        });
    }
});