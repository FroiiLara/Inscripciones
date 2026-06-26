# ================================================================
# Dockerfile — Sistema de Inscripciones UTSC
# Imagen base: Python 3.12 slim (ligera, sin paquetes innecesarios)
# ================================================================

FROM python:3.12-slim

# Metadatos de la imagen
LABEL maintainer="FroiiLara"
LABEL project="Sistema de Inscripciones UTSC"
LABEL version="1.0"

# Evitar que Python genere archivos .pyc y active el buffer
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Instalar dependencias del sistema necesarias para PyMongo y cryptography
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar primero requirements.txt para aprovechar el caché de capas de Docker
# Si requirements.txt no cambia, Docker no reinstala las dependencias
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el resto del proyecto al contenedor
COPY . .

# Exponer el puerto en el que corre Flask
# Render asigna el puerto dinámicamente via variable PORT
EXPOSE 5000

# Comando de inicio de la aplicación
# Usar la variable PORT si existe (Render), sino usar 5000 (local)
CMD ["python", "app.py"]
