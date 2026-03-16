# Puerto Muerto
## Despliegue

Situarse en el directorio raíz del proyecto antes de ejecutar cualquier script.

```bash
# 1. Preparar la imagen (instala dependencias y construye el contenedor)
bash prepare.sh [nombre] [ftp_port] [http_port] [ssh_port] [portal_port]

# 2. Iniciar el contenedor
bash start.sh

# 3. Detener el contenedor
bash stop.sh

# 4. Eliminar el contenedor y la imagen
bash remove.sh
```

Los archivos `.env` y `dockername.txt` se generan automáticamente con los puertos
y el nombre del contenedor configurados. Se pueden eliminar con `bash clearenv.sh`.

---

## Puertos internos del contenedor

| Servicio        | Puerto interno |
| --------------- | -------------- |
| FTP (vsftpd)    | 2121           |
| HTTP (SIGEPORT) | 8090           |
| SSH (OpenSSH)   | 2222           |
| Portal de flags | 3000           |

El puerto FTP (`PORTOUT`) es el único expuesto directamente al participante como
punto de entrada. Los puertos HTTP y SSH se desbloquean mediante port knocking.
El portal de flags se expone en un puerto separado configurable.

---

## Variables de entorno requeridas

El `docker-compose.yml` espera las siguientes variables de entorno en el archivo `.env`:

| Variable        | Descripción                         |
| --------------- | ------------------------------------ |
| `FLAG1`       | Valor de la flag 1 (`G3CUBO{...}`) |
| `FLAG2`       | Valor de la flag 2 (`G3CUBO{...}`) |
| `FLAG3`       | Valor de la flag 3 (`G3CUBO{...}`) |
| `PORTOUT`     | Puerto externo del host para FTP     |
| `PORTAL_PORT` | Puerto externo para el portal        |

---

## Script de solución automatizada

El directorio `solution/` contiene `solve.sh`, que replica la cadena de explotación
completa sin utilizar información privilegiada.

```bash
bash solution/solve.sh <IP> <FTP_PORT> <PORTAL_PORT> <SSH_PORT> <HTTP_PORT>

# Ejemplo con puertos por defecto:
bash solution/solve.sh 127.0.0.1 2121 3000 2222 8090
```

Requisitos del sistema que ejecuta el script: `ftp`, `knock`, `curl`, `ssh`,
`ssh-keygen`, `sha256sum`, `openssl`, `xxd`, `scp`.

---

## Estructura del proyecto

```
.
├── docker-compose.yml
├── Dockerfile
├── prepare.sh
├── start.sh
├── stop.sh
├── remove.sh
├── clearenv.sh
├── docs/
│   ├── descripcion.md     <- Entregable al participante
│   └── writeup.md         <- Solución completa (uso interno)
├── html/
│   ├── app.py
│   ├── static/
│   │   └── style.css
│   └── templates/
│       ├── login.html
│       └── panel.html
├── src/
│   ├── prepare.sh
│   └── execute.sh
├── flag/
│   ├── flag1.txt
│   ├── flag2.txt
│   └── flag3.txt
└── solution/
    └── solve.sh
```

---

## Información técnica

| Componente          | Detalle                                                                                                                             |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Sistema operativo   | Debian Bookworm (slim)                                                                                                              |
| Contenedor          | Docker — imagen única multi-servicio                                                                                              |
| Servicios activos   | FTP (vsftpd), HTTP (Flask/SIGEPORT), SSH (OpenSSH), knockd, cron                                                                    |
| Portal de flags     | Flask + Gunicorn                                                                                                                    |
| Dificultad          | Media-Alta                                                                                                                          |
| Técnicas cubiertas | Port knocking, encoding chain, SQLi auth bypass, UNION-based extraction, SSH key cracking, FTP metadata, AES decrypt, SUID GTFOBins |
