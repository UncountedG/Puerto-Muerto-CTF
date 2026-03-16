# Puerto Muerto — Descripción del Reto

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
