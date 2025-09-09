"""
Cliente TCP para envío de archivos
----------------------------------------------------------------------------
Este cliente se conecta a un servidor TCP que implementa el protocolo FTv1
(descrito abajo) y le envía un archivo (imagen, etc.) verificando la integridad
mediante SHA-256.

PROTOCOLO (lado cliente)
========================
1) Conectarse al servidor (host, port).
2) Esperar saludo 'READY\\n' (servidor está listo).
3) Enviar HEADER FIJO (48 bytes) + nombre (UTF-8) + datos del archivo:
      HEADER struct: "!4sBBHQ32s"
      - magic   : b"FTv1"
      - version : 1
      - opcode  : 1 (PUT)
      - name_len: N (largo del nombre en bytes)
      - file_size: tamaño del archivo (uint64)
      - sha256  : hash binario del archivo completo
4) Enviar el contenido del archivo por bloques (chunks).
5) Leer respuesta:
      "OK <sha256_hex>\\n" si todo bien
      "ERR <mensaje>\\n"    si hubo error
"""

import socket
import struct
import argparse
import os
import hashlib
import sys
import time

# ----------------------------
# Constantes del protocolo
# ----------------------------
MAGIC = b"FTv1"
VERSION = 1
OP_PUT = 1
HEADER_FMT = "!4sBBHQ32s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
CHUNK = 64 * 1024  # 64 KiB


def send_file(host: str, port: int, path: str) -> int:
    """
    Envía un archivo 'path' al servidor (host:port) usando el protocolo FTv1.
    Retorna 0 en éxito; distinto de 0 en error (para usar como exit code).
    """
    # 1) Validar archivo de origen
    if not os.path.isfile(path):
        print(f"Archivo no existe: {path}")
        return 2

    filename = os.path.basename(path)     # solo el nombre (sin directorio)
    file_size = os.path.getsize(path)     # tamaño en bytes

    # 2) Calcular SHA-256 del archivo completo (integridad extremo a extremo)
    #    Se hace previo al envío para incluir el hash en el header.
    hasher = hashlib.sha256()
    with open(path, "rb") as f_in:
        for chunk in iter(lambda: f_in.read(CHUNK), b""):
            hasher.update(chunk)
    sha256_bytes = hasher.digest()

    # 3) Construir header binario con struct
    name_bytes = filename.encode("utf-8")
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, OP_PUT, len(name_bytes), file_size, sha256_bytes)

    # 4) Establecer conexión TCP con el servidor
    with socket.create_connection((host, port), timeout=20) as sock:
        # 4.1) Esperar saludo READY del servidor
        ready = sock.recv(64)
        if not ready.startswith(b"READY"):
            print("Servidor no respondió READY")
            return 3

        # 4.2) Enviar header + nombre
        sock.sendall(header)
        sock.sendall(name_bytes)

        # 4.3) Enviar el archivo en chunks y mostrar progreso simple
        sent = 0
        t0 = time.time()
        with open(path, "rb") as f_in:
            while True:
                data = f_in.read(CHUNK)
                if not data:
                    break
                sock.sendall(data)
                sent += len(data)

                # Barra de progreso simple por porcentaje (sin librerías externas)
                pct = (sent / file_size) * 100 if file_size else 100.0
                sys.stdout.write(f"\rEnviado {sent}/{file_size} bytes ({pct:5.1f}%)")
                sys.stdout.flush()

        sys.stdout.write("\n")

        # 4.4) Leer respuesta final del servidor
        resp = sock.recv(256).decode("utf-8", errors="ignore").strip()
        dt = time.time() - t0

        if resp.startswith("OK "):
            # Éxito: servidor confirmó que el hash calculado coincide
            print(f"Servidor confirmó OK (sha256={resp.split()[1]}) en {dt:.2f}s")
            return 0
        else:
            print("Error del servidor:", resp)
            return 4


def main() -> None:
    """
    Punto de entrada del cliente:
    - Parsea argumentos --host, --port y la ruta del archivo a enviar.
    - Invoca send_file y usa el valor de retorno como exit code.
    """
    ap = argparse.ArgumentParser(description="Cliente TCP para enviar archivos (protocolo FTv1)")
    ap.add_argument("--host", required=True, help="Host del servidor (o dominio público de ngrok)")
    ap.add_argument("--port", required=True, type=int, help="Puerto del servidor (o asignado por ngrok)")
    ap.add_argument("file", help="Ruta del archivo a enviar (imagen, etc.)")
    args = ap.parse_args()

    code = send_file(args.host, args.port, args.file)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
