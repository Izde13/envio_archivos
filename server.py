"""
Servidor TCP para recepción de archivos
-------------------------------------------------------------------------------
Este servidor implementa un protocolo de aplicación muy simple sobre TCP para
recibir archivos (por ejemplo, imágenes) desde un cliente. El diseño ilustra:
- Cómo "empaquetar" metadatos en un header binario (framing) para que ambas
  partes (cliente/servidor) sepan cómo comunicarse sobre un flujo TCP.
- Lectura/escritura por bloques (chunks) para archivos grandes.
- Verificación de integridad con SHA-256.

PROTOCOLO
=========
El cliente envía al servidor:
    1) HEADER FIJO (48 bytes) con formato struct: "!4sBBHQ32s"
       - magic(4)   : b"FTv1"        -> marca para reconocer el protocolo
       - version(1) : 1              -> versión del protocolo
       - opcode(1)  : 1              -> 1 = PUT (subir archivo). Futuro: 2=GET, 3=LIST...
       - name_len(2): N              -> largo en bytes del nombre (UTF-8)
       - file_size(8): tamaño del archivo (uint64, big-endian)
       - sha256(32) : hash binario SHA-256 del archivo completo
    2) N bytes con el nombre del archivo (UTF-8)
    3) file_size bytes con el contenido del archivo (stream binario)

El servidor:
    - Valida el header (magic, version, opcode).
    - Recibe el nombre y crea una ruta segura (basename).
    - Recibe el archivo por bloques, lo guarda, y calcula SHA-256 en vivo.
    - Compara el hash calculado con el recibido en header.
    - Responde:
        "OK <sha256_hex>\\n"  si todo está correcto
        "ERR <mensaje>\\n"    si hubo error (p. ej. hash distinto)

"""

import socket
import struct
import threading
import os
import hashlib
import argparse

# ----------------------------
# Constantes del protocolo
# ----------------------------
MAGIC = b"FTv1"         # Marca para identificar nuestro protocolo
VERSION = 1             # Versión del protocolo
OP_PUT = 1              # Operación PUT (subir archivo al servidor)
# Empaque binario (network byte order = big-endian, indicado por "!")
# 4s=4 bytes, B=uint8, B=uint8, H=uint16, Q=uint64, 32s=32 bytes
HEADER_FMT = "!4sBBHQ32s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Tamaño de bloque (chunk) para lectura/escritura de archivos
CHUNK = 64 * 1024  # 64 KiB


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Lee exactamente n bytes del socket. TCP es un stream; una sola llamada
    a recv() puede devolver menos de lo solicitado. Esta función acumula hasta
    recibir n bytes o lanza excepción si la conexión se cierra prematuramente.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexión cerrada mientras se recibían datos")
        buf += chunk
    return bytes(buf)


def handle_client(conn: socket.socket, addr, outdir: str) -> None:
    """
    Atiende una conexión entrante:
    - Envía saludo 'READY' para confirmar que el servidor está listo.
    - Recibe header + nombre + datos del archivo.
    - Guarda el archivo y verifica integridad SHA-256.
    - Responde 'OK' o 'ERR' según el resultado.
    """
    try:
        # Evita dejar sockets colgados indefinidamente
        conn.settimeout(60)

        # Handshake muy simple para que el cliente sepa que puede empezar
        conn.sendall(b"READY\n")

        # 1) Header fijo
        header = recv_exact(conn, HEADER_SIZE)
        magic, version, opcode, name_len, file_size, sha256_bytes = struct.unpack(HEADER_FMT, header)

        # Validaciones básicas del header
        if magic != MAGIC:
            conn.sendall(b"ERR magic_invalido\n")
            return
        if version != VERSION:
            conn.sendall(b"ERR version_no_soportada\n")
            return
        if opcode != OP_PUT:
            conn.sendall(b"ERR opcode_no_soportado\n")
            return
        if name_len == 0:
            conn.sendall(b"ERR nombre_vacio\n")
            return

        # 2) Nombre del archivo (N bytes, UTF-8)
        name_bytes = recv_exact(conn, name_len)
        filename = name_bytes.decode("utf-8", errors="strict")

        # Sanitizar para evitar que un cliente intente escribir fuera del directorio
        safe_name = os.path.basename(filename)

        # Asegurar carpeta de salida
        os.makedirs(outdir, exist_ok=True)
        dest_path = os.path.join(outdir, safe_name)

        # 3) Recepción del archivo por bloques, calculando SHA-256 en vivo
        hasher = hashlib.sha256()
        remaining = file_size
        with open(dest_path, "wb") as f:
            while remaining:
                to_read = CHUNK if remaining >= CHUNK else remaining
                data = recv_exact(conn, to_read)
                f.write(data)
                hasher.update(data)
                remaining -= len(data)

        # 4) Verificación de integridad
        if hasher.digest() == sha256_bytes:
            # Todo ok: responder con OK y el hash en hex
            conn.sendall(b"OK " + hasher.hexdigest().encode("ascii") + b"\n")
            print(f"[{addr[0]}] Recibido OK: {safe_name} ({file_size} bytes)")
        else:
            # Hash no coincide: opcionalmente borrar el archivo parcialmente recibido
            try:
                os.remove(dest_path)
            except Exception:
                pass
            conn.sendall(b"ERR sha256_mismatch\n")
            print(f"[{addr[0]}] ERROR: checksum no coincide para {safe_name}")

    except Exception as e:
        # Cualquier excepción: informamos al cliente y registramos en servidor
        try:
            conn.sendall(b"ERR " + str(e).encode("utf-8", errors="ignore") + b"\n")
        except Exception:
            pass
        print(f"[{addr[0]}] Excepción: {e}")
    finally:
        conn.close()


def main() -> None:
    """
    Punto de entrada del servidor:
    - Parsea argumentos --host, --port, --outdir.
    - Inicia socket TCP, escucha y maneja múltiples clientes con threads.
    """
    ap = argparse.ArgumentParser(description="Servidor TCP de recepción de archivos (protocolo FTv1)")
    ap.add_argument("--host", default="0.0.0.0", help="Dirección de escucha (por defecto 0.0.0.0)")
    ap.add_argument("--port", type=int, default=5001, help="Puerto de escucha (por defecto 5001)")
    ap.add_argument("--outdir", default="received", help="Directorio donde guardar los archivos recibidos")
    args = ap.parse_args()

    # Crear socket TCP IPv4 y configurarlo
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Permite reutilizar el puerto rápidamente tras reiniciar el server
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen(50)  # backlog: cuántas conexiones pueden quedar en cola

        print(f"Servidor escuchando en {args.host}:{args.port} -> guardando en '{args.outdir}'")

        # Bucle principal: aceptar conexiones y despacharlas a threads
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, args.outdir), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
