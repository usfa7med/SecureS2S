import socket
import sys
import threading
import time
import crypto

MY_HOST = '0.0.0.0'
MY_PORT = 65432
REMOTE_PORT = 65431
REMOTE_HOST = HOST_IP_ADDRESS

session_key = None
key_established = threading.Event()   
send_ready = threading.Event()        

send_socket_global = None

PROMPT = "> "
print_lock = threading.Lock()


def safe_print(msg):
    with print_lock:
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        print(msg)
        sys.stdout.write(PROMPT)
        sys.stdout.flush()


def send_ack():
    if not send_ready.wait(timeout=5):
        safe_print("[!] Could not send ACK: outbound channel not ready yet.")
        return
    try:
        ack_payload = crypto.aes_gcm_encrypt(session_key, b"__ACK__")
        crypto.send_framed(send_socket_global, ack_payload)
    except Exception as e:
        safe_print(f"[!] Failed to send ACK: {e}")


def receive_handler():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((MY_HOST, MY_PORT))
        s.listen()
        print(f"# Server B listening for Server A on port {MY_PORT}...")

        conn, addr = s.accept()
        print(f"# Server A connected from {addr}")
        with conn:
            while True:
                payload = crypto.recv_framed(conn)
                if not payload:
                    safe_print("# Server A disconnected.")
                    break
                try:
                    decrypted = crypto.aes_gcm_decrypt(session_key, payload)
                    msg_text = decrypted.decode('utf-8')
                except Exception as e:
                    safe_print(f"[!] Dropped a corrupt/invalid message: {e}")
                    continue

                if msg_text == "__ACK__":
                    safe_print(" (Arrived)")
                else:
                    safe_print(f"[Server A]: {msg_text}")
                    send_ack()


def send_handler():
    global session_key, send_socket_global

    print(f"# Server B connecting to Server A at {REMOTE_HOST}:{REMOTE_PORT}...")
    send_socket = None
    while True:
        try:
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            send_socket.connect((REMOTE_HOST, REMOTE_PORT))
            break
        except OSError:
            send_socket.close()
            time.sleep(1)

    public_key_bytes = crypto.recv_framed(send_socket)
    if not public_key_bytes:
        safe_print("[!] Server A disconnected during key exchange.")
        return

    server_public_key = crypto.load_public_key(public_key_bytes)
    session_key = crypto.generate_aes_key()
    encrypted_session_key = crypto.encrypt_session_key(server_public_key, session_key)
    crypto.send_framed(send_socket, encrypted_session_key)
    print("# Secure key exchange completed! Secure channel live.")

    send_socket_global = send_socket
    send_ready.set()
    key_established.set()

    while True:
        try:
            msg = input(PROMPT)
            if not msg or msg.lower() == 'exit':
                break
            encrypted_msg = crypto.aes_gcm_encrypt(session_key, msg.encode('utf-8'))
            crypto.send_framed(send_socket, encrypted_msg)
        except Exception as e:
            safe_print(f"[!] Send error: {e}")
            break


if __name__ == "__main__":
    t_send = threading.Thread(target=send_handler, daemon=True)
    t_recv = threading.Thread(target=receive_handler, daemon=True)

    t_send.start()
    key_established.wait()
    t_recv.start()

    t_send.join()
