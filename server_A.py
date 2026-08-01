import socket
import sys
import threading
import time
import crypto

MY_HOST = '0.0.0.0'
MY_PORT = 65431
REMOTE_PORT = 65432
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
    global session_key
    print("# Server A generating RSA Key Pair...")
    private_key, public_key = crypto.generate_rsa_keypair()
    public_key_bytes = crypto.serialize_public_key(public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((MY_HOST, MY_PORT))
        s.listen()
        print(f"# Server A listening for Server B on port {MY_PORT}...")

        conn, addr = s.accept()
        print(f"# Server B connected from {addr}")
        with conn:
            crypto.send_framed(conn, public_key_bytes)

            encrypted_session_key = crypto.recv_framed(conn)
            if not encrypted_session_key:
                print("# Server B disconnected during key exchange.")
                return

            session_key = crypto.decrypt_session_key(private_key, encrypted_session_key)
            print("# Secure key exchange completed! Secure channel live.")
            key_established.set()

            while True:
                payload = crypto.recv_framed(conn)
                if not payload:
                    safe_print("# Server B disconnected.")
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
                    safe_print(f"[Server B]: {msg_text}")
                    send_ack()


def send_handler():
    global send_socket_global
    key_established.wait()

    send_socket = None
    while True:
        try:
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            send_socket.connect((REMOTE_HOST, REMOTE_PORT))
            break
        except OSError:
            send_socket.close()
            time.sleep(0.5)

    send_socket_global = send_socket
    send_ready.set()

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
    t_recv = threading.Thread(target=receive_handler, daemon=True)
    t_send = threading.Thread(target=send_handler, daemon=True)

    t_recv.start()
    t_send.start()

    t_recv.join()
