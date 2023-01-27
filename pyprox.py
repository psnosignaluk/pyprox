#!/usr/bin/env python3
'''
A Python3 proxy that hexdumps
'''

import sys
import socket
import threading

HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

def hexdump(src, length=16, show=True):                         # pylint: disable=inconsistent-return-statements
    '''
    Creates ASCII-printable characters if they exist, or produces a . if they don't

        Parameters:
            src (bytes, string)         : Takes inputs as bytes or a string
            length (int)                : Input length
            show (bool)                 : Whether to show the hex in the output or not

    '''
    if isinstance(src, bytes):
        src = src.decode()

    results = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])

        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        results.append(f'{i:04x}  {hexa:<{hexwidth}}  {printable}')

    if show:
        for line in results:
            print(line)
    else:
        return results

def receive_from(connection):
    '''
    Receive data from the remote host.

        Parameters:
            connection (bytes)         : The socket used by the remote host
    '''
    buffer = b""
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception:                                           # # pylint: disable=broad-except
        pass

    return buffer

def request_handler(buffer):
    '''
    Modify requests in-flight

        Parameters:
            buffer (bytes)              : Bytes buffer from the request object
    '''
    # perform packet modifications
    return buffer

def response_handler(buffer):
    '''
    Modify reponses in-flight

        Parameters:
            buffer (bytes)              : Bytes from the response object
    '''
    # perform packet modifications
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    '''
    Handle requests through the proxy.

        Parameters:
            client_socket (bytes)           : Byte-like object of the client socket
            remote_host (string)            : String containing the FQDN of the target host
            remote_port (string)            : String containing the port on the target host
            receive_first (bool)            : Whether or not to wait for the server to send data or not
    '''
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print(f"[<==] Sending {len(remote_buffer)} bytes to localhost.")
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print(f"[==>] Received {len(local_buffer)} bytes from locahost.")
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        if not len(local_buffer) or not len(remote_buffer):     # pylint: disable=use-implicit-booleaness-not-len
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    '''
    Loop through client/server exchanges.

        Parameters:
            local_host (string)             : The IP address of the localhost
            local_port (string)             : The port to spin the proxy up on
            remote_host (string)            : The FQDN or IP of the remote host
            remote_port (string)            : The port on the remote host
            receive_first (string)          : String representation of True or False as whether or not to make the proxy wait for traffic from the remote host
    '''
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:                                      # pylint: disable=invalid-name, broad-except
        print(f"[!!] Problem in bind: {e} !!!")
        print(f"[!!] Failed to listen on {local_host}:{int(local_port)}")
        print("[!!] Check for other listening sockets or verify permissions.")
        sys.exit(0)

    print(f"[*] Listening on {local_host}:{int(local_port)}")
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        # print local connection information
        print(f"> Received incoming connection from {addr[0]}:{addr[1]}")
        # start a thread to talk to the remote host
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first)
        )
        proxy_thread.start()

def main():
    '''
    Main function
    '''
    if len(sys.argv[1:]) != 5:
        print("Usage: pyprox [localhost] [localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: pyprox 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:                                 # pylint: disable=simplifiable-if-statement
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Keyboard interrupt received.")
