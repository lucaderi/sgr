import socket
import time
# Create a connection to the server application on port 81

tcp_socket = socket.create_connection(("172.20.10.13", 81))
while True:
    try:
        data = str.encode("Hi. I am a TCP client sending data to the server")
        tcp_socket.sendall(data)
    finally:
        print("sended")

tcp_socket.close()
