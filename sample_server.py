import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 3126
s.bind(('localhost', port))
print('Socket binded to port 3126')
s.listen(3)
print('socket is listening')

while True:
    c, addr = s.accept()
    print('Got connection from ', addr)
    print(c.recv(1024))
    c.close()
