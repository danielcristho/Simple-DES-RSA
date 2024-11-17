import socket
import threading
import re

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverRunning = True
ip = str(socket.gethostbyname(socket.gethostname()))
port = 2024

clients = {}
clientPublicKeys = {}

s.bind((ip, port))
s.listen()
print('IP Address Server: %s'%ip)

def handleClient(client, uname):
    clientConnected = True
    keys = clients.keys()
    while clientConnected:
        try:
            msg = client.recv(1024).decode('ascii')
            found = False
            if '**quit' in msg:
                response = 'Goodbye!' # jika client menjalankan command **quit
                client.send(response.encode('ascii'))
                clients.pop(uname)
                print(uname + ' logout dari server')
                clientConnected = False
                """
                server mengirimkan kunci publik dari klien lain kepada klien.
                """
            elif '**get' in msg:
                for i in clients:
                    if uname!=i:
                        response = '!!' + clientPublicKeys[i]
                        client.send(response.encode('ascii'))
                """
                server mengirimkan pesan tersebut kepada semua klien lainnya.
                """
            elif '@' in msg:
                for i in clients:
                    if uname!=i:
                        response = '@' + msg
                        clients.get(i).send(msg.encode('ascii'))
            else:
                """
                Jika pesan tidak mengandung perintah khusus, server mengenkripsi dan mengirimkan pesan kepada klien lainnya menggunakan DES.
                Pesan tersebut juga dicetak di server tapi terencode.
                """
                for name in keys:
                    if(uname!=name):
                        temp=msg
                        msg = uname +'>>'
                        print(msg, end ='')
                        msg2=temp
                        msg2=msg2.replace(uname+'>>', '')
                        msg2=re.findall('..',msg2)
                        for x in range(len(msg2)):
                            msg2[x]=chr(int(msg2[x],16))
                        print(''.join(msg2))
                        msg=uname+'>>'
                        clients.get(name).send(msg.encode('ascii'))
                        msg = temp
                        msg = msg.replace(uname+'>>', '##')
                        clients.get(name).send(msg.encode('ascii'))
                        found = True
                if(not found):
                    client.send('Gagal mengirim pesan, tidak ada lawan bicara.'.encode('ascii'))
        except:
            clients.pop(uname)
            print(uname + ' logout dari server')
            clientConnected = False

"""
menyimpan informasi dari client (nama dan pub key)
"""
while serverRunning:
    client, address = s.accept()
    uname, publickeyclient = [str(i) for i in client.recv(1024).decode('ascii').split('\n')]
    print(str(uname),'connected to the server with public key',str(publickeyclient))
    client.send('\nHalo! Mulai chat dengan lawan bicaramu!\n'.encode('ascii'))

    if(client not in clients):
        clients[uname] = client
        clientPublicKeys[uname] = publickeyclient
        threading.Thread(target = handleClient, args = (client, uname, )).start()