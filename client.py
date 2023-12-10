from utils import DES, RSA
import socket, threading, random, string

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 1234

uname = input("Masukkan username: ")
ip = '127.0.1.1'

selfpublic_key, selfprivate_key = RSA.generate_keypair(RSA.generate_big_prime(8),RSA.generate_big_prime(8))
print("Public Key", uname, selfpublic_key)
print("Private Key", uname, selfprivate_key)

s.connect((ip, port))
s.sendall(str.encode('\n'.join([str(uname), str(selfpublic_key)])))

clientRunning = True
sessionKey = "        "
publicKeyOther = ()

def receiveMsg(sock):
    serverDown = False
    while clientRunning and (not serverDown):
        try:
            global sessionKey
            global publicKeyOther
            msg = sock.recv(1024).decode('ascii')
            if '>>' in msg:
                print(msg, end='')
            elif '##' in msg:
                msg=msg.replace('##', '')
                msg = DES.toDecrypt(msg, sessionKey)
                print(msg)
            elif '@' in msg:
                msg=msg.replace('@', '')
                msg = RSA.decrypt_rsa(selfprivate_key, msg)
                sessionKey = msg
                print("Session Key", msg) #ini session key untuk ngomong
            elif '!!' in msg:
                if (uname == "alice"):
                    letters = string.ascii_lowercase
                    sessionKey = ''.join(random.choice(letters) for i in range(8))
                msg = msg.replace('!!(', '')
                msg = msg.replace(',', '')
                sep = ' '
                rest = msg.split(sep, 1)[0]
                msg = msg.replace(rest, '')
                msg = msg.replace(' ', '')
                msg = msg.replace(')', '')
                publicKeyOther = publicKeyOther + (int(rest),int(msg))
                print("Session Key", sessionKey)
                print(publicKeyOther)
            else:
                print(msg)
        except:
            print('Server tidak dapat diakses. Klik enter untuk exit...')
            serverDown = True

threading.Thread(target = receiveMsg, args = (s,)).start()
while clientRunning:
    tempMsg = input()
    if '**quit' in tempMsg:
        clientRunning = False
        s.send('**quit'.encode('ascii'))
    elif '**get' in tempMsg:
        s.send('**get'.encode('ascii'))
    elif '**send' in tempMsg:
        tempMsg = RSA.encrypt_rsa(publicKeyOther, sessionKey)
        msg = '@' + tempMsg
        s.send(msg.encode('ascii'))
    else:
        if sessionKey == "        ":
            print("Session Key belum dishare!")
        else:
            tempMsg = DES.toEncrypt(tempMsg, sessionKey)
            msg = uname + '>>' + tempMsg
            s.send(msg.encode('ascii'))