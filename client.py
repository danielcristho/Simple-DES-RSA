import socket
import threading
from utils import RSA, DES
import random
import string

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 1212

uname = input("Masukkan username: ")
ip = '127.0.1.1'

"""
generate&store key
"""
selfpublic_key, selfprivate_key = RSA.generate_keypair(RSA.generate_big_prime(8),RSA.generate_big_prime(8))
print("Public Key", uname, selfpublic_key)
print("Private Key", uname, selfprivate_key)

"""
send information(username & pub key) to server
"""
s.connect((ip, port))
s.sendall(str.encode('\n'.join([str(uname), str(selfpublic_key)])))

clientRunning = True
sessionKey = "        "
publicKeyOther = () # save key from other user

def receiveMsg(sock):
    serverDown = False
    while clientRunning and (not serverDown):
        try:
            """
            sessionKey -> menyimpan kunci sesi (session key) yang digunakan dalam komunikasi.
            publicKeyOther -> menyimpan pub key dari user lain
            menerima pesan dari server dengan maksimum panjang 1024 byte dan mendekodekannya menggunakan encoding ASCII.
            """
            global sessionKey
            global publicKeyOther
            msg = sock.recv(1024).decode('ascii')
            """
            mengecek apakah pesan yang diterima memiliki pola '>>'. Jika iya, maka pesan tersebut dicetak tanpa perubahan
            mengecek apakah pesan yang diterima memiliki pola '##, @'. Jika iya, maka pesan tersebut diubah (menghapus tanda) dan kemudian didekripsi
            mengecek apakah pesan yang diterima memiliki pola '!!'. Jika iya, maka pesan tersebut diubah (menghapus '!!(') dan diolah untuk mendapatkan pub key dari user yang lain
            """
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
                print("Session Key", msg) #ini session key
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
                print("Session Key: ", sessionKey)
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

        """
        mengirimkan permintaan ke server untuk mendapatkan kunci publik dari pengguna lain
        """
    elif '**get' in tempMsg:
        s.send('**get'.encode('ascii'))

        """
        maka enkripsi session key menggunakan kunci publik dari pihak lain dan kirim pesan ke server.
        """
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