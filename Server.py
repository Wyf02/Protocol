import socket
import ssl
import os
from pyDes import des, CBC, PAD_PKCS5
import binascii
from Crypto import Random
import base64
from random import randint
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import hmac

class server:
    #写文件
    random_generator = Random.new().read
    rsa = RSA.generate(1024, random_generator)
    private_pem = rsa.exportKey()
    with open("server-private.pem", "wb") as f:
        f.write(private_pem)
    public_pem = rsa.publickey().exportKey()
    with open("server-public.pem", "wb") as f:
        f.write(public_pem)
    private_pem = rsa.exportKey()
    with open("client-private.pem", "wb") as f:
        f.write(private_pem)
    public_pem = rsa.publickey().exportKey()
    with open("client-public.pem", "wb") as f:
        f.write(public_pem)

    def get_cert(self, fd):
        if os.path.isfile(fd):
            fp = open(fd, 'rb')
            while(1):
                data = fp.read(2048)
                if not data:
                    break
                msg = data
            fp.close()
        return msg

    
    #计算密钥
    #会话密钥
    def __sessionkey(self, r1: int, r2: int, r3: int):
        #DES里必须是8
        key = self.__myPRF(r1, r2, r3)
        skey = str(key)
        if(len(skey) < 8):
            skey.ljust(8, '0')
        elif(len(skey) > 8):
            skey = skey[len(skey) - 9:len(skey) - 1]
        return skey

    #hmac生成mac要用到的密钥，实际上我将它和sessionkey用了一个生成函数
    def __mackey(self, r1, r2, r3):
        macKey = self.__myPRF(r2, r1, r3)
        key = str(macKey)
        if(len(key) < 8):
            key.ljust(8, '0')
        elif(len(key) > 8):
            key = key[len(key) - 9:len(key) - 1]
        return key

    #将三个重要的随机数合成一个密钥的算法
    def __myPRF(self, x: int, y: int, z: int) -> bytes:
        return ((x+y+z)& 0xffffffff).to_bytes(8, byteorder='big')
    
    #接收加密的msg
    def recv_msg(self, msg, sessionkey:str, mackey: str, client_socket):
        print(f"receive msg from server : {msg}")
        finished = "finished"
        p = 1
        
        for i in range(0, 7):
            if(msg[i] != finished[i]):
                p = 0
                break
        if(p == 0):
            des_obj = des(sessionkey, CBC, sessionkey, pad=None, padmode=PAD_PKCS5)
            t = binascii.a2b_hex(msg)
            msg = des_obj.decrypt(t, padmode=PAD_PKCS5)
            mac = msg[(len(msg)-64):len(msg)].decode("utf-8")
            message = msg[:(len(msg)-64)].decode("utf-8")
            h = hmac.new(mackey.encode("utf-8"),message.encode("utf-8"),digestmod='sha256')
            verify = 1
            print("MAC:",mac)
            for i in range(0, 63):
                if(mac[i] != h.hexdigest()[i]):
                    verify = 0
                    print("MAC Inconsistent")
                    msgException = "Server: MAC Inconsistent, Please resend."
                    client_socket.send(msgException.encode("utf-8"))
                    self.recv_msg(self, client_socket.recv(1024).decode("utf-8"), sessionkey, mackey, client_socket)
                    break
            if verify == 1:
                print("MAC Consistent\n")
                msg = "Server: MAC Consistent. Receive message successfully!!!"
                client_socket.send(msg.encode("utf-8"))
        elif(p == 1):
            print("finished")
        return p
                    

    def Server_hello(self):
        CA_FILE = "ca.crt"
        KEY_FILE = "server.key"
        CERT_FILE = "server.crt"
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            with context.wrap_socket(sock, server_side=True) as SSLSocket:
                SSLSocket.bind(('127.0.0.1', 8888))
                SSLSocket.listen(10)
                while True:
                    client_socket, addr = SSLSocket.accept()
                    msg = client_socket.recv(1024).decode("utf-8")
                    print(f"receive msg from client {addr}：{msg}")
                    client_random = int.from_bytes(client_socket.recv(1024), byteorder='big')
                    print(f"receive client_random：{client_random}")
                    msg = f"hello, client".encode("utf-8")
                    client_socket.send(msg)
                    client_socket.send(self.get_cert(CA_FILE))
                    client_socket.send(self.get_cert(KEY_FILE))
                    server_random = randint(1 << 31, 1 << 32)
                    client_socket.send(server_random.to_bytes(8, byteorder='big'))
                    print("------------------------hello done------------------------\n")

                    premaster = client_socket.recv(1024).decode("utf-8")
                    with open("server-private.pem") as f:
                        key = f.read()
                        rsakey = RSA.importKey(key)
                        cipher = Cipher_pkcs1_v1_5.new(rsakey)
                        cipher_text = cipher.decrypt(base64.b64decode(premaster), self.random_generator)
                    premaster = int(cipher_text.decode('utf-8'))
                    print(f"receive pre_master from server [after decode] : {premaster}")

                    sessionkey = self.__sessionkey(client_random, server_random, premaster)
                    print("Sessionkey: ", sessionkey)
                    mackey = self.__mackey(client_random, server_random, premaster)
                    print("-------------start communicate------------")
                    while(True):
                        msg = client_socket.recv(1024).decode("utf-8")
                        if(self.recv_msg(msg, sessionkey, mackey, client_socket)==1):
                            break
                    
if __name__ == "__main__":   
    server = server()
    server.Server_hello()

