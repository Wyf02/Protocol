import socket
import ssl
import base64
from Crypto.PublicKey import RSA
import binascii
from pyDes import des, CBC, PAD_PKCS5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import hmac
from random import randint

class client:
    ca_cert = None
    #计算密钥
    #计算会话密钥
    def __sessionkey(self, r1: int, r2: int, r3: int):
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
    

    #发送加密的msg
    def send_msg(self, msg: str, sessionkey: str, mackey: str):
        h = hmac.new(mackey.encode("utf-8"),msg.encode("utf-8"),digestmod='sha256')
        mac = h.hexdigest()
        msg += mac
        des_obj = des(sessionkey, CBC, sessionkey, pad=None, padmode=PAD_PKCS5)
        secret_bytes = des_obj.encrypt(msg, padmode=PAD_PKCS5)
        return binascii.b2a_hex(secret_bytes)
    
    #hello
    def Client_hello(self,):
        CA_FILE = "ca.crt"
        KEY_FILE = "client.key"
        CERT_FILE = "client.crt"
        
        #证书
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.check_hostname = False
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.socket() as sock:
            with context.wrap_socket(sock, server_side=False) as SSLsocket:
                SSLsocket.connect(('127.0.0.1', 8888))
                msg = "Hello server! We will follw TLS/SSL, We will use RSA、DES、SHA256. ".encode("utf-8")
                SSLsocket.send(msg)
                client_random = randint(1 << 31, 1 << 32)
                SSLsocket.send(client_random.to_bytes(8, byteorder='big'))
                msg = SSLsocket.recv(1024).decode("utf-8")
                print(f"-- Message from server : {msg}")
                self.ca_cert = SSLsocket.recv(3096).decode("utf-8")
                print(f"-- Cert from server: \n{self.ca_cert}")
                key_cert = SSLsocket.recv(3096).decode("utf-8")
                print(f"-- Key from server: \n{key_cert}")
                server_random = int.from_bytes(SSLsocket.recv(1024), byteorder='big')
                print(f"-- Server_random from server: {server_random}")
                print("-----------hello done------------")

                premaster = randint(1 << 31, 1 << 32)
                with open("server-public.pem") as f:
                    key = f.read()
                    rsakey = RSA.importKey(key)
                    cipher = Cipher_pkcs1_v1_5.new(rsakey)
                    cipher_text = base64.b64encode(cipher.encrypt(str(premaster).encode('utf-8')))
                    SSLsocket.send(cipher_text)

                sessionkey = self.__sessionkey(client_random, server_random, premaster)
                print("Sessionkey: ", sessionkey)
                mackey = self.__mackey(client_random, server_random, premaster)

                print("-------------start communicate------------")
                while(True):
                    print("Do you want to send a string to server?[1:yes; 0:no]\n")
                    choice = input("your choice is ")
                    print(choice)
                    if(int(choice) == 1):
                        msg = input("please enter the string to be encrypted: ")
                        print(msg)
                        SSLsocket.send(self.send_msg(msg, sessionkey, mackey))
                        print("send",self.send_msg(msg, sessionkey, mackey))
                        while(True):
                            recv = SSLsocket.recv(1024).decode("utf-8")
                            print(recv)
                            print("")
                            if(recv[:22] == "Server: MAC Inconsiste"):
                                SSLsocket.send(self.send_msg(msg, sessionkey, mackey))
                            elif(recv[:22] == "Server: MAC Consistent"):
                                break
                            else: 
                                print("[ERROR]server no correct response\n")
                                break
                    elif(int(choice) == 0):
                        msg = "finished"
                        print(msg)
                        SSLsocket.send(msg.encode("utf-8"))
                        SSLsocket.close()
                        break
                    else:
                        print("Please choose 1 or 2")

if __name__ == "__main__":
    client = client()
    client.Client_hello()

