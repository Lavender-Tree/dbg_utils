import socket
import json 
import os
import signal
import sys
from dbg_utils.config import cfg, load_cfg, save_cfg



class IDPSynServer(object):
    
    def __init__(self):
        global cfg
        
        print('Load Config')
        load_cfg()

        self.sock = socket.socket(
            socket.AF_INET, 
            socket.SOCK_STREAM)
    
    def handle_envs(self, envs):
        with open(cfg['idp_env'] + '.json', "w") as f:
            json.dump(envs, f)

    def start(self):

        try :
            self.sock.bind((cfg['bind_ip'], cfg['port']))
            self.sock.listen(2)
        except:
            print('Check Your Permission')
            return

        print("[LISTEN] {}:{}".format(cfg['bind_ip'], cfg['port']))


        # 1. syn_client -> syn_server
        # START_SYN
        # 2. syn_server -> syn_client
        # SERVER_OK
        # 3. syn_client -> syn_server
        # [ENVS]
        # 4. syn_server -> syn_client (check format)
        #   - pass  
        #     SYN_FINISH
        #   - fail
        #     SYN_BADFMT
        while True:
            client, addr = self.sock.accept()
            print(client, addr)

            buf = client.recv(100)
            if b'START_SYN' not in buf:
                print('Unknown Cmd')
                client.close()
                continue

            client.send(b'SERVER_OK')

            envs = client.recv(0x1000)

            try:
                envs = json.loads(envs)
                self.handle_envs(envs)
            except:
                client.send(b'SYN_BADFMT')
                print('Wrong Format')
                print(envs)
                client.close()
                continue

            client.send(b'SYN_FINISH')

            client.close()
        
    def stop(self):
        save_cfg()
        self.sock.close()
        print('[IDPSynServer] Stop')

idpss = IDPSynServer()

def stop_idpss(sig, frame):
    idpss.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, stop_idpss)

if __name__ =="__main__":
    idpss.start()
