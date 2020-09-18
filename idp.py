# -*- coding: utf-8 -*-

import os
import re
import json
import time
import socket
import idaapi


class Config(dict):
    IDP_CFGFILE = os.path.join(idaapi.get_user_idadir(), "cfg", "idp.cfg")

    DEF_CFG = {
        'ip': '192.168.23.134',
        'port': 19988
    }

    def __init__(self, path=IDP_CFGFILE, default=DEF_CFG):
        self.path = path
        if not os.path.exists(path):
            json.dump(default, open(self.path, 'w'), indent=4)
        self.cfg = json.load(open(path))
        for k, v in default.items():
            if not (k in self.cfg and self.cfg[k] is not None):
                self.__setitem__(k, v)

    def __getitem__(self, key):
        return self.cfg[key]

    def __setitem__(self, key, val):
        if key in self.cfg and self.cfg[key] == val:
            return
        self.cfg[key] = val
        json.dump(self.cfg, open(self.path, 'w'), indent=4)


# 
cfg = Config()


class UserEnvs(object):
    __envs = {}

    def __init__(self, envs={}):
        self.load()
        if isinstance(envs, dict):
            for key, val in envs.items():
                self.__envs[key] = val
        elif isinstance(envs, str):
            for key, val in self.unpack(envs).items():
                self.__envs[key] = val

    def add(self, name, va):
        self.__envs[name] = va - idaapi.get_imagebase()
        self.save()

    def add_abs(self, name, va):
        self.__envs[name] = va
        self.save()
    
    def delete(self, name):
        if name in self.__envs:
            self.__envs.__delitem__(name)
        self.save()

    def pack(self):
        return self.__envs
    
    def unpack(self, buf):
        return json.loads(buf)

    def save(self):
        path = os.path.join(os.getcwd(), "uenvs.json")
        with open(path, "w") as f:
            json.dump(self.__envs, f)

    def load(self):
        path = os.path.join(os.getcwd(), "uenvs.json")
        if os.path.exists(path):
            with open(path, "r") as f:
                self.__envs = json.load(f)

uenvs = UserEnvs()


class IDPSyn(object):

    def connect(self):
        self.sock.connect( (cfg['ip'], cfg['port']) )
    
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
    def syn(self, envs):

        self.sock = socket.socket(
            socket.AF_INET, 
            socket.SOCK_STREAM)

        try:
            self.connect()
        except:
            print(
                "[IDPSyn] Cannot Connect Syn Server. "
                "Check Config Fisrt. ")
            print(cfg)
            return

        self.sock.send(b'START_SYN')
        buf = self.sock.recv(100)
        if b'SERVER_OK' in buf:
            self.sock.send(envs.encode())
            buf = self.sock.recv(100)
            if b'SYN_FINISH' not in buf:
                print('SYN FAIL')
                return 
        else:
            print('SYN FAIL') 
            return 

        print('[%s] Syn Finish' % (time.ctime(time.time())))

        self.sock.close()

# 
rsyn = None

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class IDP_Plugin_t(idaapi.plugin_t):
    comment = "GDB Debug Utils (IDA Plugin)"
    help = 'https://github.com/agfn/dbg_utils/README.md'
    wanted_name = "GDB Debug Utils"
    wanted_hotkey = "Ctrl-Alt-D"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global rsyn
        print("GDB Debug Utils Loading")
        print('Load Syn')
        rsyn = IDPSyn()
        return idaapi.PLUGIN_OK

    def get_all_bp(self):
        bl = {}
        n_bl = idaapi.get_bpt_qty()
        base = idaapi.get_imagebase()
        for i in range(n_bl):
            ea = idaapi.get_bpt_tev_ea(i)
            name = idaapi.get_ea_name(ea)
            ea -= base
            if name == '':
                name = 'block_' + hex(ea)[2:]
            bl[name] = ea
        return bl

    def run(self, ctx):
        bl = self.get_all_bp() 

        rsyn.syn(json.dumps({
            'envs': uenvs.pack(), 
            'bl': bl}))
    
    def term(self):
        print("IDP term")


### config when in idapython
def idp_config(ip, port):
    global cfg
    cfg['ip'] = ip 
    cfg['port'] = port


# register IDA plugin
def PLUGIN_ENTRY():
    idp_plugin = IDP_Plugin_t()
    return idp_plugin

