# -*- coding: utf-8 -*-

import os
import re
import json
import idc
import idaapi
from idc import GetOpType, GetOpnd, ItemEnd
from idc_bc695 import *
from ida_name import *
import socket


VERSION = "0.1.0"


IDP_GITHUB = "https://github.com/Lavender-Tree/dbg_utils"


# Configuration file
IDP_CFGFILE = os.path.join(idaapi.get_user_idadir(), "idp.cfg")

# default configuration
DEF_CFG = {
    'ip': '192.168.23.134',
    'port': 19988
}


# 
cfg = None


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

        self.sock.send('START_SYN')
        buf = self.sock.recv(100)
        if b'SERVER_OK' in buf:
            self.sock.send(json.dumps(envs))
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

user_env = []

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class IDP_Plugin_t(idaapi.plugin_t):
    comment = "GDB Debug Utils (IDA Plugin)"
    help = IDP_GITHUB + '/README.md'
    wanted_name = "GDB Debug Utils"
    wanted_hotkey = "Ctrl-Alt-D"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global rsyn

        print("GDB Debug Utils Loading")

        print('Load Config')
        self.load_cfg()

        print('Load Syn')
        rsyn = IDPSyn()

        return idaapi.PLUGIN_OK
    

    def load_cfg(self):
        global cfg

        try:
            with open(IDP_CFGFILE, "r") as f:
                cfg = json.load(f)
        except:
            print('{} not found, use default setting'
                .format(IDP_CFGFILE))
            cfg = DEF_CFG


    def get_all_bp(self):
        bl = []
        n_bl = GetBptQty()
        for i in range(n_bl):
            ea = GetBptEA(i)
            bl.append({
                'name': get_ea_name(ea), 
                'ptr': ea, 
                'abs_ptr': False})
        return bl 

    def run(self, ctx):
        img_base = idaapi.get_imagebase()
        bl = self.get_all_bp() 

        rsyn.syn({
            'elf_base': img_base, 
            'envs': user_env, 
            'bl': bl})

    
    def term(self):
        print("IDP term")
        with open(IDP_CFGFILE, "w") as f:
            json.dump(cfg, f)



### user defined environments
def add_env(name, ea, abs_ea=False):
    global user_env

    user_env.append({
        'name': name,
        'ptr': ea, 
        'abs_ptr': abs_ea
    })

def del_env(name, ea, abs_ea=False):
    global user_env
    item = {
        'name': name,
        'ptr': ea, 
        'abs_ptr': abs_ea
    }
    user_env.pop(
        idp_plugin.user_env.index(item)
    )


### config when in idapython
def config(ip, port):
    global cfg
    cfg['ip'] = ip 
    cfg['port'] = port

# register IDA plugin
def PLUGIN_ENTRY():
    idp_plugin = IDP_Plugin_t()
    return idp_plugin

