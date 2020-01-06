
import re
from dbg_utils.config import cfg, load_cfg
import json


def ida_dbg(p):
    load_cfg()
    with open(cfg['idp_env'] + '.json', "r") as f:
        env_bl = json.load(f)
    
    envs = env_bl['envs']
    bl = env_bl['bl']

    gdb_cmd = ''

    with open("/proc/{}/maps".format(p.pid), "r") as f:
        buf = f.read(30)
        text = re.findall('([\da-fA-F]+)(-)', buf)[0][0]
        real_elf_base = int(text, 16)

    for key, val in envs.items():
        val = val + real_elf_base

        gdb_cmd += 'set ${}={}\n'\
            .format(key, hex(val))

    for key, val in bl.items():
        val = val + real_elf_base

        gdb_cmd += 'set ${}={}\n'\
            .format(key, hex(val)) 
        
        gdb_cmd += 'b *${}\n'.format(key) 
    
    return gdb_cmd