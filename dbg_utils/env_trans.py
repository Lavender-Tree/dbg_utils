
import re
from dbg_utils.config import cfg, load_cfg
import json

# must contain 'elf_base' 
def dbg_pie(p, gdb_env):
    with open("/proc/{}/maps".format(p.pid), "r") as f:
        buf = f.read(30)
        real_elf_base = int(re.findall('([\da-fA-F]+)(-)', buf)[0][0], 16)
    gdb_cmd = ''
    for key, val in gdb_env.items():
        gdb_cmd += 'set ${}={}\n'\
            .format(key, hex(val - gdb_env['elf_base'] + real_elf_base))
    return gdb_cmd


def ida_dbg(p):
    load_cfg()
    with open(cfg['idp_env'] + '.json', "r") as f:
        env_bl = json.load(f)
    
    elf_base = env_bl['elf_base']
    envs = env_bl['envs']
    bl = env_bl['bl']

    gdb_cmd = ''

    with open("/proc/{}/maps".format(p.pid), "r") as f:
        buf = f.read(30)
        real_elf_base = int(re.findall('([\da-fA-F]+)(-)', buf)[0][0], 16)
    
    for env in envs:
        p = env['ptr']
        if not env['abs_ptr']:
            p = env['ptr'] - elf_base + real_elf_base

        gdb_cmd += 'set ${}={}\n'\
            .format(env['name'], hex(p))

    for b in bl:
        p = b['ptr']
        if not b['abs_ptr']:
            p = b['ptr'] - elf_base + real_elf_base

        if b['name'] != '':
            gdb_cmd += 'set ${}={}\n'\
                .format(b['name'], hex(p))

            gdb_cmd += 'b *${}\n'.format(b['name'])
        else:
            gdb_cmd += 'b *${}\n'.format(hex(p))
    
    return gdb_cmd