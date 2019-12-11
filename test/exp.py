
from pwn import *
from dbg_utils import *

DEBUG = True

context.log_level = 'debug'

p = process("./love_house")

# gdb_cmd = dbg_pie(p, {
#     'elf_base': 0x400000,
#     'menu': 0x400A5A,
#     'cur': 0x601030
# }) + '''
# b *$menu
# b free
# c
# '''

gdb_cmd = ida_dbg(p) + '\nc\n'


if DEBUG:
    gdb.attach(p, gdb_cmd)

def cmd(op):
    p.sendlineafter('exit\n', str(op))

def add(size, cont, ext=[]):
    cmd(1)
    p.sendlineafter('size : ', str(size))
    p.sendafter('content : ', cont)

    if len(ext) == 0:
        p.sendlineafter('(Y/n)\n', 'Y')
    
    for buf in ext:
        p.sendlineafter('(Y/n)\n', '')
        p.sendlineafter('size : ', str(len(buf)))
        p.sendafter('content : ', buf)

def free():
    cmd(2)

### 
# bug analysis
# 1. heap overflow
# 
# #

add(0x100000, 'bbbb')

p.interactive()

