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

def exploit():
	##################################################################### 
	######################## EXPLOIT CODE ###############################
	#####################################################################
	pass
	
if __name__ == "__main__":
	# === per-challenge config ===
	binary = None
	REMOTE = []
	CUSTOM_LIBC = None
	CUSTOM_LD = None
	
	gs = """
	break main
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


