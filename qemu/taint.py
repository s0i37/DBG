from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct
import string
import colorama
import sys
sys.path.append(".")
import gdb_helper

gdb_helper.gdb = gdb

PAGE_SIZE = 0x1000


class Cpu:

	def get(self,register):
		return self.__dict__[register]

	def update_registers(self):
		for register,value in gdb_helper.get_registers().items():
			self.__dict__[ register ] = value

	def show_registers(self, group=''):
		if group == '':
			for register in ['eax','ecx','edx','ebx','esp','ebp','esi','edi','eip','eflags']:
				gdb_helper.log( colorama.Fore.GREEN + "\t\t%s %s" % ( register.upper(), deref( self.__dict__[register] ) ) + colorama.Fore.RESET )
		elif group == 'mmx':
			for register in ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7']:
				gdb_helper.log( colorama.Fore.GREEN + "\t\t%s %s" % ( register.upper(), deref( self.__dict__[register] ) ) + colorama.Fore.RESET )
		elif group == 'sse':
			for register in ['st0','st1','st2','st3','st4','st5','st6','st7']:
				gdb_helper.log( colorama.Fore.GREEN + "\t\t%s %s" % ( register.upper(), deref( self.__dict__[register] ) ) + colorama.Fore.RESET )

read = set()
write = set()
allocated_regions = set()
def _mem_access(uc, access, address, size, value, user_data):
	global read, write
	if access in (UC_MEM_WRITE,):
		for i in range(size):
			write.add( address + i )
	else:
		for i in range(size):
			read.add( address + i )

def _mem_add_page(uc, access, address, size, value, user_data):
	try:
		_alloc_region(address)
	except:
		gdb_helper.log( colorama.Back.RED + "\t[!] error allocating memory at 0x%08x" % (address,) + colorama.Back.RESET )

def _alloc_region(address):
	global allocated_regions
	address &= 0xfffff000
	mu.mem_map( address, PAGE_SIZE)
#	gdb_helper.log( colorama.Fore.BLUE + "\t[i] alloc(0x%08x)" % (address & 0xfffff000,) + colorama.Fore.RESET )
	allocated_regions.add( address )

def _free_regions():
	global allocated_regions
	for region in allocated_regions:
		try:
			mu.mem_unmap(region, PAGE_SIZE)
#			gdb_helper.log( colorama.Fore.BLUE + "\t[i] free(0x%08x)" % (region,) + colorama.Fore.RESET )
		except Exception as e:
			gdb_helper.log(str(e))
	allocated_regions = set()


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.hook_add(UC_HOOK_MEM_WRITE, _mem_access)
mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, _mem_add_page)
mu.hook_add(UC_HOOK_MEM_READ, _mem_access)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, _mem_add_page)
mu.mem_map(0, PAGE_SIZE)
cpu = Cpu()

def get_used_memory(opcode, cpu):
	global mu, read, write
	read = set()
	write = set()
	try:
		_alloc_region(cpu.eip)
	except:
		pass
	mu.mem_write(cpu.eip, opcode)

	max_attempts = 5
	while True:
		try:
			max_attempts -= 1
			if max_attempts <= 0:
				gdb_helper.log(colorama.Back.RED + "\t[!] error emulation\n"  + colorama.Back.RESET)
				break

			mu.reg_write(UC_X86_REG_EAX, cpu.eax)
			mu.reg_write(UC_X86_REG_ECX, cpu.ecx)
			mu.reg_write(UC_X86_REG_EDX, cpu.edx)
			mu.reg_write(UC_X86_REG_EBX, cpu.ebx)
			mu.reg_write(UC_X86_REG_ESP, cpu.esp)
			mu.reg_write(UC_X86_REG_EBP, cpu.ebp)
			mu.reg_write(UC_X86_REG_ESI, cpu.esi)
			mu.reg_write(UC_X86_REG_EDI, cpu.edi)
			mu.emu_start( cpu.eip, cpu.eip + len(opcode) )
			mu.emu_stop()
			break
		except KeyboardInterrupt:
			mu.emu_stop()
			break
		except Exception as e:
			mu.emu_stop()
			read = set()
			write = set()
			#gdb_helper.log(str(e))
	return (read, write)

def get_used_registers(opcode):
	global md
	read = set()
	write = set()
	for inst in md.disasm(opcode, 0):
		(regs_read, regs_write) = inst.regs_access()
		break
	for reg_read in regs_read:
		read.add( inst.reg_name(reg_read) )
	for reg_write in regs_write:
		write.add( inst.reg_name(reg_write) )
	return (read, write)

def get_full_register(register):
	register = register.lower()
	if register in ('eax', 'ax', 'ah', 'al'):
		return 'eax'
	elif register in ('ecx', 'cx', 'ch', 'cl'):
		return 'ecx'
	elif register in ('edx', 'dx', 'dh', 'dl'):
		return 'edx'
	elif register in ('ebx', 'bx', 'bh', 'bl'):
		return 'ebx'
	elif register in ('ebx', 'bx'):
		return 'esp'
	elif register in ('ebp', 'bp'):
		return 'ebp'
	elif register in ('esi', 'si'):
		return 'esi'
	elif register in ('edi', 'di'):
		return 'edi'
	else:
		return ''

def disas(opcode):
	mnem = ""
	for inst in md.disasm(opcode, 0):
		mnem = "%s %s" % (inst.mnemonic, inst.op_str)
		break
	return mnem

def _ascii(dword):
	buf = ''
	_bytes = struct.pack("<I", dword)
	for byte in _bytes:
		if chr(byte) in string.printable[:-5]:
			buf += chr(byte)
		else:
			buf += "."
	return buf

def deref(ptr):
	buf = '0x%08x' % ptr
	if ptr <= 0xffffffff:
		for _ in range(5):
			buf += colorama.Fore.YELLOW + ' "%s"' % ( _ascii(ptr), ) + colorama.Fore.RESET
			ptr = gdb_helper.ptr(ptr)
			if ptr == None:
				break
			buf += ' -> 0x%08x' % ptr
	return buf

def print_ptrs_reg(regs, prefix):
	for reg in regs:
		try:
			reg_value = cpu.get(reg)
			gdb_helper.log( colorama.Fore.GREEN + "\t%s %s = %s" % ( prefix, reg, deref(reg_value) ) + colorama.Fore.RESET )
		except:
			gdb_helper.log( colorama.Fore.GREEN + "\t%s %s" % (prefix, reg) + colorama.Fore.RESET )

def print_ptrs_mem(addrs, prefix):
	for addr in addrs:
		gdb_helper.log( colorama.Fore.GREEN + "\t%s %s" % ( prefix, deref(addr), ) + colorama.Fore.RESET )

def check_violations(used_memory):
	allowed = set()
	denied = set()
	for pointer in used_memory:
		if gdb_helper.ptr(pointer) == None:
			denied.add(pointer)
		else:
			allowed.add(pointer)
	return (allowed,denied)

def taint_execute(used_registers, used_memory):
	global tainted_regs, tainted_mems

	used_regs_r, used_regs_w = used_registers
	used_mems_r, used_mems_w = used_memory
	is_spread = False
	is_use = False

	for used_reg in used_regs_r:
		used_reg = get_full_register(used_reg)
		if used_reg and used_reg in tainted_regs:
			is_spread = True
			gdb_helper.log( colorama.Fore.GREEN + "\t[+] use tainted register: %s" % (used_reg,) + colorama.Fore.RESET )

	for used_memory_cell in used_mems_r:
		if used_memory_cell in tainted_mems:
			is_spread = True
			gdb_helper.log( colorama.Fore.GREEN + "\t[+] use tainted memory: 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET )

	if is_spread:
		for used_reg in used_regs_w:
			used_reg = get_full_register(used_reg)
			if used_reg:
				gdb_helper.log( colorama.Fore.GREEN + "\t[+] taint register %s" % (used_reg,) + colorama.Fore.RESET )
				tainted_regs.add(used_reg)
		for used_memory_cell in used_mems_w:
			gdb_helper.log(colorama.Fore.GREEN + "\t[+] taint memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET )
			tainted_mems.add(used_memory_cell)
	else:
		for used_reg in used_regs_w:
			used_reg = get_full_register(used_reg)
			if used_reg:
				tainted_regs.remove(used_reg)
		for used_memory_cell in used_mems_w:
			gdb_helper.log(colorama.Fore.RED + "\t[-] free memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET )
			tainted_mems.remove(used_memory_cell)

	return is_spread or is_use

try:
	tainted_regs
	tainted_mems
except:
	tainted_regs = set()
	tainted_mems = set( range(0x82f0008,0x82f0177) )

def step():
	cpu.update_registers()
	opcode = gdb_helper.get_opcode(cpu.eip)
	instruction = disas(opcode)
	gdb_helper.log( colorama.Fore.LIGHTCYAN_EX + "[*][%d] 0x%08x: %s" % (gdb_helper.ins_count, cpu.eip, instruction) + colorama.Fore.RESET )
	used_registers = get_used_registers(opcode)
	used_memory = get_used_memory(opcode,cpu)

	print_ptrs_reg( used_registers[0], 'regs read:' )
	print_ptrs_reg( used_registers[1], 'regs write:' )
	print_ptrs_mem( used_memory[0], 'mems read:' )
	print_ptrs_mem( used_memory[1], 'mems write:' )

	cpu.show_registers()
	cpu.show_registers('mmx')
	cpu.show_registers('sse')
	gdb_helper.step()

def taint_instruction():
	cpu.update_registers()
	opcode = gdb_helper.get_opcode(cpu.eip)
	instruction = disas(opcode)
	
	if not gdb_helper.ins_count % 1000:
		gdb_helper.log( colorama.Fore.LIGHTCYAN_EX + "[*][%d] 0x%08x: %s" % (gdb_helper.ins_count, cpu.eip, instruction) + colorama.Fore.RESET )
	
	if instruction.split()[0] in ('call','ret') or instruction.startswith('j'):
		#gdb_helper.log(colorama.Fore.YELLOW + "\t[i] ignore" + colorama.Fore.RESET)
		return
	if instruction.split()[0] == 'sysenter':
		gdb_helper.log(colorama.Fore.GREEN + "[*][%d] sysenter (EAX=0x%x)" % (gdb_helper.ins_count, cpu.eax) + colorama.Fore.RESET)

	used_registers = get_used_registers(opcode)
	used_memory = get_used_memory(opcode,cpu)

	try:
		(allowed,denied) = check_violations(used_memory)
		for denied_ptr in denied:
			gdb_helper.log(colorama.Fore.RED + "\t[!] ACCESS VIOLATION: 0x%08x" % (denied_ptr,) + colorama.Fore.RESET)
			raise gdb_helper.StopExecution()
		if taint_execute(used_registers, used_memory):
			gdb_helper.log("\t\t[debug] current taint regs: %s" % str(tainted_regs))
			gdb_helper.log("\t\t[debug] current taint mems: %s" % str(tainted_mems))
			raise gdb_helper.StopExecution()
			#pass
	except gdb_helper.StopExecution as e:
		raise e
	except Exception as e:
		print(str(e))
	_free_regions()

	'''
	if instruction.find('rep') != -1 and not cpu.eip in [0x00668537, 0x75716a72]:
		raise gdb_helper.StopExecution()
	'''

def print_tainted_mem():
	gdb_helper.log( "\ttainted regs: %s" % str(tainted_regs) )
	gdb_helper.log( "\ttainted mems: %s" % str(tainted_mems) )

import traceback

def do_taint( process_marks ):
	while True:
		try:
			gdb_helper.in_kernel()
			gdb_helper.in_process( taint_instruction, process_marks )
		except KeyboardInterrupt:
			break
		except gdb_helper.StopExecution:
			break
		except Exception as e:
			a,b,c = sys.exc_info()
			gdb_helper.log( traceback.extract_tb(c) )
			gdb_helper.log( str(e) )

def print_registers(group=''):
	cpu.show_registers(group)

if __name__ == '__main__':
	gdb_helper.init()
	cpu.update_registers()

	while True:
		gdb.execute("set logging off")
		cmd = input( colorama.Fore.LIGHTCYAN_EX + "[taint] " + colorama.Fore.RESET )
		gdb.execute("set logging on")
		if cmd == 'taint':
			do_taint( {0x140b000: 0xd744abea} )
		elif cmd == 'step':
			step()
		elif cmd == 'cpu':
			print_registers()
		elif cmd == 'mmx':
			print_registers('mmx')
		elif cmd == 'sse':
			print_registers('sse')
		elif cmd == 'tainted':
			print_tainted_mem()
		elif cmd == 'exit':
			break
		else:
			gdb_helper.execute(cmd)
	
	gdb_helper.finit()