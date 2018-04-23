from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct
import string
import colorama
import sys
import traceback
import gdb

PAGE_SIZE = 0x1000


class StopExecution(BaseException):
	pass

class DBG:
	ins_count = 0
	@staticmethod
	def step():
		gdb.execute("si")
		DBG.ins_count += 1

	@staticmethod
	def get_opcode(rip):
		hex_string = ''
		opcode_size = int( gdb.execute("x/2i $rip", False, True).split('\n')[1].split(':')[0].split()[0].strip(), 16 ) - rip
		for line in gdb.execute("x/%dbx $rip" % opcode_size, False, True).split('\n'):
			if not line.strip():
				break
			for byte in line.split(':')[1].strip().split('\t'):
				hex_string += byte[2:]
		return bytes.fromhex(hex_string)

	@staticmethod
	def get_registers():
		registers = {}
		registers_name = (
			'rax','eax','ax','ah','al',
			'rcx','ecx','cx','ch','cl',
			'rdx','edx','dx','dh','dl',
			'rbx','ebx','bx','bh','bl',
			'rsp','esp','sp',
			'rbp','ebp','bp',
			'rsi','esi','si',
			'rdi','edi','di',
			'rip','eip',
			'eflags',
			'st0','st1','st2','st3','st4','st5','st6','st7',
			'xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7',
			'mm0','mm1','mm2','mm3','mm4','mm5','mm6','mm7'
			)
		for line in gdb.execute("maint print cooked-registers", False, True).split('\n')[1:]:
			try:
				register = line.split().pop(0)
				value = line.split().pop()
				if register in registers_name:
					registers.update( { register: int(value,16) } )
			except Exception as e:
				pass
		return registers

	@staticmethod
	def ptr(addr):
		try:
			return int( gdb.execute("x/1wx %d" % addr, False, True).split('\n')[0].split(':')[1].strip(), 16 )
		except:
			return None


class CPU:
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True

	@staticmethod
	def get(register):
		return CPU.__dict__[register]

	@staticmethod
	def update_registers():
		for register,value in DBG.get_registers().items():
			setattr(CPU, register, value)

	@staticmethod
	def show_registers(group=''):
		if group == '':
			for register in ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','rip','eflags']:
				print( colorama.Fore.GREEN + "%s %s" % ( register.upper(), deref( CPU.__dict__[register] ) ) + colorama.Fore.RESET )
		elif group == 'mmx':
			for register in ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7']:
				print( colorama.Fore.GREEN + "%s %s" % ( register.upper(), deref( CPU.__dict__[register] ) ) + colorama.Fore.RESET )
		elif group == 'sse':
			for register in ['st0','st1','st2','st3','st4','st5','st6','st7']:
				print( colorama.Fore.GREEN + "%s %s" % ( register.upper(), deref( CPU.__dict__[register] ) ) + colorama.Fore.RESET )

	@staticmethod
	def disas(opcode):
		mnem = ""
		for inst in CPU.md.disasm(opcode, 0):
			mnem = "%s %s" % (inst.mnemonic, inst.op_str)
			break
		return mnem

	@staticmethod
	def get_used_registers(opcode):
		read = set()
		write = set()
		for inst in CPU.md.disasm(opcode, 0):
			(regs_read, regs_write) = inst.regs_access()
			break
		for reg_read in regs_read:
			read.add( inst.reg_name(reg_read) )
		for reg_write in regs_write:
			write.add( inst.reg_name(reg_write) )
		return (read, write)

	@staticmethod
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

class EMU:
	def _mem_access(uc, access, address, size, value, user_data):
		if access in (UC_MEM_WRITE,):
			for i in range(size):
				EMU.write.add( address + i )
		else:
			for i in range(size):
				EMU.read.add( address + i )

	def _mem_add_page(uc, access, address, size, value, user_data):
		try:
			EMU._alloc_region(address)
		except:
			print( colorama.Back.RED + "[!] error allocating memory at 0x%08x" % (address,) + colorama.Back.RESET )

	def _alloc_region(address):
		print( colorama.Fore.BLUE + "[i] allocate for 0x%08x" % address + colorama.Fore.RESET )
		address &= 0xfffffffffffff000
		EMU.mu.mem_map( address, PAGE_SIZE )
		EMU.allocated_regions.add( address )

	mu = Uc(UC_ARCH_X86, UC_MODE_64)
	mu.hook_add(UC_HOOK_MEM_READ, _mem_access)
	mu.hook_add(UC_HOOK_MEM_WRITE, _mem_access)
	mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID | UC_HOOK_MEM_WRITE_INVALID, _mem_add_page)

	read = set()
	write = set()
	allocated_regions = set()

	@staticmethod
	def free_regions():
		for region in EMU.allocated_regions:
			try:
				EMU.mu.mem_unmap(region, PAGE_SIZE)
				#print( colorama.Fore.BLUE + "[i] free(0x%08x)" % (region,) + colorama.Fore.RESET )
			except Exception as e:
				print(str(e))
		EMU.allocated_regions = set()

	@staticmethod
	def get_used_memory(opcode, cpu):
		EMU.read = set()
		EMU.write = set()
		
		try:
			if not cpu.rip & 0xfffffffffffff000 in EMU.allocated_regions:
				EMU._alloc_region(cpu.rip)
			EMU.mu.mem_write(cpu.rip, opcode)
		except Exception as e:
			print( str(e))

		max_attempts = 5
		while True:
			try:
				max_attempts -= 1
				if max_attempts <= 0:
					#print(colorama.Back.RED + "[!] error emulation\n"  + colorama.Back.RESET)
					break

				EMU.mu.reg_write(UC_X86_REG_RAX, cpu.rax)
				EMU.mu.reg_write(UC_X86_REG_RCX, cpu.rcx)
				EMU.mu.reg_write(UC_X86_REG_RDX, cpu.rdx)
				EMU.mu.reg_write(UC_X86_REG_RBX, cpu.rbx)
				EMU.mu.reg_write(UC_X86_REG_RSP, cpu.rsp)
				EMU.mu.reg_write(UC_X86_REG_RBP, cpu.rbp)
				EMU.mu.reg_write(UC_X86_REG_RSI, cpu.rsi)
				EMU.mu.reg_write(UC_X86_REG_RDI, cpu.rdi)
				EMU.mu.emu_start(cpu.rip, 0, 0, 1)
				EMU.mu.emu_stop()
				break
			except KeyboardInterrupt:
				EMU.mu.emu_stop()
				break
			except Exception as e:
				EMU.mu.emu_stop()
				EMU.read = set()
				EMU.write = set()
				print(str(e))
		return (EMU.read, EMU.write)

	@staticmethod
	def get_registers():
		for reg,val in {
			'RAX': EMU.mu.reg_read(UC_X86_REG_RAX),
			'RCX': EMU.mu.reg_read(UC_X86_REG_RCX),
			'RDX': EMU.mu.reg_read(UC_X86_REG_RDX),
			'RBX': EMU.mu.reg_read(UC_X86_REG_RBX),
			'RSP': EMU.mu.reg_read(UC_X86_REG_RSP),
			'RBP': EMU.mu.reg_read(UC_X86_REG_RBP),
			'RSI': EMU.mu.reg_read(UC_X86_REG_RSI),
			'RDI': EMU.mu.reg_read(UC_X86_REG_RDI),
		}.items():
			print( "%s: 0x%08x" % (reg,val) )


def deref(ptr):
	def _ascii(qword):
		buf = ''
		_bytes = struct.pack("<Q", qword % 0x10000000000000000)
		for byte in _bytes:
			if chr(byte) in string.printable[:-5]:
				buf += chr(byte)
			else:
				buf += "."
		return buf

	buf = '0x%08x' % ptr
	for _ in range(5):
		buf += colorama.Fore.YELLOW + ' "%s"' % ( _ascii(ptr), ) + colorama.Fore.RESET
		ptr = DBG.ptr(ptr)
		if ptr == None:
			break
		buf += ' -> '
	return buf

def print_registers(group=''):
	CPU.show_registers(group)

def print_ptrs_reg(regs, prefix):
	for reg in regs:
		try:
			reg_value = CPU.get(reg)
			print( colorama.Fore.GREEN + "%s %s = %s" % ( prefix, reg, deref(reg_value) ) + colorama.Fore.RESET )
		except:
			print( colorama.Fore.GREEN + "%s %s" % (prefix, reg) + colorama.Fore.RESET )

def print_ptrs_mem(addrs, prefix):
	for addr in addrs:
		print( colorama.Fore.GREEN + "%s %s" % ( prefix, deref(addr), ) + colorama.Fore.RESET )





def is_taint(used_registers, used_memory):
	global tainted_regs, tainted_mems

	used_regs_r, used_regs_w = used_registers
	used_mems_r, used_mems_w = used_memory
	is_spread = False

	for used_reg in used_regs_r:
		used_reg = CPU.get_full_register(used_reg)
		if used_reg and used_reg in tainted_regs:
			is_spread = True
			print( colorama.Fore.GREEN + "[+] use tainted register: %s" % (used_reg,) + colorama.Fore.RESET )

	for used_memory_cell in used_mems_r:
		if used_memory_cell in tainted_mems:
			is_spread = True
			print( colorama.Fore.GREEN + "[+] use tainted memory: 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET )

	if is_spread:
		for used_reg in used_regs_w:
			used_reg = CPU.get_full_register(used_reg)
			if used_reg:
				print( colorama.Fore.GREEN + "[+] taint register %s" % (used_reg,) + colorama.Fore.RESET )
				tainted_regs.add(used_reg)
		for used_memory_cell in used_mems_w:
			print(colorama.Fore.GREEN + "[+] taint memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET )
			tainted_mems.add(used_memory_cell)
	else:
		for used_reg in used_regs_w:
			used_reg = CPU.get_full_register(used_reg)
			if used_reg:
				tainted_regs.remove(used_reg)
		for used_memory_cell in used_mems_w:
			#print(colorama.Fore.RED + "[-] free memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET )
			tainted_mems.remove(used_memory_cell)

	return is_spread


def step():
	CPU.update_registers()
	opcode = DBG.get_opcode(CPU.rip)
	instruction = CPU.disas(opcode)
	print( colorama.Fore.LIGHTCYAN_EX + "[%d] 0x%08x: %s" % (DBG.ins_count, CPU.rip, instruction) + colorama.Fore.RESET )
	used_registers = CPU.get_used_registers(opcode)
	used_memory = EMU.get_used_memory(opcode,CPU)

	print_ptrs_reg( used_registers[0], 'regs read:' )
	print_ptrs_reg( used_registers[1], 'regs write:' )
	print_ptrs_mem( used_memory[0], 'mems read:' )
	print_ptrs_mem( used_memory[1], 'mems write:' )

	#CPU.show_registers()
	#CPU.show_registers('mmx')
	#CPU.show_registers('sse')
	DBG.step()

def taint_instruction(is_stop=True):
	CPU.update_registers()
	opcode = DBG.get_opcode(CPU.rip)
	instruction = CPU.disas(opcode)
	
	if DBG.ins_count and not DBG.ins_count % 1000:
		print( colorama.Fore.LIGHTBLACK_EX + "[*][%d] 0x%08x: %s" % (DBG.ins_count, CPU.rip, instruction) + colorama.Fore.RESET )
	
	if instruction.split()[0] in ('call','ret') or instruction.startswith('j'):
		#print(colorama.Fore.YELLOW + "\t[i] ignore" + colorama.Fore.RESET)
		pass
	if instruction.split()[0] == 'sysenter':
		print(colorama.Fore.GREEN + "[*][%d] sysenter (EAX=0x%x)" % (DBG.ins_count, CPU.eax) + colorama.Fore.RESET)

	used_registers = CPU.get_used_registers(opcode)
	used_memory = EMU.get_used_memory(opcode,CPU)

	try:
		if is_taint(used_registers, used_memory):
			print( colorama.Fore.LIGHTCYAN_EX + "[*][%d] 0x%08x: %s" % (DBG.ins_count, CPU.rip, instruction) + colorama.Fore.RESET )
			if is_stop:
				DBG.step()
				raise StopExecution()
	except StopExecution as e:
		raise e
	except Exception as e:
		print(str(e))
	#EMU.free_regions()
	DBG.step()
	'''
	if instruction.find('rep') != -1 and not CPU.rip in [0x00668537, 0x75716a72]:
		raise StopExecution()
	'''

def print_tainted():
	print( "tainted regs: %s" % str(tainted_regs) )
	print( "tainted mems: %s" % str(tainted_mems) )


def taint_execute(stop=True):
	while True:
		try:
			taint_instruction(is_stop=stop)
		except KeyboardInterrupt:
			break
		except StopExecution:
			break
		except Exception as e:
			a,b,c = sys.exc_info()
			print( traceback.extract_tb(c) )
			print( str(e) )


tainted_regs = set()
tainted_mems = set()

CPU.update_registers()

print_registers()
print_registers('mmx')
print_registers('sse')

print( '"tainted_regs", "tainted_mems"' )
print( "print_tainted()" )
print( "step()" )
print( "taint_execute()" )
