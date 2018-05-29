
WINDOWS_KERNEL_BOUND = 0x80000000
WINDOWS_SYSENTER = None
WINDOWS_SYSEXIT = None #0x804de904

ins_count = 0
ctx_switches = 0

class StopExecution(BaseException):
	pass

def init():
	gdb.execute("set height 0")
	gdb.execute("set pagination off")
	gdb.execute("set logging redirect on")
	gdb.execute("set logging file /dev/null")
	gdb.execute("set logging on")

def finit():
	gdb.execute("set logging off")
	gdb.execute("d br")

def log(buff):
	gdb.execute("set logging off")
	print( buff )
	gdb.execute("set logging on")

def execute(cmd):
	gdb.execute("set logging off")
	gdb.execute(cmd)
	gdb.execute("set logging on")



def is_our_process(process_marks):
	for addr, dword in process_marks.items():
		try:
			if gdb.execute("p *((int *) 0x%08x) == 0x%08x" % (addr, dword), False, True).find(' = 1') == -1:
				return False
		except Exception as e:
			return False
	return True

def step():
	global ins_count
	gdb.execute("si")
	ins_count += 1

def step_out():
	global ins_count
	gdb.execute("ni")
	ins_count += 1
	
def cont():
	gdb.execute("c")

def bpx(eip):
	gdb.execute("b *0x%08x" % eip)

'''
def bpx_del(eip):
	for line in gdb.execute("i br", False, True).split('\n')[1:]:
		if line.strip():
			bpx_id = int( line.split()[0] )
			if line.find("%08x" % eip) != -1:
				gdb.execute("d br %d" % bpx_id)
				with open('temp.txt','a') as o:
					o.write("d br %d\n" % bpx_id)
'''

def ptr(addr):
	try:
		return int( gdb.execute("x/1wx %d" % addr, False, True).split('\n')[0].split(':')[1].strip(), 16 )
	except:
		return None

def disas(eip):
	return gdb.execute("x/1i %d" % eip, False, True).split('\n')[0].split(':')[1].strip()

def get_register(register):
	return int( gdb.parse_and_eval("$%s" % register) )

def get_registers():
	registers = {}
	registers_name = (
		'eax','ax','ah','al',
		'ecx','cx','ch','cl',
		'edx','dx','dh','dl',
		'ebx','bx','bh','bl',
		'esp','sp',
		'ebp','bp',
		'esi','si',
		'edi','di',
		'eip',
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
		except:
			pass
	return registers

def get_opcode(eip):
	hex_string = ''
	opcode_size = int( gdb.execute("x/2i $eip", False, True).split('\n')[1].split(':')[0].strip(), 16 ) - eip
	for line in gdb.execute("x/%dbx $eip" % opcode_size, False, True).split('\n'):
		if not line.strip():
			break
		for byte in line.split(':')[1].strip().split('\t'):
			hex_string += byte[2:]
	return bytes.fromhex(hex_string)

def get_eip():
	return get_register('eip')

def is_kernel(eip):
	return eip >= WINDOWS_KERNEL_BOUND

kernel_ins_count = 0
def in_kernel():
	global WINDOWS_SYSEXIT, kernel_ins_count, ctx_switches
	if not is_kernel( get_eip() ):
		return
	if WINDOWS_SYSEXIT:
		if gdb.execute("i br", False, True).find("%x" % WINDOWS_SYSEXIT) == -1:
			bpx(WINDOWS_SYSEXIT)
		cont()
		step()
		ctx_switches += 1
#		log("[i] leave kernel")
	else:
		while True:
			eip = get_eip()
			if not WINDOWS_SYSEXIT and disas(eip).find("sysexit") != -1:
				WINDOWS_SYSEXIT = eip
				log("[i] sysexit: 0x%08x" % eip)
			if not is_kernel(eip):
#				log("[i] in user R3")
				break
			step_out()
			kernel_ins_count += 1
			if not kernel_ins_count % 1000:
				log( "[0x%08x] (%d)" % ( eip, kernel_ins_count ) )
		ctx_switches += 1
	if not ctx_switches % 1000:
		log( "[i] contexts switches: %d" % ctx_switches )

user_ins_count = 0
def in_process( callback, process_marks={} ):
	global WINDOWS_SYSENTER, user_ins_count, ctx_switches
	if is_kernel( get_eip() ):
		return
	if not is_our_process(process_marks):
#		log("[-] neighbor process")
		'''
		if WINDOWS_SYSENTER and disas(WINDOWS_SYSENTER).find('sysenter') == -1:
			bpx_del(WINDOWS_SYSENTER)
			breakpoint_sysenter = 0
			WINDOWS_SYSENTER = 0
		'''
		if WINDOWS_SYSENTER:
			if gdb.execute("i br", False, True).find("%x" % WINDOWS_SYSENTER) == -1:
				bpx(WINDOWS_SYSENTER)
			cont()
			step()
			ctx_switches += 1
#			log("[i] entering in kernel")
		else:
			while True:
				eip = get_eip()
				
				user_ins_count += 1
				if not user_ins_count % 1000:
					log( "[0x%08x]: (%d)" % ( eip, user_ins_count ) )

				if not WINDOWS_SYSENTER and disas(eip).find("sysenter") != -1:
					WINDOWS_SYSENTER = eip
					log("[i] sysenter: 0x%08x" % eip)
					break
				if is_kernel(eip):
					log("[i] neighbor process R3 -> kernel R0")
					break
				step()
			ctx_switches += 1
	else:
		log("[+] return to process")
		while not is_kernel( get_eip() ):
			try:
				callback()
			except StopExecution as e:
				raise e
			except Exception as e:
				log( "[!] %s" % str(e) )
			step()
		ctx_switches += 1
#		log("[*] in kernel R0")




if __name__ == '__main__':
	init()

	for reg,val in get_registers().items():
		log( "%s: 0x%x" % (reg,val) )

	finit()