import sys
sys.path.append(".")
import gdb_helper

gdb_helper.gdb = gdb

def stop():
	raise gdb_helper.StopExecution()

if __name__ == '__main__':
	gdb_helper.init()
	while True:
		try:
			gdb_helper.in_kernel()
			gdb_helper.in_process( stop, {} )
		except KeyboardInterrupt:
			break
		except gdb_helper.StopExecution:
			break
		except Exception as e:
			gdb_helper.log( str(e) )
	
	gdb_helper.finit()