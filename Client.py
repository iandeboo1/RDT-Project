import argparse
import RDT
import time

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Quotation client talking to a Pig Latin server.')
	parser.add_argument('server', help='Server.')
	parser.add_argument('port', help='Port.', type=int)
	args = parser.parse_args()
	
	msg_L = [
		'The use of COBOL cripples the mind; its teaching should, therefore, be regarded as a criminal offense. -- Edsgar Dijkstra',
		'C makes it easy to shoot yourself in the foot; C++ makes it harder, but when you do, it blows away your whole leg. -- Bjarne Stroustrup',
		'A mathematician is a device for turning coffee into theorems. -- Paul Erdos',
		'Grove giveth and Gates taketh away. -- Bob Metcalfe on the trend of hardware speedups not being able to keep up with software demands',
		'Wise men make proverbs, but fools repeat them. -- Samuel Palmer']
	
	timeout = 2  # send the next message if no response
	time_of_last_data = time.time()
	isACKed = 0
	
	rdt = RDT.RDT('client', args.server, args.port)
	for msg_S in msg_L:
		print('Converting: ' + msg_S)
		rdt.rdt_2_1_send(msg_S, isACKed)
		
		# try to receive message before timeout
		ret_S = None
		while ret_S is None or ret_S == 0:
			ret_S = rdt.rdt_2_1_receive()
			if ret_S is None:
				if time_of_last_data + timeout < time.time():
					break
				else:
					continue
			elif ret_S == 0:
				# print("\nResending message: " + msg_S)
				rdt.rdt_2_1_send(msg_S, 0)
				# reset timeout after receiving a corrupted response
				time_of_last_data = time.time()
				ret_S = None

		# reset timeout after receiving a response
		time_of_last_data = time.time()
		isACKed = 1
		# print the result
		if ret_S:
			print('TO \n' + ret_S + '\n')
	
	rdt.disconnect()
	print('\nClient disconnected...')
