import Network
import argparse
from time import sleep
import hashlib





class Packet:
	# the number of bytes used to store packet length
	seq_num_S_length = 10
	length_S_length = 10
	ack_S_length = 5
	# length of md5 checksum in hex
	checksum_length = 32
	# ack or nak identifiers (0 is NAK, 1 is ACK)
	is_ACK = 0

	def __init__(self, seq_num, msg_S, is_ACK):
		self.seq_num = seq_num
		self.msg_S = msg_S
		self.is_ACK = is_ACK

	@classmethod
	def from_byte_S(self, byte_S):
		if Packet.corrupt(byte_S):
			return None
		# extract the fields
		seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
		is_ACK = int(byte_S[Packet.length_S_length + Packet.seq_num_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length])
		msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length + Packet.checksum_length:]
		return self(seq_num, msg_S, is_ACK)

	def get_byte_S(self):
		# convert sequence number to a byte field of seq_num_S_length bytes
		seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
		# convert ack/nak to a byte field of ack_S_length bytes
		ack_S = str(self.is_ACK).zfill(self.ack_S_length)
		# convert length to a byte field of length_S_length bytes
		length_S = str(self.length_S_length + self.seq_num_S_length + self.ack_S_length + self.checksum_length + len(self.msg_S)).zfill(
			self.length_S_length)
		# compute the checksum
		checksum = hashlib.md5((length_S + seq_num_S + ack_S + self.msg_S).encode('utf-8'))
		checksum_S = checksum.hexdigest()
		# compile into a string
		return length_S + seq_num_S + ack_S + checksum_S + self.msg_S

	@staticmethod
	def corrupt(byte_S):
		# extract the fields
		length_S = byte_S[0:Packet.length_S_length]
		seq_num_S = byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length]
		ack_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length]
		checksum_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length + Packet.checksum_length]
		msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length + Packet.checksum_length:]

		# compute the checksum locally
		checksum = hashlib.md5(str(length_S + seq_num_S + ack_S + msg_S).encode('utf-8'))
		computed_checksum_S = checksum.hexdigest()
		# and check if the same
		return checksum_S != computed_checksum_S


class RDT:
	# latest sequence number used in a packet
	seq_num = 0
	# buffer of bytes read from network
	byte_buffer = ''
	role_S = ''

	def __init__(self, role_S, server_S, port):
		self.network = Network.NetworkLayer(role_S, server_S, port)
		self.role_S = role_S

	def disconnect(self):
		self.network.disconnect()

	def rdt_1_0_send(self, msg_S):
		p = Packet(self.seq_num, msg_S)
		self.seq_num += 1
		self.network.udt_send(p.get_byte_S())

	def rdt_1_0_receive(self):
		ret_S = None
		byte_S = self.network.udt_receive()
		self.byte_buffer += byte_S
		# keep extracting packets - if reordered, could get more than one
		while True:
			# check if we have received enough bytes
			if (len(self.byte_buffer) < Packet.length_S_length):
				return ret_S  # not enough bytes to read packet length
			# extract length of packet
			length = int(self.byte_buffer[:Packet.length_S_length])
			if len(self.byte_buffer) < length:
				return ret_S  # not enough bytes to read the whole packet
			# create packet from buffer content and add to return string
			p = Packet.from_byte_S(self.byte_buffer[0:length])
			ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
			# remove the packet bytes from the buffer
			self.byte_buffer = self.byte_buffer[length:]
		# if this was the last packet, will return on the next iteration

	def rdt_2_1_send(self, msg_S, is_ACK):
		p = Packet(self.seq_num, msg_S, is_ACK)
		self.network.udt_send(p.get_byte_S())

	def rdt_2_1_receive(self):
		ret_S = None
		byte_S = self.network.udt_receive()
		self.byte_buffer += byte_S
		# keep extracting packets - if reordered, could get more than one
		while True:
			# check if we have received enough bytes
			if (len(self.byte_buffer) < Packet.length_S_length):
				return ret_S  # not enough bytes to read packet length
			# extract length of packet
			length = int(self.byte_buffer[:Packet.length_S_length])
			if len(self.byte_buffer) < length:
				return ret_S  # not enough bytes to read the whole packet
			if self.role_S == 'client':
				# create packet from buffer content
				p = Packet.from_byte_S(self.byte_buffer[0:length])
				if p is None:  # packet is corrupt
					self.byte_buffer = self.byte_buffer[length:]
					print("\nResponse packet corrupted!")
					return 0
				else:
					# packet is NAK
					if p.is_ACK == 0:
						print("\nRecognized NAK!")
						self.byte_buffer = self.byte_buffer[length:]
						return 0
					elif p.is_ACK == 1:
						print("\nRecognized ACK!\n")
						# add packet message to return string
						ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
						if self.seq_num == 0:
							self.seq_num = 1
						else:
							self.seq_num = 0
						# remove the packet bytes from the buffer
						self.byte_buffer = self.byte_buffer[length:]
						# if this was the last packet, will return on the next iteration
			else:
				# is server
				# create packet from buffer content
				p = Packet.from_byte_S(self.byte_buffer[0:length])
				if p is None:  # packet is corrupt
					self.byte_buffer = self.byte_buffer[length:]
					return 0
				else:
					if p.is_ACK == 1:
						if self.seq_num == 0:
							self.seq_num = 1
						else:
							self.seq_num = 0
					# add packet message to return string
					ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
					# remove the packet bytes from the buffer
					self.byte_buffer = self.byte_buffer[length:]
					# if this was the last packet, will return on the next iteration

	def rdt_3_0_send(self, msg_S, is_ACK):
		p = Packet(self.seq_num, msg_S, is_ACK)
		self.network.udt_send(p.get_byte_S())

	def rdt_3_0_receive(self):
		ret_S = None
		byte_S = self.network.udt_receive()
		self.byte_buffer += byte_S
		# keep extracting packets - if reordered, could get more than one
		while True:
			# check if we have received enough bytes
			if (len(self.byte_buffer) < Packet.length_S_length):
				return ret_S  # not enough bytes to read packet length
			# extract length of packet
			length = int(self.byte_buffer[:Packet.length_S_length])
			if len(self.byte_buffer) < length:
				return ret_S  # not enough bytes to read the whole packet
			if self.role_S == 'client':
				# create packet from buffer content
				p = Packet.from_byte_S(self.byte_buffer[0:length])
				if p is None:  # packet is corrupt
					self.byte_buffer = self.byte_buffer[length:]
					print("\nResponse packet corrupted!")
					return 0
				else:
					# packet is NAK
					if p.is_ACK == 0:
						print("\nRecognized NAK!")
						self.byte_buffer = self.byte_buffer[length:]
						return 0
					# packet is ACK
					elif p.is_ACK == 1:
						if p.seq_num == self.seq_num:
							# is ACK for current packet
							print("\nRecognized ACK!\n")
							# add packet message to return string
							ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
							if self.seq_num == 0:
								self.seq_num = 1
							else:
								self.seq_num = 0
							# remove the packet bytes from the buffer
							self.byte_buffer = self.byte_buffer[length:]
							# if this was the last packet, will return on the next iteration
						else:
							# is duplicate ACK for previous packet, delayed arrival
							pass

			else:
				# is server
				# create packet from buffer content
				p = Packet.from_byte_S(self.byte_buffer[0:length])
				if p is None:  # packet is corrupt
					self.byte_buffer = self.byte_buffer[length:]
					print("\nPacket corrupted, sending NAK!")
					return 0
				else:
					if p.seq_num == self.seq_num:
						# this is not a resent package
						# add packet message to return string
						ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
						# remove the packet bytes from the buffer
						self.byte_buffer = self.byte_buffer[length:]
						# if this was the last packet, will return on the next iteration
					else:
						# this is a resent package
						if self.seq_num == 0:
							self.seq_num = 1
						else:
							self.seq_num = 0
						# add packet message to return string
						ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
						# remove the packet bytes from the buffer
						self.byte_buffer = self.byte_buffer[length:]
						# if this was the last packet, will return on the next iteration

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='RDT implementation.')
	parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
	parser.add_argument('server', help='Server.')
	parser.add_argument('port', help='Port.', type=int)
	args = parser.parse_args()

	rdt = RDT(args.role, args.server, args.port)
	if args.role == 'client':
		rdt.rdt_1_0_send('MSG_FROM_CLIENT')
		sleep(2)
		print(rdt.rdt_1_0_receive())
		rdt.disconnect()
	else:
		sleep(1)
		print(rdt.rdt_1_0_receive())
		rdt.rdt_1_0_send('MSG_FROM_SERVER')
		rdt.disconnect()
