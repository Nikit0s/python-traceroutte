import socket
import argparse
import re
import threading
global result

NTPMessage = bytes('\x1b' + 47 * '\0', "utf-8")
result = {}

def toIP(host):
	regex = re.search(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", host)
	if not regex == None and regex.group(0) == host:
		return host
	else:
		return socket.gethostbyname(host)

class TCP(threading.Thread):
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.settimeout(0.5)
		threading.Thread.__init__(self)
	def run(self):
		res = []
		request = b"ehlo\r\n"
		try:
			self.sock.connect((self.host, self.port))
			if self.sock:
				res.append("TCP OPEN")
				for proto in ("SMTP", "HTTP", "POP"):
					if proto == "SMTP":
						request = b"HELO x\r\n"
					if proto == "HTTP":
						request = b"GET"
					if proto ==  "POP":
						request = b"USER smb\r\n"
					try:
						self.sock.sendall(request)
						data = self.sock.recv(1024)
						if proto == "SMTP" and (data[:3] == b'220' or data[:3] == b'250'):
							res.append("SMTP")
						if proto == "HTTP" and (data == b''):
							res.append("HTTP")
						if proto == "POP" and (data[:3] == b'+OK' or data[:4] == b'-ERR'):
							res.append("POP")
					except Exception as e:
						pass
		# except (ConnectionRefusedError, socket.timeout):
		except Exception:
			# print("Порт {0}:TCP не доступен".format(port))
			self.sock.close()
		self.sock.close()
		if self.port in result:
			result[self.port] += res
		else:
			if not len(res) == 0:
				if len(res) == 1:
					result[self.port] = res[0]
				else:
					result[self.port] = res[1:]

class UDP(threading.Thread):
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(0.5)
		threading.Thread.__init__(self)
	def run(self):
		res = []
		try:
			self.sock.sendto(NTPMessage, (self.host, self.port))
			data, _ = self.sock.recvfrom(1024)
			if not (data == None):
				res.append("NTP")
		except Exception:
			pass
		if self.port in result:
			result[self.port] += res
		else:
			if not len(res) == 0:
				result[self.port] = res

# def checkUDP(host, port):
# 	result = []
# 	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# 	sock.settimeout(0.5)
# 	try:
# 		sock.sendto(NTPMessage, (host, port))
# 		data, _ = sock.recvfrom(1024)
# 		if not (data == None):
# 			res.append("NTP")
# 	except socket.timeout:
# 		pass
# 	return res

def main(args):
	threads = []
	ports = [i for i in range(int(args.left), int(args.right) + 1)]
	print("PortScanner started for {0}".format(args.host))
	args.host = toIP(args.host)
	for port in ports:
		tcp = TCP(args.host, port)
		udp = UDP(args.host, port)
		threads.append(tcp)
		threads[-1].start()
		threads.append(udp)
		threads[-1].start()
		if len(threads) > 150:
			for thread in threads:
				if thread.isAlive():
					thread.join()
				threads.remove(thread)
	for thread in threads:
		if thread.isAlive():
			thread.join()


	print(result)
	print("Finished")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Arguments for portscan")
	parser.add_argument("host", help="Input hostname")
	parser.add_argument("left", help="Left limit of range")
	parser.add_argument("right", help="Right limit of range")
	args = parser.parse_args()
	main(args)