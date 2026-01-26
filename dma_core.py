import socket
import threading
import time
import struct
from dma_protocol import *

class DMACore:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", BIND_PORT))
        # 增大内核缓冲区，防止大数据流传输时丢包
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        
        self.is_running = True
        self.driver_online = False
        self.seq = 0
        
        # 接收同步
        self.recv_event = threading.Event()
        self.buffer = bytearray()
        self.expected_size = 0
        self.lock = threading.Lock() # 保证请求串行

        threading.Thread(target=self._receiver_loop, daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def _receiver_loop(self):
        while self.is_running:
            try:
                # 65536 足够接收 UDP 最大包
                data, addr = self.sock.recvfrom(65536)
                
                # 过滤心跳包
                if data.startswith(b"[ACK]") or data.startswith(b"Alive"):
                    self.driver_online = True
                    continue

                # 业务数据处理
                if self.expected_size > 0:
                    self.buffer.extend(data)
                    # 只有接收到足够的字节数才唤醒主线程
                    if len(self.buffer) >= self.expected_size:
                        self.recv_event.set()
                else:
                    try:
                        msg = data.decode('utf-8', errors='ignore').strip()
                        if msg and len(msg) < 200: print(f"\r[LOG] {msg}\n>> ", end="")
                    except: pass
            except: pass

    def _heartbeat_loop(self):
        while self.is_running:
            try:
                payload = b'HELO' + struct.pack('<I', self.seq) + b'\x01'
                self.sock.sendto(payload, (DRIVER_IP, DRIVER_PORT))
                self.seq += 1
                time.sleep(1.0)
            except: pass

    def request_bytes(self, payload, size, timeout=3.0):
        """通用请求接口"""
        with self.lock: # 确保一次只有一个请求在进行
            self.recv_event.clear()
            self.buffer = bytearray()
            self.expected_size = size
            
            self.sock.sendto(payload, (DRIVER_IP, DRIVER_PORT))
            
            # 针对大内存读取，适当放宽超时时间
            dynamic_timeout = timeout + (size / 1024 / 100.0) 
            
            if self.recv_event.wait(timeout=dynamic_timeout):
                return bytes(self.buffer[:size])
            return None
