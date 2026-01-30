import socket
import threading
import time
import struct
from dma_protocol import *

class DMACore:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 允许端口复用（可选，开发调试时有用）
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", BIND_PORT))
        
        # 增大内核缓冲区，防止大数据流传输时丢包
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        
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
        """
        [修复版] 核心接收循环
        不再盲目接收数据，而是根据首字节 Header 分流日志与数据
        """
        print(f"[*] UDP Receiver started on port {BIND_PORT}")
        
        while self.is_running:
            try:
                # 65536 足够接收 UDP 最大包
                data, addr = self.sock.recvfrom(65536)
                
                if not data or len(data) < 1:
                    continue

                # [核心逻辑] 解析 1 字节头部
                pkt_type = data[0]
                payload = data[1:] # 剥离头部，剩下的才是真实内容

                # ==========================================================
                # 分支 1: 日志包 / 心跳包 (Type = 0x01)
                # ==========================================================
                if pkt_type == PACKET_TYPE_LOG:
                    try:
                        msg = payload.decode('utf-8', errors='ignore').strip()
                        
                        # 检查心跳特征 (假设 C++ 端把 "Alive" 也作为 Log 发送了)
                        if "Alive" in msg or "DRIVER_ONLINE" in msg:
                            if not self.driver_online:
                                print("[+] Driver is ONLINE.")
                            self.driver_online = True
                            continue # 心跳包不打印日志，避免刷屏
                        
                        # 普通日志打印
                        if msg:
                            # 使用 \r 避免打断用户的输入行（如果有 CLI 交互）
                            print(f"\r[LOG] {msg}\n>> ", end="")
                    except:
                        pass

                # ==========================================================
                # 分支 2: 业务数据包 (Type = 0x02)
                # ==========================================================
                elif pkt_type == PACKET_TYPE_DATA:
                    # 只有当主线程明确在“等待数据”时，才接收这个包
                    if self.expected_size > 0:
                        self.buffer.extend(payload)
                        
                        # 接收到足够的数据量后，唤醒主线程
                        if len(self.buffer) >= self.expected_size:
                            self.recv_event.set()
                    else:
                        # 如果当前没有在请求数据，却收到了 DATA 包，
                        # 说明是滞后的旧数据或错乱数据，直接丢弃，防止污染下一次请求
                        pass

                # ==========================================================
                # 兼容性/未知包
                # ==========================================================
                else:
                    # 如果你还没完全更新驱动，可能会收到无头部的旧包
                    # 这里可以选择打印 hex 以便调试
                    # print(f"[Unknown] {data.hex()}")
                    pass

            except Exception as e:
                print(f"[Loop Error] {e}")
                time.sleep(0.1)

    def _heartbeat_loop(self):
        while self.is_running:
            try:
                payload = b'HELO'.ljust(32, b'\x00')
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
