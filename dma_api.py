import struct
from dma_protocol import *

class DMAApi:
    def __init__(self, core):
        self.core = core
        self.cached_pid = 0
        self.cached_dtb = 0 # 这是 User CR3
        self.cached_kdtb = 0 #这是Kernel CR3

    def get_cr3(self, pid):
        """获取 CR3 和 模块基址"""
        payload = pack_cr3_req(pid)
        # [修改] 现在接收 24 字节
        data = self.core.request_bytes(payload, 24) 
        
        if data and len(data) >= 24:
            # 解析 3 个 Q (unsigned long long)
            user_cr3, kernel_cr3, base_addr = struct.unpack("<QQQ", data[:24])
            
            self.cached_pid = pid
            self.cached_dtb = user_cr3
            self.cached_kdtb = kernel_cr3
            
            # [新增] 返回基址
            return user_cr3, kernel_cr3, base_addr
            
        return None, None, None

    def read_mem(self, addr, size):
        """直接使用缓存的 CR3 读取内存"""
        if self.cached_dtb == 0:
            return None
        payload = pack_read_req(self.cached_dtb, addr, size)
        return self.core.request_bytes(payload, size)

    def scan(self, module, section, pattern):
        """发送扫描请求"""
        payload = pack_scan_req(module, section, pattern)
        # 扫描可能耗时较长，给 10秒 超时
        data = self.core.request_bytes(payload, 8, timeout=10.0)
        if data and len(data) >= 8:
            return struct.unpack("<Q", data)[0]
        return 0