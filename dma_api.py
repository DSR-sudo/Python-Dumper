import struct
from dma_protocol import *


#配合驱动 Lookaside List 大小 (4352 bytes)
# 我们预留头部空间，安全设置为 4096
DRIVER_MAX_CHUNK = 4096

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


    def read_chunk(self, addr, size):
        # 内部辅助函数
        payload = pack_read_req(self.cached_dtb, addr, size)
        return self.core.request_bytes(payload, size)

    def read_mem(self, addr, size):
        """
        [双端优化版] 自动分片读取
        """
        if self.cached_dtb == 0: return None
        
        # 如果请求小于等于块大小，直接发一个包
        if size <= DRIVER_MAX_CHUNK:
            payload = pack_read_req(self.cached_dtb, addr, size)
            return self.core.request_bytes(payload, size)
        
        # 如果请求很大 (例如 100MB)，自动切片
        # 这就是“客户端优化”的核心：不给驱动造成压力
        result = bytearray()
        offset = 0
        while offset < size:
            chunk_size = min(DRIVER_MAX_CHUNK, size - offset)
            
            # 这里的 request_bytes 内部是同步的 (Stop-and-Wait)
            # 发送 -> 等待 -> 接收 -> 下一次循环
            # 天然形成了流量控制，绝不会耗光资源
            chunk_data = self.read_chunk(addr + offset, chunk_size)
            
            if not chunk_data:
                # 容错：如果中间断了一块，可以重试或填 0
                # 这里简单填 0 保持对齐
                result.extend(b'\x00' * chunk_size)
            else:
                result.extend(chunk_data)
                
            offset += chunk_size
            
        return bytes(result)

    def enum_user_modules(self, pid):
        """发送枚举模块请求"""
        payload = pack_enum_modules_req(pid)
        # 注意: 这是一个流式指令，C++ 会发送多个 DATA 包回来
        # 此处仅负责发送指令，接收逻辑需由 core.py 的 _receiver_loop 处理
        self.core.sock.sendto(payload, (DRIVER_IP, DRIVER_PORT))