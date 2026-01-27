import struct

# ==========================================
# 协议定义 (L0) - 修复字节对齐
# ==========================================

DRIVER_IP = "192.168.2.231"
DRIVER_PORT = 12003
BIND_PORT = 12003

MAGIC_KEY = 0xDEADBEEF
CMD_READ_MEM = 1
CMD_GET_CR3 = 3
CMD_SCAN_PATTERN = 4

PACKET_TYPE_LOG  = 0x01
PACKET_TYPE_DATA = 0x02

# --- 核心包格式 (Standard Request) ---
# C++ 结构: Magic(4) + Cmd(1) + [Padding(3)] + Value(8) + Addr(8) + Size(8)
# Value 复用: GetCr3时为PID, ReadMem时为CR3
# 修复: 增加 '3x' (3个填充字节) 以匹配 C++ x64 对齐
PACKET_FMT = "<IBQQI" 

# --- 扫描包格式 (Scan Request) ---
# C++ 结构: Magic(4) + Cmd(1) + Module(64) + ...
# Char 数组通常只有 1 字节对齐，紧跟在 Cmd 后面，无需 Padding
PACKET_SCAN_FMT = "<IB64s8s64s64sI"

def parse_packet_header(data: bytes):
    """
    返回 (packet_type, payload)
    如果数据为空或长度不足，抛出异常或返回 None
    """
    if not data or len(data) < 1:
        return None, None
    
    pkt_type = data[0]
    payload = data[1:]
    return pkt_type, payload


def pack_read_req(cr3, addr, size):
    """构建读取请求 (Value=CR3)"""
    return struct.pack(PACKET_FMT, MAGIC_KEY, CMD_READ_MEM, cr3, addr, size)

def pack_cr3_req(pid):
    """构建CR3请求 (Value=PID)"""
    return struct.pack(PACKET_FMT, MAGIC_KEY, CMD_GET_CR3, pid, 0, 0)

def pack_scan_req(module, section, pattern_str):
    """构建特征码扫描请求"""
    parts = pattern_str.strip().split()
    sig_bytes = []
    mask_chars = []
    
    for p in parts:
        if p == '?' or p == '??':
            sig_bytes.append(0)
            mask_chars.append('?')
        else:
            sig_bytes.append(int(p, 16))
            mask_chars.append('x')
            
    sig_len = len(sig_bytes)
    
    return struct.pack(PACKET_SCAN_FMT, MAGIC_KEY, CMD_SCAN_PATTERN,
                       module.encode('utf-8').ljust(64, b'\x00'), 
                       section.encode('utf-8').ljust(8, b'\x00'),
                       "".join(mask_chars).encode('utf-8').ljust(64, b'\x00'),
                       bytes(sig_bytes).ljust(64, b'\x00'), 
                       sig_len)
