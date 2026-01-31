# dma_command.py
import time
import sys
import struct
import datetime
import ue_memory
from ue_types import FNameCache, FNameEntryArray_UE424, TUObjectArray
from ue_reflection import ReflectionDumper
from ue_generator import SDKGenerator
from ue_scanner import UEScanner

def log(msg, level="INFO"):
    """带时间戳的日志输出"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    prefix = "[*]"
    if level == "SUCCESS": prefix = "[+]"
    elif level == "ERROR": prefix = "[-]"
    elif level == "WARN":  prefix = "[!]"
    print(f"{prefix} [{timestamp}] {msg}")

def print_banner():
    """打印欢迎信息"""
    print(r"""
  __  __ ______  _  _  ____  _  _    
 / / / /|  ____|| || ||___ \| || |   
/ /_/ / | |__   | || |_ __) | || |_  
\__, |  |  __|  |__   _|__ <|__   _| 
  / /   | |____    | | ___) |  | |   
 /_/    |______|   |_||____/   |_|   
    DMA UE4.24 Reflection Dumper     
    """)

def print_detailed_help():
    """打印详细帮助菜单"""
    print("\n" + "="*60)
    print("COMMAND HELP MENU".center(60))
    print("="*60)
    cmds = [
        ("attach <PID>", "步骤1: 绑定到目标游戏进程 (获取 CR3)。"),
        ("auto_init",    "步骤2: 自动扫描特征码获取引擎基址。"),
        ("cache_gnames", "步骤3: [推荐] 缓存所有字符串到本地内存。"),
        ("dump_sdk <ClassName>", "步骤4: 生成完整的 C++ SDK 头文件。"),
        ("dump <ClassName>",     "调试: 快速查看类成员偏移。"),
        ("init <GN> <GO>",       "调试: 手动初始化基址 (Hex)。"),
        ("cr3 <PID>",            "调试: 测试 DTB 获取。"),
        ("pe_info",              "调试: 手动获取 PE 中的 text 位置。"),
        ("dump_mem <Addr> <Size> <File>", "调试: 手动 Dump 特定内存范围。"),
        ("modules <PID>",        "新功能: 通过 CR3 隔离枚举用户态模块。"),
        ("dump_mem <PID>",        "调试：直接dump内存为文件")
        ("exit",                 "退出程序。")
    ]
    for cmd, desc in cmds:
        print(f"\n[ {cmd} ]\n    {desc}")
    print("\n" + "="*60 + "\n")

class UEContext:
    """引擎全局上下文管理"""
    def __init__(self):
        self.GNames = 0
        self.GObjects = 0
        self.NameStore = None
        self.NameCache = None
        self.ObjArray = None
        self.g_base_addr = 0

class CommandHandler:
    """命令处理器类，封装所有业务逻辑"""
    def __init__(self, api):
        self.api = api
        self.ctx = UEContext()

    def handle_attach(self, args):
        if not args:
            log("Usage: attach <PID>", "ERROR")
            return
        try:
            pid = int(args[0])
            u, k, base = self.api.get_cr3(pid) #
            if u:
                ue_memory.mem = ue_memory.UEMemory(self.api, pid) #
                self.ctx.g_base_addr = base
                log(f"Attached! UserDTB: {hex(u)}, Base: {hex(base)}", "SUCCESS")
            else:
                log("Failed to get CR3. Is the game running?", "ERROR")
        except ValueError:
            log("PID must be a number.", "ERROR")

    def handle_pe_info(self):
        if self.ctx.g_base_addr == 0:
            log("Base Address is 0! Run 'attach' first.", "ERROR")
            return
        log(f"Parsing PE Headers at 0x{self.ctx.g_base_addr:X}...")
        dos = self.api.read_mem(self.ctx.g_base_addr, 0x40) #
        if not dos or dos[0:2] != b'MZ':
            log("Invalid DOS Signature", "ERROR")
            return
        e_lfanew = struct.unpack("<I", dos[0x3C:0x40])[0]
        nt = self.api.read_mem(self.ctx.g_base_addr + e_lfanew, 0x108)
        if not nt or nt[0:4] != b'PE\0\0':
            log("Invalid PE Signature", "ERROR")
            return
        num_sections = struct.unpack("<H", nt[6:8])[0]
        size_opt = struct.unpack("<H", nt[20:22])[0]
        sec_table_base = self.ctx.g_base_addr + e_lfanew + 4 + 20 + size_opt
        sec_data = self.api.read_mem(sec_table_base, num_sections * 40)
        print(f"\n{'Idx':<4} {'Name':<10} {'RVA':<10} {'VSize':<10}")
        for i in range(num_sections):
            off = i * 40
            name = sec_data[off:off+8].rstrip(b'\x00').decode('utf-8', errors='ignore')
            v_addr = struct.unpack("<I", sec_data[off+12:off+16])[0]
            v_size = struct.unpack("<I", sec_data[off+8:off+12])[0]
            print(f"{i:<4} {name:<10} {v_addr:<10X} {v_size:<10X}")

    def handle_auto_init(self):
        if self.api.cached_dtb == 0:
            log("Please run 'attach <PID>' first!", "ERROR")
            return
        scanner = UEScanner(self.api, self.ctx.g_base_addr) #
        gnames = scanner.find_gnames()
        gobjects = scanner.find_gobjects()
        if gnames and gobjects:
            self.ctx.GNames = gnames
            self.ctx.GObjects = gobjects
            self.ctx.NameStore = FNameEntryArray_UE424(gnames) #
            self.ctx.ObjArray = TUObjectArray(gobjects)
            log(f"Engine Initialized: GN={hex(gnames)}, GO={hex(gobjects)}", "SUCCESS")
        else:
            log("Auto-init failed.", "ERROR")

    def handle_cache_gnames(self):
        if not self.ctx.GNames:
            log("Run 'auto_init' first.", "ERROR")
            return
        cache = FNameCache(self.ctx.GNames) #
        cache.build_cache()
        if cache.is_cached:
            self.ctx.NameCache = cache
            log("GNames Cached Successfully!", "SUCCESS")

    def handle_dump_sdk(self, args):
        if not args or not self.ctx.ObjArray:
            log("Usage: dump_sdk <ClassName> (or engine not init)", "ERROR")
            return
        target = args[0]
        name_provider = self.ctx.NameCache if self.ctx.NameCache else self.ctx.NameStore
        log(f"Searching for class '{target}'...")
        found_addr = 0
        for i in range(min(self.ctx.ObjArray.num_elements, 300000)):
            obj = self.ctx.ObjArray.get_object_ptr(i)
            if not obj: continue
            if name_provider.get_name(ue_memory.mem.read_u32(obj + 0x18)) == target:
                found_addr = obj
                break
        if found_addr:
            gen = SDKGenerator(name_provider, self.ctx.ObjArray) #
            gen.generate_class_sdk(found_addr)
        else:
            log("Class not found.", "ERROR")

    def handle_modules(self, args):
        if not args:
            log("Usage: modules <PID>", "WARN")
            return
        try:
            target_pid = int(args[0])
            self.api.enum_user_modules(target_pid) #
            log("Command sent. Check [LOG] for module stream.", "SUCCESS")
        except ValueError:
            log("PID must be a number.", "ERROR")
            
    def handle_dump_mem(self, args):
        """通用内存 Dump (支持特定基址+范围)"""
        if len(args) < 3:
            log("Usage: dump_mem <HexAddr> <HexSize> <Filename>", "ERROR")
            return
        try:
            target_addr = int(args[0], 16)
            target_size = int(args[1], 16)
            filename = args[2]
            
            log(f"Dumping {target_size/1024:.2f} KB from 0x{target_addr:X} to '{filename}'...")
            
            start_time = time.time()
            # 调用 api 进行读取
            data = self.api.read_mem(target_addr, target_size)
            
            if data and len(data) == target_size:
                with open(filename, "wb") as f:
                    f.write(data)
                duration = time.time() - start_time
                log(f"Dump saved successfully! Speed: {target_size/1024/1024/duration:.2f} MB/s", "SUCCESS")
            else:
                log(f"Dump failed. Received {len(data) if data else 0}/{target_size} bytes.", "ERROR")
                
        except Exception as e:
            log(f"Dump Error: {e}", "ERROR")
