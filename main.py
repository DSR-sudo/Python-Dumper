# main.py
from dma_core import DMACore
from dma_api import DMAApi
import ue_memory
from ue_types import FNameCache, FNameEntryArray_UE424, TUObjectArray
from ue_reflection import ReflectionDumper
from ue_generator import SDKGenerator
from ue_scanner import UEScanner
import time
import sys
import datetime

# ==========================================
# 工具函数
# ==========================================
def log(msg, level="INFO"):
    """带时间戳的日志输出"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    prefix = "[*]"
    if level == "SUCCESS": prefix = "[+]"
    elif level == "ERROR": prefix = "[-]"
    elif level == "WARN":  prefix = "[!]"
    print(f"{prefix} [{timestamp}] {msg}")

def print_banner():
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
    print("\n" + "="*60)
    print("COMMAND HELP MENU".center(60))
    print("="*60)
    
    cmds = [
        ("attach <PID>", "步骤1: 绑定到目标游戏进程 (获取 CR3)。", "示例: attach 10564"),
        ("auto_init",    "步骤2: 自动扫描特征码获取引擎基址。", "无需参数"),
        ("cache_gnames", "步骤3: [推荐] 缓存所有字符串到本地内存。", "极大提升后续 SDK 生成速度"),
        ("dump_sdk <ClassName>", "步骤4: 生成完整的 C++ SDK 头文件。", "示例: dump_sdk TslCharacter"),
        ("dump <ClassName>",     "调试: 快速查看类成员偏移。", "示例: dump TslCharacter"),
        ("init <GN> <GO>",       "调试: 手动初始化基址 (Hex)。", "示例: init 0x7FF... 0x7FF..."),
        ("cr3 <PID>",            "调试: 测试 DTB 获取。", "示例: cr3 10564"),
        ("exit",                 "退出程序。", ""),
    ]
    
    for cmd, desc, ex in cmds:
        print(f"\n[ {cmd} ]")
        for line in desc.split('\n'):
            print(f"    {line}")
        if ex:
            print(f"    -> {ex}")
    print("\n" + "="*60 + "\n")

# ==========================================
# 全局上下文管理
# ==========================================
class UEContext:
    def __init__(self):
        self.GNames = 0
        self.GObjects = 0
        self.NameStore = None # 基础读取器 (慢速, 远程DMA)
        self.NameCache = None # 缓存读取器 (快速, 本地内存)
        self.ObjArray = None
        self.g_base_addr = 0
ue_ctx = UEContext()

# ==========================================
# 主逻辑
# ==========================================
def main():
    print_banner()
    
    # 初始化 DMA 核心
    log("Initializing DMA Core...")
    core = DMACore()
    api = DMAApi(core)

    log("Waiting for DMA Driver connection...")
    while not core.driver_online: 
        time.sleep(0.1)
    log("Driver Connected! Type 'help' for commands.", "SUCCESS")

    while True:
        try:
            line = input("\n>> ").strip()
            if not line: continue
            parts = line.split()
            cmd = parts[0].lower()

            # -------------------------------------------------
            # 1. 帮助信息
            # -------------------------------------------------
            if cmd == "help":
                print_detailed_help()

            # -------------------------------------------------
            # 2. 附加进程 (Atomic Op 1)
            # -------------------------------------------------
            elif cmd == "attach":
                if len(parts) < 2:
                    log("Usage: attach <PID>", "ERROR")
                    continue
                
                try:
                    pid = int(parts[1])
                    log(f"Attempting to attach to PID {pid}...")
                    u, k, base = api.get_cr3(pid)
                    
                    if u:
                        # 关键: 初始化内存模块
                        ue_memory.mem = ue_memory.UEMemory(api, pid)
                        g_base_addr = base # 保存基址
                        log(f"Attached! UserDTB: {hex(u)}, Base: {hex(base)}", "SUCCESS")
                    else:
                        log("Failed to get CR3. Is the game running?", "ERROR")
                except ValueError:
                    log("PID must be a number.", "ERROR")

            # -------------------------------------------------
            # 3. 自动初始化 (Atomic Op 2)
            # -------------------------------------------------     
            elif cmd == "auto_init":
                # 1. 检查是否已 Attach
                if api.cached_dtb == 0:
                    log("Please run 'attach <PID>' first!", "ERROR")
                    continue
                
                # 2. 检查是否有基址
                if g_base_addr == 0:
                    log("Base Address is 0! Driver might be old or attach failed.", "ERROR")
                    continue
                
                log(f"Starting Auto-Initialization using Base: 0x{g_base_addr:X}...")
                
                # 3. 初始化扫描器 (传入 api 和 基址)
                scanner = UEScanner(api, g_base_addr)
                
                # 4. 扫描 GNames
                log("Scanning for GNames...")
                gnames = scanner.find_gnames()
                if gnames:
                    log(f"GNames Found: 0x{gnames:X}", "SUCCESS")
                else:
                    log("GNames scan failed. Check patterns.", "ERROR")
                    
                # 5. 扫描 GObjects
                log("Scanning for GObjects...")
                gobjects = scanner.find_gobjects()
                if gobjects:
                    log(f"GObjects Found: 0x{gobjects:X}", "SUCCESS")
                else:
                    log("GObjects scan failed. Check patterns.", "ERROR")
                    
                # 6. 初始化上下文
                if gnames and gobjects:
                    ue_ctx.GNames = gnames
                    ue_ctx.GObjects = gobjects
                    
                    try:
                        # 初始化 UE 结构读取器
                        ue_ctx.NameStore = FNameEntryArray_UE424(ue_ctx.GNames)
                        ue_ctx.ObjArray = TUObjectArray(ue_ctx.GObjects)
                        
                        log("Engine Initialized Successfully!", "SUCCESS")
                        log(f"Object Count: {ue_ctx.ObjArray.num_elements}")
                    except Exception as e:
                        log(f"Struct Init Error: {e}", "ERROR")
                else:
                    log("Auto-init failed due to missing addresses.", "ERROR")

            # -------------------------------------------------
            # 4. 手动初始化 (Backup for Op 2)
            # -------------------------------------------------
            elif cmd == "init":
                if len(parts) < 3:
                    log("Usage: init <GNamesHex> <GObjectsHex>", "ERROR")
                    continue
                try:
                    ue_ctx.GNames = int(parts[1], 16)
                    ue_ctx.GObjects = int(parts[2], 16)
                    
                    ue_ctx.NameStore = FNameEntryArray_UE424(ue_ctx.GNames)
                    ue_ctx.ObjArray = TUObjectArray(ue_ctx.GObjects)
                    
                    log(f"Manual Init: GNames=0x{ue_ctx.GNames:X}, GObjects=0x{ue_ctx.GObjects:X}", "SUCCESS")
                    log(f"Object Count: {ue_ctx.ObjArray.num_elements}")
                except Exception as e:
                    log(f"Init Failed: {e}", "ERROR")

            # -------------------------------------------------
            # 5. 缓存字符串 (Atomic Op 3)
            # -------------------------------------------------
            elif cmd == "cache_gnames":
                if not ue_ctx.GNames:
                    log("Run 'auto_init' first.", "ERROR")
                    continue
                
                log("Starting GNames Bulk Cache (This may take 5-15s)...")
                start_t = time.time()
                
                # 创建缓存对象
                cache = FNameCache(ue_ctx.GNames)
                cache.build_cache()
                
                if cache.is_cached:
                    # 将缓存对象存入全局上下文
                    ue_ctx.NameCache = cache
                    duration = time.time() - start_t
                    log(f"GNames Cached! {len(cache.cache)} names loaded in {duration:.2f}s", "SUCCESS")
                else:
                    log("Cache build skipped or failed (Check ue_types.py implementation)", "WARN")

            # -------------------------------------------------
            # 6. 生成 SDK (Atomic Op 4b)
            # -------------------------------------------------
            elif cmd == "dump_sdk":
                if len(parts) < 2:
                    log("Usage: dump_sdk <ClassName>", "ERROR")
                    continue
                if not ue_ctx.ObjArray:
                    log("Engine not initialized. Run 'auto_init'.", "ERROR")
                    continue

                target_class_name = parts[1]
                
                # 智能选择命名提供者：优先使用缓存，否则使用远程读取
                name_provider = None
                if ue_ctx.NameCache and ue_ctx.NameCache.is_cached:
                    name_provider = ue_ctx.NameCache
                else:
                    log("GNames NOT cached. Search will be SLOW (Network Latency).", "WARN")
                    log("Recommend running 'cache_gnames' first.", "WARN")
                    name_provider = ue_ctx.NameStore

                log(f"Searching for class '{target_class_name}'...")
                
                found_addr = 0
                limit = min(ue_ctx.ObjArray.num_elements, 300000)
                
                # 进度条逻辑
                last_print = time.time()
                
                for i in range(limit):
                    obj_addr = ue_ctx.ObjArray.get_object_ptr(i)
                    if not obj_addr: continue
                    
                    # 读取 NameID
                    name_id = ue_memory.mem.read_u32(obj_addr + 0x18)
                    name = name_provider.get_name(name_id)
                    
                    if name == target_class_name:
                        found_addr = obj_addr
                        break
                    
                    # 每0.5秒打印一次进度
                    if time.time() - last_print > 0.5:
                        sys.stdout.write(f"\r[*] Scanning... {i}/{limit} ({name})")
                        sys.stdout.flush()
                        last_print = time.time()
                
                print("") # 换行

                if found_addr:
                    log(f"Found Class at 0x{found_addr:X}", "SUCCESS")
                    log("Generating SDK...")
                    try:
                        gen = SDKGenerator(name_provider, ue_ctx.ObjArray)
                        gen.generate_class_sdk(found_addr)
                        log("SDK Generation Complete.", "SUCCESS")
                    except Exception as e:
                        log(f"Generation Error: {e}", "ERROR")
                        import traceback
                        traceback.print_exc()
                else:
                    log(f"Class '{target_class_name}' not found within {limit} objects.", "ERROR")

            # -------------------------------------------------
            # 7. 快速 Dump (Atomic Op 4a - Debug)
            # -------------------------------------------------
            elif cmd == "dump":
                if not ue_ctx.ObjArray:
                    log("Run 'auto_init' first.", "ERROR")
                    continue
                if len(parts) < 2:
                    log("Usage: dump <ClassName>", "ERROR")
                    continue
                
                target = parts[1]
                log(f"Quick searching for '{target}'...")
                
                # 这里默认用慢速查找，因为只是调试
                name_provider = ue_ctx.NameCache if ue_ctx.NameCache else ue_ctx.NameStore
                
                found = False
                for i in range(min(ue_ctx.ObjArray.num_elements, 300000)):
                    obj = ue_ctx.ObjArray.get_object_ptr(i)
                    if not obj: continue
                    name_idx = ue_memory.mem.read_u32(obj + 0x18)
                    name = name_provider.get_name(name_idx)
                    if name == target:
                        log(f"Found at 0x{obj:X}", "SUCCESS")
                        dumper = ReflectionDumper(name_provider)
                        dumper.dump_struct(obj)
                        found = True
                        break
                if not found: log("Class not found.", "ERROR")

            # -------------------------------------------------
            # 8. 调试 CR3
            # -------------------------------------------------
            elif cmd == "cr3":
                if len(parts) < 2: continue
                try:
                    u, k , b= api.get_cr3(int(parts[1]))
                    log(f"UserDTB: {hex(u) if u else 'N/A'}")
                    log(f"KernelDTB: {hex(k) if k else 'N/A'}")
                    log(f"Base:{hex(b) if b else 'N/A'}")
                except:
                    log("Failed to fetch CR3", "ERROR")

            # -------------------------------------------------
            # 9. 退出
            # -------------------------------------------------
            elif cmd == "exit":
                log("Exiting...")
                break

            else:
                log("Unknown command. Type 'help'.", "WARN")

        except KeyboardInterrupt:
            print("\n")
            log("Interrupted by user. Exiting...", "WARN")
            break
        except Exception as e:
            log(f"Critical Loop Error: {e}", "ERROR")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
