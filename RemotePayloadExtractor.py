#!/usr/bin/env python3
# 远程负载提取工具 - 修复中断流程和文件名问题

import bz2
import hashlib
import lzma
import sys
import struct
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import zstandard
import argparse
import update_metadata_pb2 as um
import threading
import queue
import time
from collections import deque
import zlib
import os
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal

# ========== 常量定义 ==========
ZIP_HEADERS = {
    'END': b"\x50\x4b\x05\x06",
    'LOCAL': b"\x50\x4b\x03\x04",
    'CENTRAL': b"\x50\x4b\x01\x02",
    'END64': b"\x50\x4b\x06\x06",
    'LOCATOR64': b"\x50\x4b\x06\x07"
}

COMPRESSION_METHODS = {
    0: ("未压缩", lambda x: x),
    8: ("DEFLATE", lambda x: zlib.decompress(x, -15)),
    12: ("BZIP2", bz2.decompress),
    14: ("LZMA", lzma.decompress),
    93: ("Zstandard", zstandard.ZstdDecompressor().decompress),
    95: ("XZ", lzma.decompress)
}

HEADER_FIXED_SIZE = 24
CHUNK_SIZE = 1024 * 1024 * 4  # 4MB块大小
MAX_RETRIES = 3
DOWNLOAD_THREADS = 8
SPEED_SAMPLES = 5
FILE_DOWNLOAD_THREADS = 8  # 文件下载线程数

# ========== 自定义异常 ==========
class FileNotFoundInZipError(ValueError):
    """ZIP中未找到文件"""
    pass

class DownloadInterrupted(Exception):
    """下载被中断"""
    pass

# ========== 全局状态 ==========
file_lock = threading.Lock()
download_stats = {
    "total": 0,
    "downloaded": 0,
    "lock": threading.Lock(),
    "history": deque(maxlen=SPEED_SAMPLES),
}
stop_event = threading.Event()
download_complete = threading.Event()

class DownloadManager:
    """下载管理类"""
    
    @staticmethod
    def create_session():
        session = requests.Session()
        retry = Retry(
            total=MAX_RETRIES,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=DOWNLOAD_THREADS)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    @staticmethod
    def get_range(url, start, end=None, session=None):
        if stop_event.is_set():
            raise DownloadInterrupted("下载已被中断")
            
        session = session or DownloadManager.create_session()
        range_header = f"bytes={start}-{end}" if end else f"bytes={start}-"
        try:
            # 缩短超时时间
            response = session.get(url, headers={"Range": range_header}, timeout=5)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            if stop_event.is_set():
                raise DownloadInterrupted("下载已被中断")
            raise

class ZipUtils:
    """ZIP文件处理工具类"""
    
    @staticmethod
    def parse_header(header_data):
        return struct.unpack("<4sHHHHHHIIIHHHHHII", header_data[:46])
    
    @staticmethod
    def parse_zip64_extra(extra_field):
        values = {}
        pos = 0
        while pos <= len(extra_field) - 4:
            header_id, size = struct.unpack("<HH", extra_field[pos:pos+4])
            if header_id == 0x0001:
                data = extra_field[pos+4:pos+4+size]
                ptr = 0
                if size >= 8:
                    values["uncomp_size"] = struct.unpack("<Q", data[ptr:ptr+8])[0]
                    ptr += 8
                if size >= 16:
                    values["compressed_size"] = struct.unpack("<Q", data[ptr:ptr+8])[0]
                    ptr += 8
                if size >= 24:
                    values["local_header_offset"] = struct.unpack("<Q", data[ptr:ptr+8])[0]
                break
            pos += 4 + size
        return values
    
    @staticmethod
    def find_zip_structure(url, file_size, session):
        search_end = min(1024 * 1024, file_size)
        end_chunk = DownloadManager.get_range(url, file_size-search_end, file_size-1, session)
        
        locator_pos = end_chunk.rfind(ZIP_HEADERS['LOCATOR64'])
        if locator_pos != -1:
            locator_offset = file_size - search_end + locator_pos
            end_offset = struct.unpack(
                "<Q", DownloadManager.get_range(url, locator_offset+8, locator_offset+15, session)
            )[0]
            
            zip64_end = DownloadManager.get_range(url, end_offset, end_offset+1023, session)
            cd_offset = struct.unpack("<Q", zip64_end[48:56])[0]
            cd_size = struct.unpack("<Q", zip64_end[40:48])[0]
            return cd_offset, cd_size
        else:
            # 如果没有找到ZIP64结构，尝试标准ZIP结构
            end_pos = end_chunk.rfind(ZIP_HEADERS['END'])
            if end_pos != -1:
                end_header = end_chunk[end_pos:end_pos+22]
                cd_offset = struct.unpack("<I", end_header[16:20])[0]
                cd_size = struct.unpack("<I", end_header[12:16])[0]
                return cd_offset, cd_size
            raise ValueError("无法识别ZIP文件结构")
    
    @staticmethod
    def validate_local_header(url, local_offset, filename, session):
        local_header = DownloadManager.get_range(url, local_offset, local_offset+29, session)
        if local_header[:4] != ZIP_HEADERS['LOCAL']:
            raise ValueError(f"无效的本地头签名: {local_header[:4].hex()}")

        name_len_local = struct.unpack("<H", local_header[26:28])[0]
        extra_len_local = struct.unpack("<H", local_header[28:30])[0]

        full_header_size = 30 + name_len_local
        local_header = DownloadManager.get_range(
            url, local_offset, local_offset + full_header_size - 1, session
        )

        name_local = local_header[30:30+name_len_local].decode("utf-8", "ignore")
        if name_local != filename:
            raise ValueError(f"本地头文件名不匹配: {name_local} vs {filename}")

        return local_offset + full_header_size + extra_len_local
    
    @staticmethod
    def find_file_in_zip(url, cd_offset, cd_size, filename, session):
        cd_data = DownloadManager.get_range(url, cd_offset, cd_offset + cd_size - 1, session)
        pos = 0

        while pos <= len(cd_data) - 46:
            if stop_event.is_set():
                raise DownloadInterrupted("下载已被中断")
                
            if cd_data[pos:pos+4] != ZIP_HEADERS['CENTRAL']:
                pos += 1
                continue

            header = ZipUtils.parse_header(cd_data[pos:pos+46])
            name_len = header[10]
            extra_len = header[11]
            comment_len = header[12]
            local_header_offset = header[16]

            name = cd_data[pos+46:pos+46+name_len].decode("utf-8", "ignore")
            extra_field = cd_data[pos+46+name_len:pos+46+name_len+extra_len]
            zip64_values = ZipUtils.parse_zip64_extra(extra_field)
            actual_offset = zip64_values.get("local_header_offset", local_header_offset)

            if name == filename:
                print(f"定位到 {filename}，尝试验证本地头...")
                try:
                    data_offset = ZipUtils.validate_local_header(
                        url, actual_offset, filename, session
                    )
                    return data_offset, zip64_values.get("uncomp_size", header[8])
                except ValueError as e:
                    print(f"本地头验证失败: {str(e)}")
                    data_offset = ZipUtils.heuristic_search(url, actual_offset, filename, session)
                    return data_offset, zip64_values.get("uncomp_size", header[8])

            pos += 46 + name_len + extra_len + comment_len

        raise FileNotFoundInZipError(f"ZIP中未找到 {filename}")
    
    @staticmethod
    def heuristic_search(url, base_offset, filename, session):
        search_start = max(0, base_offset - 1024)
        search_data = DownloadManager.get_range(url, search_start, base_offset+1024, session)
        target_header = ZIP_HEADERS['LOCAL'] + filename.encode()
        found_pos = search_data.find(target_header)
        if found_pos != -1:
            return (
                search_start + found_pos + 30 + len(filename) +
                struct.unpack("<H", search_data[found_pos+28:found_pos+30])[0]
            )
        raise ValueError("自动修正失败，请检查ZIP文件完整性")

class ProgressUtils:
    """进度显示工具类"""
    
    @staticmethod
    def format_size(size):
        size = int(size)
        if size < 1024:
            return f"{size} B"
        units = ["KB", "MB", "GB", "TB", "PB"]
        shift = (size.bit_length() - 1) // 10
        shift = min(shift, len(units))
        size = f"{(size / (1 << (shift * 10))):.2f}".replace(".00", "")
        return f"{size} {units[shift-1]}"
    
    @staticmethod
    def print_progress(current, total, speed=0, elapsed=0):
        percent = current * 100 / total if total else 0
        speed_str = f"{ProgressUtils.format_size(speed)}/s"
        eta = (total - current) / speed if speed > 0 else 0
        eta_str = f"{eta:.1f}s" if eta else "--"
        
        progress = (
            f"\r下载进度: {ProgressUtils.format_size(current)}/{ProgressUtils.format_size(total)} "
            f"({percent:.1f}%) | 速度: {speed_str} | 用时: {elapsed:.1f}s | ETA: {eta_str}"
        )
        print(progress, end="", flush=True)
    
    @staticmethod
    def print_progress_loop():
        start_time = time.time()
        while not download_complete.is_set() and not stop_event.is_set():
            with download_stats["lock"]:
                current = download_stats["downloaded"]
                total = download_stats["total"]
                history = list(download_stats["history"])

            if len(history) >= 2:
                time_diff = history[-1][0] - history[0][0]
                bytes_diff = sum(h[1] for h in history)
                speed = int(bytes_diff / max(time_diff, 1e-6))
            else:
                speed = 0

            elapsed = time.time() - start_time
            ProgressUtils.print_progress(current, total, speed, elapsed)
            time.sleep(0.5)

        if stop_event.is_set():
            print("\n下载已终止")
        else:
            with download_stats["lock"]:
                current = download_stats["downloaded"]
                total = download_stats["total"]
            elapsed = time.time() - start_time
            ProgressUtils.print_progress(current, total, 0, elapsed)
            print()

class PayloadExtractor:
    """payload.bin提取器"""
    
    @staticmethod
    def parse_payload_header(url, payload_offset, session):
        header = DownloadManager.get_range(
            url, payload_offset, payload_offset + 512*1024 - 1, session
        )

        if len(header) < HEADER_FIXED_SIZE or header[:4] != b"CrAU":
            raise ValueError("无效的payload.bin格式")

        manifest_size = int.from_bytes(header[12:20], byteorder="big")
        metadata_sig_size = int.from_bytes(header[20:24], byteorder="big")

        partitions_start = HEADER_FIXED_SIZE + manifest_size + metadata_sig_size
        if partitions_start > len(header):
            raise ValueError(f"头部数据不足，需要至少 {partitions_start + 1024} 字节")

        manifest = header[24:24+manifest_size]
        dam = um.DeltaArchiveManifest()
        dam.ParseFromString(manifest)

        if not dam.partitions:
            raise ValueError("未找到有效分区")

        print(f"成功解析 {len(dam.partitions)} 个分区")
        return partitions_start, dam.partitions, dam.block_size
    
    @staticmethod
    def process_operation(op, data, block_size):
        if op.data_sha256_hash:
            actual_hash = hashlib.sha256(data).digest()
            if actual_hash != op.data_sha256_hash:
                raise ValueError(f"操作 {op.data_offset} 哈希校验失败")

        # 修复操作类型处理 - 使用枚举值而不是字符串
        if op.type == op.ZERO:
            return b"\x00" * op.dst_extents[0].num_blocks * block_size
        
        decompressors = {
            op.REPLACE_XZ: lzma.decompress,
            op.ZSTD: lambda data: zstandard.ZstdDecompressor().decompress(data),
            op.REPLACE_BZ: bz2.decompress,
            op.REPLACE: lambda x: x,
        }
        
        decompressor = decompressors.get(op.type)
        if not decompressor:
            raise ValueError(f"不支持的操作类型: {op.type}")

        return decompressor(data)
    
    @staticmethod
    def download_worker(url, base_offset, op_queue, session, block_size, out_file):
        while not stop_event.is_set():
            try:
                op = op_queue.get(timeout=0.5)  # 缩短超时时间
            except queue.Empty:
                continue

            if stop_event.is_set():
                op_queue.task_done()
                break

            try:
                start = base_offset + op.data_offset
                data = DownloadManager.get_range(url, start, start+op.data_length-1, session)
                processed = PayloadExtractor.process_operation(op, data, block_size)

                with download_stats["lock"]:
                    download_stats["downloaded"] += op.data_length
                    download_stats["history"].append((time.time(), op.data_length))

                with file_lock:
                    out_file.seek(op.dst_extents[0].start_block * block_size)
                    out_file.write(processed)
            except Exception as e:
                print(f"下载失败: {str(e)}")
                stop_event.set()
            finally:
                op_queue.task_done()
    
    @staticmethod
    def download_partition(url, base_offset, partition, output_file, session, block_size):
        total_size = sum(op.data_length for op in partition.operations)
        with download_stats["lock"]:
            download_stats["total"] = total_size
            download_stats["downloaded"] = 0
            download_stats["history"].clear()
        stop_event.clear()
        download_complete.clear()

        op_queue = queue.Queue()
        for op in partition.operations:
            op_queue.put(op)

        try:
            with open(output_file, "wb") as out_file:
                threads = []
                for _ in range(DOWNLOAD_THREADS):
                    t = threading.Thread(
                        target=PayloadExtractor.download_worker,
                        args=(url, base_offset, op_queue, session, block_size, out_file),
                        daemon=True
                    )
                    t.start()
                    threads.append(t)

                progress_thread = threading.Thread(target=ProgressUtils.print_progress_loop, daemon=True)
                progress_thread.start()

                # 等待队列清空或终止事件
                while not op_queue.empty() and not stop_event.is_set():
                    time.sleep(0.2)  # 更频繁地检查中断

                # 清理队列和线程
                op_queue.join()
                download_complete.set()
                progress_thread.join(timeout=1)

            return True

        except KeyboardInterrupt:
            print("\n用户中断，正在退出...")
            stop_event.set()
            sys.exit(1)
        finally:
            if stop_event.is_set():
                print("\n下载已终止")

class FileExtractor:
    """ZIP文件提取器"""
    
    @staticmethod
    def get_file_compression_info(cd_data, filename):
        pos = 0
        while pos <= len(cd_data) - 46:
            if stop_event.is_set():
                raise DownloadInterrupted("下载已被中断")
                
            if cd_data[pos:pos+4] != ZIP_HEADERS['CENTRAL']:
                pos += 1
                continue

            header = ZipUtils.parse_header(cd_data[pos:pos+46])
            name_len = header[10]
            extra_len = header[11]
            comment_len = header[12]
            compression_method = header[5]
            compressed_size = header[8]

            name = cd_data[pos+46:pos+46+name_len].decode("utf-8", "ignore")
            
            if name == filename:
                extra_field = cd_data[pos+46+name_len:pos+46+name_len+extra_len]
                zip64_values = ZipUtils.parse_zip64_extra(extra_field)
                actual_compressed_size = zip64_values.get("compressed_size", compressed_size)
                return compression_method, actual_compressed_size
            
            pos += 46 + name_len + extra_len + comment_len
        
        raise FileNotFoundInZipError(f"中央目录中未找到 {filename}")
    
    @staticmethod
    def download_chunk(args):
        """下载文件块的工作函数"""
        if stop_event.is_set():
            return None
            
        url, session, file_offset, start, end, chunk_idx = args
        try:
            # 使用更小的超时时间
            data = DownloadManager.get_range(url, file_offset + start, file_offset + end - 1, session)
            return chunk_idx, data
        except DownloadInterrupted:
            return None
        except Exception as e:
            print(f"下载块 {chunk_idx} 失败: {str(e)}")
            return None
    
    @staticmethod
    def extract_file_from_zip(url, file_size, cd_offset, cd_size, filename, output_path, session=None):
        """从ZIP中提取文件，使用预解析的中央目录信息"""
        session = session or DownloadManager.create_session()
        
        try:
            print(f"正在从 {url} 提取 {filename}...")
            file_offset, uncompressed_size = ZipUtils.find_file_in_zip(url, cd_offset, cd_size, filename, session)
            
            cd_data = DownloadManager.get_range(url, cd_offset, cd_offset + cd_size - 1, session)
            compression_method, compressed_size = FileExtractor.get_file_compression_info(cd_data, filename)
            
            print(f"文件位置: 偏移={file_offset}, 大小={ProgressUtils.format_size(uncompressed_size)}")
            print(f"压缩方法: {COMPRESSION_METHODS.get(compression_method, ('未知', None))[0]}")
            print("开始下载... (按Ctrl+C可中断)")
            
            start_time = time.time()
            
            if compression_method == 0:  # 未压缩
                # 多线程下载文件
                return FileExtractor.download_uncompressed_file(
                    url, session, file_offset, uncompressed_size, output_path, start_time
                )
            else:  # 需要解压缩
                # 单线程下载压缩文件
                return FileExtractor.download_compressed_file(
                    url, session, file_offset, compressed_size, uncompressed_size, 
                    compression_method, output_path, start_time
                )
        
        except DownloadInterrupted:
            print("\n下载被中断")
            try:
                os.remove(output_path)
            except:
                pass
            return False
        except FileNotFoundInZipError:
            raise  # 重新抛出，让调用者处理
        except Exception as e:
            print(f"\n提取失败: {str(e)}")
            return False
    
    @staticmethod
    def download_uncompressed_file(url, session, file_offset, file_size, output_path, start_time):
        """多线程下载未压缩文件"""
        # 创建文件并设置大小
        try:
            with open(output_path, 'wb') as f:
                f.truncate(file_size)
        except:
            pass
        
        # 计算块数量和大小
        num_chunks = max(1, math.ceil(file_size / CHUNK_SIZE))
        chunk_size = min(CHUNK_SIZE, file_size)
        
        # 进度统计
        downloaded = 0
        last_update = time.time()
        
        # 使用线程池下载
        try:
            # 创建线程池时设置线程名称以便识别
            with ThreadPoolExecutor(max_workers=FILE_DOWNLOAD_THREADS, thread_name_prefix="Downloader") as executor:
                futures = []
                for i in range(num_chunks):
                    if stop_event.is_set():
                        break
                        
                    start = i * chunk_size
                    end = min(start + chunk_size, file_size)
                    if start >= file_size:
                        break
                        
                    args = (url, session, file_offset, start, end, i)
                    futures.append(executor.submit(FileExtractor.download_chunk, args))
                
                # 处理下载结果
                for future in as_completed(futures):
                    if stop_event.is_set():
                        break
                        
                    result = future.result()
                    if result is None:
                        continue
                    
                    chunk_idx, data = result
                    chunk_size = len(data)
                    
                    # 写入文件
                    start_pos = chunk_idx * CHUNK_SIZE
                    try:
                        with open(output_path, 'r+b') as f:
                            f.seek(start_pos)
                            f.write(data)
                    except:
                        pass
                    
                    # 更新进度
                    downloaded += chunk_size
                    current_time = time.time()
                    
                    # 限制进度更新频率（每秒最多更新4次）
                    if current_time - last_update > 0.25:
                        elapsed = current_time - start_time
                        speed = downloaded / elapsed if elapsed > 0 else 0
                        ProgressUtils.print_progress(downloaded, file_size, speed, elapsed)
                        last_update = current_time
        except:
            pass
        
        if stop_event.is_set():
            print("\n下载被中断")
            try:
                os.remove(output_path)
            except:
                pass
            return False
        
        # 最终进度更新
        elapsed = time.time() - start_time
        ProgressUtils.print_progress(file_size, file_size, 0, elapsed)
        print(f"\n文件已保存至: {output_path}")
        return True
    
    @staticmethod
    def download_compressed_file(url, session, file_offset, compressed_size, uncompressed_size, 
                                compression_method, output_path, start_time):
        """下载并解压缩文件（带进度显示）"""
        # 获取解压器
        decompressor_info = COMPRESSION_METHODS.get(compression_method, (None, None))
        decompressor_name, decompressor_func = decompressor_info
        if not decompressor_func:
            raise ValueError(f"不支持的压缩方法: {compression_method}")
        
        print(f"使用 {decompressor_name} 解压缩...")
        
        # 分块下载压缩数据
        compressed_data = b''
        downloaded = 0
        chunk_size = min(CHUNK_SIZE, compressed_size)
        last_update = time.time()
        
        try:
            while downloaded < compressed_size and not stop_event.is_set():
                chunk_end = min(downloaded + chunk_size - 1, compressed_size - 1)
                data = DownloadManager.get_range(url, file_offset + downloaded, file_offset + chunk_end, session)
                compressed_data += data
                downloaded += len(data)
                
                # 更新进度
                current_time = time.time()
                if current_time - last_update > 0.25:
                    elapsed = current_time - start_time
                    speed = downloaded / elapsed if elapsed > 0 else 0
                    ProgressUtils.print_progress(downloaded, compressed_size, speed, elapsed)
                    last_update = current_time
        except:
            pass
        
        if stop_event.is_set():
            print("\n下载被中断")
            return False
        
        # 最终进度更新
        elapsed = time.time() - start_time
        ProgressUtils.print_progress(compressed_size, compressed_size, 0, elapsed)
        print("\n解压缩中...")
        
        # 解压缩数据
        try:
            decompressed_data = decompressor_func(compressed_data)
        except Exception as e:
            raise ValueError(f"解压缩失败: {str(e)}")
        
        if len(decompressed_data) != uncompressed_size:
            raise ValueError(f"解压后大小不匹配: 预期 {uncompressed_size}, 实际 {len(decompressed_data)}")
        
        # 写入文件
        try:
            with open(output_path, 'wb') as f:
                f.write(decompressed_data)
        except:
            pass
        
        print(f"文件已保存至: {output_path}")
        return True

class ZipFileInfo:
    """ZIP文件信息缓存类"""
    def __init__(self):
        self.url = None
        self.file_size = None
        self.cd_offset = None
        self.cd_size = None
        self.payload_offset = None
        self.payload_size = None
        self.partitions_start = None
        self.partitions = None
        self.block_size = None
        self.session = None
    
    def load_basic_info(self, url, session):
        """加载基本文件信息（大小和中央目录位置）"""
        self.url = url
        self.session = session or DownloadManager.create_session()
        
        # 获取文件大小
        if not self.file_size:
            print("正在获取文件大小...")
            try:
                self.file_size = int(
                    self.session.head(url, allow_redirects=True).headers["Content-Length"]
                )
            except:
                pass
        
        # 获取中央目录信息
        if not self.cd_offset or not self.cd_size:
            print("解析ZIP结构...")
            try:
                self.cd_offset, self.cd_size = ZipUtils.find_zip_structure(url, self.file_size, self.session)
                print(f"中央目录位置: 偏移={self.cd_offset}, 大小={self.cd_size}")
            except:
                pass
    
    def load_payload_info(self):
        """加载payload.bin信息"""
        if not self.payload_offset or not self.payload_size:
            print("定位payload.bin...")
            try:
                self.payload_offset, self.payload_size = ZipUtils.find_file_in_zip(
                    self.url, self.cd_offset, self.cd_size, "payload.bin", self.session
                )
                print(f"payload.bin位置: 偏移={self.payload_offset}, 大小={self.payload_size}")
            except:
                pass
        
        if not self.partitions_start or not self.partitions or not self.block_size:
            print("解析payload.bin头部...")
            try:
                self.partitions_start, self.partitions, self.block_size = PayloadExtractor.parse_payload_header(
                    self.url, self.payload_offset, self.session
                )
            except:
                pass
    
    def list_partitions(self):
        """列出所有分区"""
        try:
            self.load_payload_info()
            
            if not self.partitions:
                print("错误: 无法解析分区信息")
                return False
                
            print("\n可用分区列表:")
            print(f"{'分区名称':<16} | {'镜像大小':<10} | {'下载大小':<10}")
            print("-" * 45)
            for p in self.partitions:
                total_size = sum(op.data_length for op in p.operations)
                print(
                    f"{p.partition_name:<16} | {ProgressUtils.format_size(p.new_partition_info.size):<10} | {ProgressUtils.format_size(total_size):<10}"
                )
            return True
        except:
            return False
    
    def extract_file(self, filename, output_path):
        """提取文件"""
        try:
            return FileExtractor.extract_file_from_zip(
                self.url, self.file_size, self.cd_offset, self.cd_size, 
                filename, output_path, self.session
            )
        except FileNotFoundInZipError:
            print(f"ZIP中未找到文件: {filename}")
            return False
        except:
            return False
    
    def extract_partition(self, partition_name, output_path):
        """提取分区"""
        try:
            self.load_payload_info()
            
            if not self.partitions:
                print("错误: 无法解析分区信息")
                return False
            
            # 查找分区
            target = next((p for p in self.partitions if p.partition_name == partition_name), None)
            if not target:
                available = ", ".join(p.partition_name for p in self.partitions)
                print(f"错误: 未找到分区 '{partition_name}'，可用分区: {available}")
                return False
            
            total_size = sum(op.data_length for op in target.operations)
            print(f"开始下载 {target.partition_name} ({ProgressUtils.format_size(total_size)})")
            
            if PayloadExtractor.download_partition(
                self.url,
                self.payload_offset + self.partitions_start,
                target,
                output_path,
                self.session,
                self.block_size,
            ):
                print(f"文件已保存至: {output_path}")
                return True
            return False
        except:
            return False

def signal_handler(sig, frame):
    """处理Ctrl+C信号"""
    print("\n接收到中断信号，正在终止下载...")
    stop_event.set()
    # 不立即退出，让清理工作完成
    # 设置一个超时，防止永久等待
    threading.Timer(15.0, force_exit).start()

def force_exit():
    """强制退出程序"""
    print("无法正常终止，强制退出")
    os._exit(1)

def main():
    global DOWNLOAD_THREADS
    
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        parser = argparse.ArgumentParser(
            description="远程分区提取工具",
            formatter_class=argparse.RawTextHelpFormatter,
            epilog="使用示例:\n"
                   "  1. 列出分区: python script.py https://example.com/update.zip\n"
                   "  2. 下载分区: python script.py https://example.com/update.zip boot\n"
                   "  3. 下载文件: python script.py https://example.com/update.zip payload.bin\n"
                   "  4. 指定输出: python script.py https://example.com/update.zip system -o system.img\n"
                   "  5. 多线程下载: python script.py https://example.com/update.zip vendor -t 16"
        )
        parser.add_argument("url", help="ZIP文件URL")
        parser.add_argument("name", nargs="?", default=None, 
                          help="要提取的分区名称或文件名（可选）")
        parser.add_argument("-o", "--output", help="输出文件名（可选）")
        parser.add_argument("-t", "--threads", type=int, default=DOWNLOAD_THREADS, 
                          help=f"下载线程数，默认值 {DOWNLOAD_THREADS}")
        parser.add_argument("-f", "--force-file", action="store_true", 
                          help="强制作为文件提取而非分区")
        args = parser.parse_args()

        DOWNLOAD_THREADS = args.threads
        session = DownloadManager.create_session()
        zip_info = ZipFileInfo()
        
        # 加载基本ZIP信息（只做一次）
        zip_info.load_basic_info(args.url, session)

        # 只提供URL时，列出分区
        if not args.name:
            if not zip_info.list_partitions():
                print("错误: 无法列出分区")
            return

        # 确定输出文件名
        # 文件提取默认使用原始文件名，分区提取默认添加.img后缀
        output_file_file = args.output if args.output else os.path.basename(args.name)
        output_file_partition = args.output if args.output else args.name + ".img"
        
        # 尝试提取文件（如果指定了强制文件或文件名中包含点）
        if args.force_file or '.' in args.name or '/' in args.name:
            print("尝试作为文件提取...")
            if stop_event.is_set():
                print("下载已被中断，退出程序")
                return
                
            if zip_info.extract_file(args.name, output_file_file):
                return
            elif args.force_file:
                print("错误: 文件提取失败")
                sys.exit(1)  # 强制文件模式下找不到文件则退出
        
        # 检查是否已被中断
        if stop_event.is_set():
            print("下载已被中断，退出程序")
            return
            
        # 尝试提取分区
        print("尝试作为分区提取...")
        if zip_info.extract_partition(args.name, output_file_partition):
            return
        
        # 检查是否已被中断
        if stop_event.is_set():
            print("下载已被中断，退出程序")
            return
            
        # 如果分区提取失败，尝试作为文件提取（作为后备）
        if not args.force_file:
            print("分区提取失败，尝试作为文件提取...")
            if stop_event.is_set():
                print("下载已被中断，退出程序")
                return
                
            if zip_info.extract_file(args.name, output_file_file):
                return
        
        # 所有尝试都失败
        print(f"错误: 无法找到分区或文件 '{args.name}'")
        sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n操作被用户中断")
        stop_event.set()
        sys.exit(1)
    except Exception as e:
        print(f"\n发生错误: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()