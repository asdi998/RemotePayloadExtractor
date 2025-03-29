#!/usr/bin/env python3
import bz2
import hashlib
import lzma
import os
import sys
import struct
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import zstandard
import argparse
from collections import namedtuple
import update_metadata_pb2 as um

# ========== 常量定义 ==========
ZIP_END_HEADER = b"\x50\x4b\x05\x06"
ZIP_LOCAL_HEADER = b"\x50\x4b\x03\x04"
ZIP_CENTRAL_HEADER = b"\x50\x4b\x01\x02"
ZIP64_END_HEADER = b"\x50\x4b\x06\x06"
ZIP64_LOCATOR = b"\x50\x4b\x06\x07"
HEADER_FIXED_SIZE = 24  # payload.bin头部固定大小
CHUNK_SIZE = 1024 * 1024  # 1MB分块下载
MAX_RETRIES = 3  # 网络请求最大重试次数


def convert_bytes(size):
    """将字节数转换为人类易读的格式"""
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    for unit in units[:-1]:
        if size < 1024:
            break
        size /= 1024
    else:
        unit = units[-1]
    return f"{size:.2f} {unit}".replace(".00", "") if unit != "B" else f"{size} B"


# ========== 网络请求配置 ==========
def create_retry_session():
    """创建带重试机制的Session对象"""
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ========== 核心功能优化 ==========
def get_remote_range(url, start, end=None, session=None):
    """带重试机制的范围下载"""
    session = session or create_retry_session()
    range_header = f"bytes={start}-{end}" if end else f"bytes={start}-"
    response = session.get(url, headers={"Range": range_header}, timeout=30)
    response.raise_for_status()
    return response.content


def validate_local_header(url, local_offset, filename, session):
    """验证本地文件头并返回数据偏移量"""
    # 下载本地文件头基础部分
    local_header = get_remote_range(url, local_offset, local_offset + 29, session)
    if local_header[:4] != ZIP_LOCAL_HEADER:
        raise ValueError(f"无效的本地头签名: {local_header[:4].hex()}")

    # 解析文件名长度
    name_len_local = struct.unpack("<H", local_header[26:28])[0]
    extra_len_local = struct.unpack("<H", local_header[28:30])[0]

    # 下载完整文件头
    full_header_size = 30 + name_len_local
    local_header = get_remote_range(
        url, local_offset, local_offset + full_header_size - 1, session
    )

    # 验证文件名
    name_local = local_header[30 : 30 + name_len_local].decode("utf-8", "ignore")
    if name_local != filename:
        raise ValueError(f"本地头文件名不匹配: {name_local} vs {filename}")

    return local_offset + full_header_size + extra_len_local


def find_zip_structure(url, file_size, session):
    """定位ZIP结构（支持ZIP64）"""
    # 尝试查找ZIP64结构
    search_end = min(1024 * 1024, file_size)
    end_chunk = get_remote_range(url, file_size - search_end, file_size - 1, session)

    zip64_locator_pos = end_chunk.rfind(ZIP64_LOCATOR)
    if zip64_locator_pos != -1:
        locator_offset = file_size - search_end + zip64_locator_pos
        zip64_end_offset = struct.unpack(
            "<Q", get_remote_range(url, locator_offset + 8, locator_offset + 15)
        )[0]

        zip64_end = get_remote_range(url, zip64_end_offset, zip64_end_offset + 1023)
        cd_offset = struct.unpack("<Q", zip64_end[48:56])[0]
        cd_size = struct.unpack("<Q", zip64_end[40:48])[0]
        return cd_offset, cd_size


def find_file_in_zip(url, cd_offset, cd_size, filename, session):
    """优化后的ZIP中央目录解析"""
    cd_data = get_remote_range(url, cd_offset, cd_offset + cd_size - 1, session)
    pos = 0

    while pos <= len(cd_data) - 46:
        if cd_data[pos : pos + 4] != ZIP_CENTRAL_HEADER:
            pos += 1
            continue

        # 结构体解析优化
        header = struct.unpack("<4sHHHHHHIIIHHHHHII", cd_data[pos : pos + 46])
        name_len = header[10]
        extra_len = header[11]
        comment_len = header[12]
        local_header_offset = header[16]

        # 提取文件名
        name = cd_data[pos + 46 : pos + 46 + name_len].decode("utf-8", "ignore")

        # 处理ZIP64扩展
        zip64_values = parse_zip64_extra(
            cd_data[pos + 46 + name_len : pos + 46 + name_len + extra_len]
        )
        actual_offset = zip64_values.get("local_header_offset", local_header_offset)

        if name == filename:
            print(f"定位到 {filename}，尝试验证本地头...")
            try:
                data_offset = validate_local_header(
                    url, actual_offset, filename, session
                )
                return data_offset, zip64_values.get("uncomp_size", header[8])
            except ValueError as e:
                print(f"本地头验证失败: {str(e)}")
                data_offset = heuristic_search(url, actual_offset, filename, session)
                return data_offset, zip64_values.get("uncomp_size", header[8])

        pos += 46 + name_len + extra_len + comment_len

    raise ValueError(f"ZIP中未找到 {filename}")


# ========== 辅助函数优化 ==========
def parse_zip64_extra(extra_field):
    """解析ZIP64扩展字段"""
    zip64_values = {}
    extra_pos = 0
    while extra_pos <= len(extra_field) - 4:
        header_id, data_size = struct.unpack(
            "<HH", extra_field[extra_pos : extra_pos + 4]
        )
        if header_id == 0x0001:
            zip64_data = extra_field[extra_pos + 4 : extra_pos + 4 + data_size]
            data_ptr = 0
            # 动态解析ZIP64字段
            if data_size >= 8:
                zip64_values["uncomp_size"] = struct.unpack(
                    "<Q", zip64_data[data_ptr : data_ptr + 8]
                )[0]
                data_ptr += 8
            if data_size >= 16:
                zip64_values["compressed_size"] = struct.unpack(
                    "<Q", zip64_data[data_ptr : data_ptr + 8]
                )[0]
                data_ptr += 8
            if data_size >= 24:
                zip64_values["local_header_offset"] = struct.unpack(
                    "<Q", zip64_data[data_ptr : data_ptr + 8]
                )[0]
            break
        extra_pos += 4 + data_size
    return zip64_values


def heuristic_search(url, base_offset, filename, session):
    """启发式搜索文件头"""
    search_start = max(0, base_offset - 1024)
    search_data = get_remote_range(url, search_start, base_offset + 1024, session)
    target_header = ZIP_LOCAL_HEADER + filename.encode()
    found_pos = search_data.find(target_header)
    if found_pos != -1:
        return (
            search_start
            + found_pos
            + 30
            + len(filename)
            + struct.unpack("<H", search_data[found_pos + 28 : found_pos + 30])[0]
        )
    raise ValueError("自动修正失败，请检查ZIP文件完整性")


# ========== 主要逻辑优化 ==========
def parse_payload_header(url, payload_offset, session):
    """优化后的payload头解析"""
    header = get_remote_range(
        url, payload_offset, payload_offset + 512 * 1024 - 1, session
    )

    # 增强头部验证
    if len(header) < HEADER_FIXED_SIZE or header[:4] != b"CrAU":
        raise ValueError("无效的payload.bin格式")

    manifest_size = int.from_bytes(header[12:20], byteorder="big")
    metadata_sig_size = int.from_bytes(header[20:24], byteorder="big")

    partitions_start = HEADER_FIXED_SIZE + manifest_size + metadata_sig_size
    if partitions_start > len(header):
        raise ValueError(f"头部数据不足，需要至少 {partitions_start + 1024} 字节")

    manifest = header[24 : 24 + manifest_size]
    dam = um.DeltaArchiveManifest()
    dam.ParseFromString(manifest)

    if not dam.partitions:
        raise ValueError("未找到有效分区")

    print(f"成功解析 {len(dam.partitions)} 个分区")
    return (
        partitions_start,
        dam.partitions,
        dam.block_size,
    )  # 返回block_size代替全局变量


# ========== 下载逻辑优化 ==========
def download_partition(url, base_offset, partition, output_file, session, block_size):
    """优化后的分区下载"""
    temp_dir = f"{partition.partition_name}_temp"
    os.makedirs(temp_dir, exist_ok=True)

    total_size = sum(op.data_length for op in partition.operations)
    downloaded = 0

    try:
        with open(output_file, "wb") as out_file:
            for op in partition.operations:
                op_path = os.path.join(temp_dir, f"{op.data_offset}.op")

                # 断点续传检查
                if (
                    os.path.exists(op_path)
                    and os.path.getsize(op_path) == op.data_length
                ):
                    downloaded += op.data_length
                    continue

                # 带重试的下载
                start = base_offset + op.data_offset
                data = get_remote_range(url, start, start + op.data_length - 1, session)

                # 实时处理数据
                processed = process_operation(op, data, block_size)
                out_file.seek(op.dst_extents[0].start_block * block_size)
                out_file.write(processed)

                downloaded += op.data_length
                print_progress(downloaded, total_size, "下载进度")

        print(f"\n分区 {partition.partition_name} 下载完成")
        return True
    finally:
        # 清理临时文件
        for f in os.listdir(temp_dir):
            os.remove(os.path.join(temp_dir, f))
        os.rmdir(temp_dir)


def process_operation(op, data, block_size):
    """统一数据处理逻辑"""
    if op.data_sha256_hash:
        actual_hash = hashlib.sha256(data).digest()
        if actual_hash != op.data_sha256_hash:
            raise ValueError(f"操作 {op.data_offset} 哈希校验失败")

    decompressors = {
        op.REPLACE_XZ: lzma.LZMADecompressor().decompress,
        op.ZSTD: zstandard.ZstdDecompressor().decompress,
        op.REPLACE_BZ: bz2.BZ2Decompressor().decompress,
        op.REPLACE: lambda x: x,
    }

    if op.type == op.ZERO:
        return b"\x00" * op.dst_extents[0].num_blocks * block_size
    if op.type not in decompressors:
        raise ValueError(f"不支持的操作类型: {op.type}")

    return decompressors[op.type](data)


def print_progress(current, total, prefix):
    """统一的进度显示"""
    percent = current * 100 / total
    print(
        f"\r{prefix}: {convert_bytes(current)}/{convert_bytes(total)} ({percent:.1f}%)",
        end="",
        flush=True,
    )


# ========== 主函数优化 ==========
def main():

    parser = argparse.ArgumentParser(description="远程分区提取工具")
    parser.add_argument("zip_url", nargs="?", help="ZIP文件URL")
    parser.add_argument("partition", nargs="?", help="要提取的分区名称")
    parser.add_argument("output", nargs="?", help="输出文件名")
    parser.add_argument(
        "-l", "--list", action="store_true", help="仅列出可用分区"
    )  # 新增列表参数
    args = parser.parse_args()

    if args.list:  # 列表模式逻辑
        if not args.zip_url:
            print("错误: 列表模式需要提供ZIP_URL")
            return

        session = create_retry_session()
        try:
            print("正在获取文件大小...")
            file_size = int(
                session.head(args.zip_url, allow_redirects=True).headers[
                    "Content-Length"
                ]
            )

            print("解析ZIP结构...")
            cd_offset, cd_size = find_zip_structure(args.zip_url, file_size, session)

            print("定位payload.bin...")
            payload_offset, _ = find_file_in_zip(
                args.zip_url, cd_offset, cd_size, "payload.bin", session
            )

            _, partitions, _ = parse_payload_header(
                args.zip_url, payload_offset, session
            )

            print("\n可用分区列表:")
            print(f"{'分区名称':<16} | {'大小':<10}")
            print("-" * 35)
            for p in partitions:
                total_size = sum(op.data_length for op in p.operations)
                print(f"{p.partition_name:<20} | {convert_bytes(total_size):<10}")
            return

        except Exception as e:
            print(f"\n错误发生: {type(e).__name__} - {str(e)}")
            sys.exit(1)

    # 原有下载逻辑
    if not args.zip_url or not args.partition:
        parser.print_help()
        return

    output_file = args.output if args.output else f"{args.partition}.img"

    session = create_retry_session()
    try:
        print("正在获取文件大小...")
        file_size = int(
            session.head(args.zip_url, allow_redirects=True).headers["Content-Length"]
        )

        print("解析ZIP结构...")
        cd_offset, cd_size = find_zip_structure(args.zip_url, file_size, session)
        print(f"中央目录位置: 偏移={cd_offset}, 大小={cd_size}")

        payload_offset, payload_size = find_file_in_zip(
            args.zip_url, cd_offset, cd_size, "payload.bin", session
        )
        print(f"payload.bin位置: 偏移={payload_offset}, 大小={payload_size}")

        partitions_start, partitions, block_size = parse_payload_header(
            args.zip_url, payload_offset, session
        )

        target = next(
            (p for p in partitions if p.partition_name == args.partition), None
        )
        if not target:
            available = ", ".join(p.partition_name for p in partitions)
            raise ValueError(f"未找到分区 '{args.partition}'，可用分区: {available}")

        total_size = sum(op.data_length for op in target.operations)
        print(f"开始下载 {target.partition_name} ({convert_bytes(total_size)})")

        if download_partition(
            args.zip_url,
            payload_offset + partitions_start,
            target,
            output_file,
            session,
            block_size,
        ):
            print(f"文件已保存至: {output_file}")

    except Exception as e:
        print(f"\n错误发生: {type(e).__name__} - {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
