#!/usr/bin/env python3
import bz2
import hashlib
import lzma
import os
import sys
import struct
from time import sleep
import requests
import zstandard
from collections import namedtuple
import update_metadata_pb2 as um

PartitionInfo = namedtuple('PartitionInfo', ['name', 'size', 'offset'])

# ZIP签名
ZIP_END_HEADER = b'\x50\x4b\x05\x06'
ZIP_LOCAL_HEADER = b'\x50\x4b\x03\x04'
ZIP_CENTRAL_HEADER = b'\x50\x4b\x01\x02'
ZIP64_END_HEADER = b'\x50\x4b\x06\x06'
ZIP64_LOCATOR = b'\x50\x4b\x06\x07'

def get_remote_range(url, start, end=None):
    """下载指定范围的数据"""
    range_header = f'bytes={start}-{end}' if end else f'bytes={start}-'
    response = requests.get(url, headers={'Range': range_header}, timeout=30)
    response.raise_for_status()
    return response.content

def find_zip_structure(url, file_size):
    """定位ZIP结构（支持ZIP64）"""
    # 尝试查找ZIP64结构
    search_end = min(1024*1024, file_size)
    end_chunk = get_remote_range(url, file_size-search_end, file_size-1)
    
    zip64_locator_pos = end_chunk.rfind(ZIP64_LOCATOR)
    if zip64_locator_pos != -1:
        locator_offset = file_size - search_end + zip64_locator_pos
        zip64_end_offset = struct.unpack('<Q', get_remote_range(
            url, locator_offset+8, locator_offset+15))[0]
        
        zip64_end = get_remote_range(url, zip64_end_offset, zip64_end_offset+1023)
        cd_offset = struct.unpack('<Q', zip64_end[48:56])[0]
        cd_size = struct.unpack('<Q', zip64_end[40:48])[0]
        return cd_offset, cd_size
    
    # 普通ZIP结构
    end_pos = end_chunk.rfind(ZIP_END_HEADER)
    if end_pos == -1:
        raise ValueError("无法找到ZIP结尾记录")
    
    end_record = get_remote_range(url, file_size-search_end+end_pos, 
                                 file_size-search_end+end_pos+21)
    cd_offset = struct.unpack('<I', end_record[16:20])[0]
    cd_size = struct.unpack('<I', end_record[12:16])[0]
    
    if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        raise ValueError("需要ZIP64支持但未找到ZIP64记录")
    
    return cd_offset, cd_size

def find_file_in_zip(url, cd_offset, cd_size, filename):
    """在中央目录中查找文件（完整修复版）"""
    cd_data = get_remote_range(url, cd_offset, cd_offset+cd_size-1)
    pos = 0
    
    while pos <= len(cd_data) - 46:
        if cd_data[pos:pos+4] != ZIP_CENTRAL_HEADER:
            pos += 1
            continue
        
        # 解析中央文件头
        header = struct.unpack('<4sHHHHHHIIIHHHHHII', cd_data[pos:pos+46])
        (
            _, version_made, version_needed, flags, compression, mod_time,
            mod_date, crc32, compressed_size, uncomp_size, name_len,
            extra_len, comment_len, disk_num, internal_attr, external_attr,
            local_header_offset
        ) = header

        # 获取文件名
        name_start = pos + 46
        name_end = name_start + name_len
        name = cd_data[name_start:name_end].decode('utf-8', 'ignore')
        print(f"分析文件: {name} (本地头偏移: {local_header_offset})")

        # 处理ZIP64扩展
        zip64_values = {}
        if any(v == 0xFFFFFFFF for v in [local_header_offset, uncomp_size, compressed_size]):
            extra_field = cd_data[name_end:name_end+extra_len]
            extra_pos = 0
            while extra_pos < len(extra_field):
                header_id, data_size = struct.unpack('<HH', extra_field[extra_pos:extra_pos+4])
                if header_id == 0x0001:  # ZIP64扩展
                    zip64_data = extra_field[extra_pos+4:extra_pos+4+data_size]
                    # 按需读取字段
                    data_ptr = 0
                    if uncomp_size == 0xFFFFFFFF:
                        zip64_values['uncomp_size'] = struct.unpack('<Q', zip64_data[data_ptr:data_ptr+8])[0]
                        data_ptr += 8
                    if compressed_size == 0xFFFFFFFF:
                        zip64_values['compressed_size'] = struct.unpack('<Q', zip64_data[data_ptr:data_ptr+8])[0]
                        data_ptr += 8
                    if local_header_offset == 0xFFFFFFFF:
                        zip64_values['local_header_offset'] = struct.unpack('<Q', zip64_data[data_ptr:data_ptr+8])[0]
                    break
                extra_pos += 4 + data_size

        # 应用ZIP64值
        local_offset = zip64_values.get('local_header_offset', local_header_offset)
        actual_uncomp_size = zip64_values.get('uncomp_size', uncomp_size)

        if name == filename:
            print(f"定位到 {filename}: 原始偏移={local_header_offset}, 修正后偏移={local_offset}")
            
            try:
                # 下载完整的本地文件头（至少30字节）
                local_header = get_remote_range(url, local_offset, local_offset+29)
                if local_header[:4] != ZIP_LOCAL_HEADER:
                    raise ValueError(f"本地头签名无效: {local_header[:4].hex()}")
                
                # 验证文件名是否匹配
                name_len_local = struct.unpack('<H', local_header[26:28])[0]
                local_header = get_remote_range(url, local_offset, local_offset+29+name_len_local)
                name_local = local_header[30:30+name_len_local].decode('utf-8', 'ignore')
                if name_local != filename:
                    raise ValueError(f"本地头文件名不匹配: {name_local} vs {filename}")
                
                # 计算实际数据偏移
                extra_len_local = struct.unpack('<H', local_header[28:30])[0]
                data_offset = local_offset + 30 + name_len_local + extra_len_local
                print(f"有效载荷位置验证通过，数据起始于: {data_offset}")
                
                return data_offset, actual_uncomp_size
            except Exception as e:
                print(f"本地头验证失败: {str(e)}")
                print("尝试自动修正偏移量...")
                # 启发式搜索文件头
                search_start = max(0, local_offset - 1024)
                search_data = get_remote_range(url, search_start, local_offset + 1024)
                found_pos = search_data.find(ZIP_LOCAL_HEADER + filename.encode())
                if found_pos != -1:
                    corrected_offset = search_start + found_pos
                    print(f"发现修正后的文件头偏移: {corrected_offset}")
                    data_offset = corrected_offset + 30 + name_len_local + extra_len_local
                    return data_offset, actual_uncomp_size
                raise ValueError("自动修正失败，请检查ZIP文件完整性")
        
        pos += 46 + name_len + extra_len + comment_len
    
    raise ValueError(f"ZIP中未找到 {filename}")

def parse_payload_header(url, payload_offset):
    global block_size
    """精确解析payload.bin分区表（修复字节序和偏移问题）"""
    try:
        # 增加头部数据到512KB以应对大清单
        header_size = 512 * 1024
        header = get_remote_range(url, payload_offset, payload_offset + header_size - 1)
        
        # 验证基本格式（关键区域检查增强）
        if len(header) < 48 or header[:4] != b'CrAU':
            raise ValueError("无效的payload.bin格式，前4字节应为CrAU")

        # 修正版本号解析（基于官方格式文档）
        major_version = int.from_bytes(header[4:12], byteorder='big')
        
        print(f"解析Payload版本: v{major_version}")

        if major_version != 2:
            raise ValueError(f"仅支持v2格式，当前版本v{major_version}")

        # 修正清单大小解析（小端序）
        manifest_size = int.from_bytes(header[12:20], byteorder='big')
        metadata_signature_size = int.from_bytes(header[20:24], byteorder='big')
        
        # 计算分区表起始位置（官方标准计算方式）
        HEADER_FIXED_SIZE = 24  # magic(4) + version(8) + manifest_size(8) + metadata_sig_size(4)
        partitions_start = HEADER_FIXED_SIZE + manifest_size + metadata_signature_size
        
        print(f"清单大小: {manifest_size} | 签名大小: {metadata_signature_size}")
        print(f"预计分区表起始于: {partitions_start} (已下载:{len(header)}字节)")

        if partitions_start > len(header):
            needed_size = partitions_start + 1024
            raise ValueError(f"头部数据不足，请将header_size设置为至少{needed_size}字节")

        manifest = get_remote_range(url, payload_offset + 24, payload_offset + 24 + manifest_size - 1)
        dam = um.DeltaArchiveManifest()
        dam.ParseFromString(manifest)
        block_size = dam.block_size
        
        # 解析分区条目（严格遵循官方结构）
        partitions = dam.partitions

        if not partitions:
            raise ValueError("未找到有效分区，可能原因：数据不完整/格式变化")
            
        print(f"成功解析{len(partitions)}个分区")
        return partitions_start, partitions

    except Exception as e:
        print(f"解析失败: {str(e)}")
        if 'header' in locals():
            print("头部Hexdump关键区域（0x00-0x24）:")
            print("00000000:", header[:0x24].hex(' '))
            print("ASCII:", header[:0x24].decode('ascii', 'replace'))
        return None

def download_partition(url, partitions_offset, partition, output_file):
    """下载分区（支持断点续传）"""

    partition_size = sum((op.data_length for op in partition.operations))
    downloaded_full = 0
    temp_dir = f"{partition.partition_name}_download_tempfile"
    os.makedirs(temp_dir, exist_ok=True)
    
    for op in partition.operations:
        start = partitions_offset + op.data_offset
        end = start + op.data_length - 1
        output_file_op = f"{partition.partition_name}_download_tempfile/{output_file}.{op.data_offset}.op"
        # 检查已下载部分
        downloaded = 0
        if os.path.exists(output_file_op):
            downloaded = os.path.getsize(output_file_op)
            if downloaded >= op.data_length:
                downloaded_full += downloaded
                print(f"{partition.partition_name}-{op.data_offset} 已下载且完整")
                continue
        
        headers = {'Range': f'bytes={start+downloaded}-{end}'}
        mode = 'ab' if downloaded else 'wb'
        
        with requests.get(url, headers=headers, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(output_file_op, mode) as f:
                for chunk in r.iter_content(chunk_size=1024*1024):
                    if chunk:
                        f.write(chunk)
                        downloaded_full += len(chunk)
                        print(f"\r下载: {downloaded_full//1024//1024}/{partition_size//1024//1024} MB "
                            f"({downloaded_full*100/partition_size:.1f}%)", end='', flush=True)
    print()
    out_file = open(output_file, 'wb')
    downloaded = 0
    for op in partition.operations:
        output_file_op = f"{partition.partition_name}_download_tempfile/{output_file}.{op.data_offset}.op"
        
        with open(output_file_op, 'rb') as opf:
            op_data = opf.read()
            data_for_op(op, op_data, out_file)
            downloaded += op.data_length
            
            print(f"\r合并: {downloaded//1024//1024}/{partition_size//1024//1024} MB "
                            f"({downloaded*100/partition_size:.1f}%)", end='', flush=True)
        os.remove(output_file_op)
     
    print("\n下载完成")
    sleep(3)
    os.rmdir(temp_dir)    
    return True

def main():
    if len(sys.argv) < 3:
        print("Usage: python RemotePayloadExtractor.py <ZIP_URL> <PARTITION> [OUTPUT]")
        return
    
    zip_url = sys.argv[1]
    part_name = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else f"{part_name}.img"
    
    # try:
    print("正在分析ZIP结构...")
    file_size = int(requests.head(zip_url).headers['content-length'])
    
    cd_offset, cd_size = find_zip_structure(zip_url, file_size)
    print(f"中央目录: 偏移={cd_offset}, 大小={cd_size}")
    
    payload_offset, payload_size = find_file_in_zip(
        zip_url, cd_offset, cd_size, 'payload.bin')
    print(f"payload.bin位置: 偏移={payload_offset}, 大小={payload_size}")
    
    partitions_start, partitions = parse_payload_header(zip_url, payload_offset)
#        print("\n可用分区:" + ' '.join((p.partition_name for p in partitions)))
    for p in partitions:
        data_length = sum((op.data_length for op in p.operations))
        print(f"可用分区: {p.partition_name} ({data_length//1024//1024}MB)")
        
    target = next((p for p in partitions if p.partition_name == part_name), None)
    if not target:
        print(f"错误: 未找到分区 '{part_name}'")
        return
        
    data_length = sum((op.data_length for op in target.operations))
    print(f"下载分区: {target.partition_name} ({data_length//1024//1024}MB)")
    if download_partition(zip_url, payload_offset+partitions_start, target, output_file):
        print(f"成功保存到: {output_file}")
            
    # except Exception as e:
    #     print(f"错误: {repr(e)}")

def data_for_op(op, data, out_file):
    global block_size

    if op.data_sha256_hash:
        assert hashlib.sha256(data).digest() == op.data_sha256_hash, f"operation data {op.data_offset} hash mismatch"

    if op.type == op.REPLACE_XZ:
        dec = lzma.LZMADecompressor()
        data = dec.decompress(data)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.ZSTD:
        dec = zstandard.ZstdDecompressor().decompressobj()
        data = dec.decompress(data)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.REPLACE_BZ:
        dec = bz2.BZ2Decompressor()
        data = dec.decompress(data)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.REPLACE:
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.ZERO:
        for ext in op.dst_extents:
            out_file.seek(ext.start_block*block_size)
            out_file.write(b'\x00' * ext.num_blocks*block_size)
    else:
        print ("Unsupported type = %d" % op.type)
        sys.exit(-1)

    return data

if __name__ == "__main__":
    main()