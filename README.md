# Payload分区提取工具
```
用法: RemotePayloadExtractor.py [-h] [-o OUTPUT] [-t THREADS] [-f] source [name]

positional arguments:
  source                ZIP文件URL或本地路径
  name                  要提取的分区名称或文件名（可选）

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        输出文件名（可选）
  -t THREADS, --threads THREADS
                        下载线程数，默认值 8
  -f, --force-file      强制作为文件提取而非分区

使用示例:
  1. 列出分区: python script.py https://example.com/update.zip
     或本地文件: python script.py /path/to/update.zip
  2. 下载分区: python script.py https://example.com/update.zip boot
     或本地文件: python script.py /path/to/update.zip boot
  3. 下载文件: python script.py https://example.com/update.zip payload.bin
  4. 指定输出: python script.py https://example.com/update.zip system -o system.img
  5. 多线程下载: python script.py https://example.com/update.zip vendor -t 16
```
