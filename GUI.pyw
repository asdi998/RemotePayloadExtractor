# gui.py
import threading
import time
import PySimpleGUI as sg
from RemotePayloadExtractor import (
    create_retry_session,
    find_zip_structure,
    find_file_in_zip,
    parse_payload_header,
    download_partition,
    convert_bytes,
    download_stats,
    stop_event,
)

# ========== GUI配置 ==========
sg.theme("LightGrey1")
TABLE_HEADERS = ["分区名称", "镜像大小", "下载大小"]
REFRESH_INTERVAL = 500  # 进度刷新间隔(ms)
PROGRESS_UPDATE_INTERVAL = 0.5  # 进度更新间隔(秒)

# ========== 全局状态 ==========
current_session = None
current_partitions = []
current_payload_offset = 0
current_partitions_start = 0
current_block_size = 4096
is_downloading = False
stop_monitor = threading.Event()  # 新增监控停止事件


# ========== GUI布局 ==========
def create_window():
    layout = [
        [
            sg.Text("固件URL:"),
            sg.Input(key="-URL-", size=(50, 1), enable_events=True),
            sg.Button("获取分区", key="-FETCH-"),
        ],
        [
            sg.Table(
                [],
                headings=TABLE_HEADERS,
                key="-PARTITIONS-",
                auto_size_columns=False,
                col_widths=[20, 15, 15],
                justification="left",
                select_mode=sg.TABLE_SELECT_MODE_BROWSE,
                expand_x=True,
            )
        ],
        [
            sg.ProgressBar(100, size=(40, 20), key="-PROGRESS-", expand_x=True),
            sg.VerticalSeparator(),
            sg.Column(
                [
                    [sg.Text("速度:", size=(8, 1)), sg.Text("0 B/s", key="-SPEED-")],
                    [sg.Text("剩余时间:", size=(8, 1)), sg.Text("--", key="-ETA-")],
                    [
                        sg.Text("已用时间:", size=(8, 1)),
                        sg.Text("0.0s", key="-ELAPSED-"),
                    ],
                ]
            ),
        ],
        [
            sg.Button("下载", key="-DOWNLOAD-", disabled=True),
            sg.Button("取消", key="-CANCEL-"),
            sg.StatusBar("就绪", key="-STATUS-", expand_x=True),
        ],
    ]
    return sg.Window("远程分区下载工具", layout, finalize=True, resizable=True)


# ========== 后台任务 ==========
def fetch_partitions_task(window, url):
    global current_session, current_partitions, current_payload_offset, current_partitions_start, current_block_size

    try:
        window.write_event_value("-STATUS-", "正在初始化会话...")
        session = create_retry_session()
        current_session = session

        window.write_event_value("-STATUS-", "获取文件大小...")
        response = session.head(url, allow_redirects=True)
        if "Content-Length" not in response.headers:
            raise ValueError("无法获取文件大小")
        file_size = int(response.headers["Content-Length"])

        window.write_event_value("-STATUS-", "解析ZIP结构...")
        cd_offset, cd_size = find_zip_structure(url, file_size, session)

        window.write_event_value("-STATUS-", "定位payload.bin...")
        payload_offset, payload_size = find_file_in_zip(
            url, cd_offset, cd_size, "payload.bin", session
        )

        window.write_event_value("-STATUS-", "解析分区信息...")
        partitions_start, partitions, block_size = parse_payload_header(
            url, payload_offset, session
        )

        # 更新全局参数
        current_payload_offset = payload_offset
        current_partitions_start = partitions_start
        current_block_size = block_size
        current_partitions = partitions

        # 生成表格数据
        table_data = [
            [
                p.partition_name,
                convert_bytes(p.new_partition_info.size),
                convert_bytes(sum(op.data_length for op in p.operations)),
            ]
            for p in partitions
        ]

        window.write_event_value("-UPDATE-TABLE-", table_data)
        window.write_event_value("-STATUS-", "就绪 | 选择分区后点击下载")

    except Exception as e:
        window.write_event_value("-ERROR-", f"获取分区失败: {str(e)}")


def download_task(window, url, partition_name, output_file):
    global current_payload_offset, current_partitions_start, current_block_size, is_downloading
    global stop_monitor  # 新增全局声明

    try:
        stop_monitor.clear()  # 重置监控停止标志
        start_time = time.time()
        last_update = start_time

        # 查找目标分区
        target = next(
            (p for p in current_partitions if p.partition_name == partition_name), None
        )
        if not target:
            raise ValueError(f"分区 {partition_name} 不存在")

        # 初始化进度
        with download_stats["lock"]:
            download_stats["total"] = sum(op.data_length for op in target.operations)
            download_stats["downloaded"] = 0
            download_stats["history"].clear()

        window.write_event_value("-STATUS-", f"开始下载 {partition_name}...")

        # 启动下载线程
        download_thread = threading.Thread(
            target=download_partition,
            args=(
                url,
                current_payload_offset + current_partitions_start,
                target,
                output_file,
                current_session,
                current_block_size,
            ),
            daemon=True,
        )
        download_thread.start()

        # 实时进度监控循环（新增双重停止检查）
        while download_thread.is_alive() and not stop_monitor.is_set():
            time.sleep(PROGRESS_UPDATE_INTERVAL)

            # 强制终止检查
            if stop_event.is_set():
                stop_monitor.set()
                break

            with download_stats["lock"]:
                current = download_stats["downloaded"]
                total = download_stats["total"]
                history = download_stats["history"].copy()

            # 计算下载速度
            now = time.time()
            valid_history = [h for h in history if h[0] > now - 3]
            if len(valid_history) >= 2:
                time_diff = valid_history[-1][0] - valid_history[0][0]
                bytes_diff = sum(h[1] for h in valid_history)
                speed = int(bytes_diff / max(time_diff, 0.001))
            else:
                speed = 0

            # 发送进度更新事件
            window.write_event_value(
                "-PROGRESS-UPDATE-",
                {
                    "progress": current / total * 100 if total else 0,
                    "speed": speed,
                    "elapsed": time.time() - start_time,
                    "remaining": (total - current) / speed if speed > 0 else 0,
                },
            )

        # 强制终止逻辑
        if stop_monitor.is_set():
            download_thread.join(0.5)  # 等待500ms
            if download_thread.is_alive():
                window.write_event_value("-STATUS-", "下载已终止")
                stop_event.set()  # 确保原始停止事件同步
        else:
            window.write_event_value("-STATUS-", "下载完成")

        # 最终状态更新
        window.write_event_value(
            "-PROGRESS-UPDATE-",
            {
                "progress": 100 if not stop_monitor.is_set() else 0,
                "speed": 0,
                "elapsed": time.time() - start_time,
                "remaining": 0,
            },
        )

    except Exception as e:
        window.write_event_value("-ERROR-", f"下载失败: {str(e)}")
    finally:
        stop_monitor.set()
        is_downloading = False
        window.write_event_value("-ENABLE-BUTTONS-", True)


# ========== 事件循环 ==========
def main():
    global is_downloading
    window = create_window()

    while True:
        event, values = window.read(timeout=REFRESH_INTERVAL)

        if event == sg.WIN_CLOSED:
            stop_event.set()
            break

        elif event == "-URL-":
            window["-PARTITIONS-"].update([])
            window["-DOWNLOAD-"].update(disabled=True)

        elif event == "-FETCH-":
            url = values["-URL-"].strip()
            if not url.startswith(("http://", "https://")):
                sg.popup_error("URL必须以http://或https://开头")
                continue
            window["-STATUS-"].update("正在获取分区信息...")
            threading.Thread(
                target=fetch_partitions_task, args=(window, url), daemon=True
            ).start()

        elif event == "-UPDATE-TABLE-":
            window["-PARTITIONS-"].update(values[event])
            window["-DOWNLOAD-"].update(disabled=False)

        elif event == "-DOWNLOAD-":
            if is_downloading:
                sg.popup_error("当前正在下载中，请等待完成")
                continue
            if not window["-PARTITIONS-"].SelectedRows:
                sg.popup_error("请先在表格中选择一个分区")
                continue

            selected_row = window["-PARTITIONS-"].SelectedRows[0]
            table_data = window["-PARTITIONS-"].get()

            if selected_row >= len(table_data):
                sg.popup_error("无效的选择")
                continue

            partition_name = table_data[selected_row][0]
            output_file = sg.popup_get_file(
                "保存文件",
                save_as=True,
                default_extension=".img",
                file_types=(("镜像文件", "*.img"), ("所有文件", "*.*")),
                default_path=f"{partition_name}.img",
            )

            if output_file:
                is_downloading = True
                window["-DOWNLOAD-"].update(disabled=True)
                window["-FETCH-"].update(disabled=True)
                threading.Thread(
                    target=download_task,
                    args=(window, values["-URL-"], partition_name, output_file),
                    daemon=True,
                ).start()

        elif event == "-CANCEL-":
            stop_monitor.set()  # 新增监控停止标志
            stop_event.set()  # 原始停止标志
            is_downloading = False
            window["-DOWNLOAD-"].update(disabled=False)
            window["-FETCH-"].update(disabled=False)
            window["-STATUS-"].update("下载已取消")

        elif event == "-PROGRESS-UPDATE-":
            data = values[event]
            window["-PROGRESS-"].update(data["progress"])
            window["-SPEED-"].update(f"{convert_bytes(data['speed'])}/s")
            window["-ELAPSED-"].update(f"{data['elapsed']:.1f}s")
            window["-ETA-"].update(
                f"{data['remaining']:.1f}s" if data["remaining"] > 0 else "--"
            )

        elif event == "-STATUS-":
            if "下载完成" in values[event]:
                is_downloading = False
                window["-DOWNLOAD-"].update(disabled=False)
                window["-FETCH-"].update(disabled=False)
            window["-STATUS-"].update(values[event])

        elif event == "-ERROR-":
            sg.popup_error(values[event])
            is_downloading = False
            window["-DOWNLOAD-"].update(disabled=False)
            window["-FETCH-"].update(disabled=False)
            window["-STATUS-"].update("错误发生")

        elif event == "-ENABLE-BUTTONS-":
            window["-DOWNLOAD-"].update(disabled=not values[event])
            window["-FETCH-"].update(disabled=not values[event])

    window.close()


if __name__ == "__main__":
    main()
