#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server Info Retriever

이 모듈은 ~/.ssh/config 파일에 정의된 서버들에 대해 SSH로 접속하여,
디스크(/, /app, /data), CPU, 메모리 사용량 등의 정보를 수집하고
rich.Table을 이용해 콘솔에 출력하는 스크립트입니다.

- 새 로깅 스타일 적용:
  - 콘솔: WARNING 이상만 표시 + 오른쪽에 [파일명:라인번호] [시간]
  - 파일: INFO 이상 전부 기록 + 메시지 후미에 [파일명:라인번호]
  - paramiko, server_info의 INFO 로그는 파일에는 기록, 콘솔에는 표시 안 됨
  - Memory 헤더 적용 (/ Total, /app Total ... Memory)
"""

import os
import re
import getpass
import logging
import concurrent.futures
import paramiko

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler

# -----------------------------------------------------------------------------
# 환경 변수 로드
# -----------------------------------------------------------------------------
load_dotenv()

SSH_CONFIG_FILE = os.getenv("SSH_CONFIG_FILE", "~/.ssh/config_test")
SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "3"))
MAX_WORKER = int(os.getenv("MAX_WORKER", "30"))

# -----------------------------------------------------------------------------
# logs 디렉터리 생성
# -----------------------------------------------------------------------------
os.makedirs("logs", exist_ok=True)

# -----------------------------------------------------------------------------
# 로깅 설정
# -----------------------------------------------------------------------------
console = Console()

logger = logging.getLogger("server_info")
logger.setLevel(logging.INFO)  # 전체 로거 레벨: INFO 이상 처리

# 1) 콘솔 핸들러(RichHandler) - WARNING 이상만 표시
console_handler = RichHandler(
    rich_tracebacks=True,
    show_time=False,    # RichHandler가 기본적으로 표시하는 시간 비활성
    show_level=True,   # 레벨 표시 비활성
    show_path=True     # 파일 경로 비활성
)
console_handler.setLevel(logging.CRITICAL)

# - 콘솔 표시 형식: 메시지 끝에 [server_info.py:라인번호] [날짜/시간]
console_format_string = (
    "%(asctime)s | %(name)s | %(message)s "    
)
console_formatter = logging.Formatter(
    console_format_string,
    datefmt="%y/%m/%d %H:%M:%S"  # 원하는 날짜 포맷
)
console_handler.setFormatter(console_formatter)

# 2) 파일 핸들러(FileHandler) - INFO 이상을 logs/app.log에 기록
file_handler = logging.FileHandler("logs/app.log", mode='a', encoding='utf-8')
file_handler.setLevel(logging.INFO)

# - 파일 기록 형식: 메시지 끝에 [파일명:라인번호]
file_format_string = (
    "%(asctime)s | %(levelname)s | %(filename)s:%(lineno)d | %(message)s "
)
file_formatter = logging.Formatter(file_format_string, datefmt="%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(file_formatter)

# 로거에 핸들러 등록
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# 3) Paramiko 로그 레벨 조정: WARNING 이상만 콘솔 출력
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.client").setLevel(logging.CRITICAL)

# -----------------------------------------------------------------------------
# 유틸 함수
# -----------------------------------------------------------------------------
def color_percentage(value: str) -> str:
    """
    퍼센티지(숫자 %) 문자열을 받아서, 임계치에 따라 rich 텍스트 색상을 적용합니다.

    Args:
        value (str): "85%" 같은 퍼센티지 문자열 또는 "N/A" / "-" 등의 예외 문자열

    Returns:
        str: 색상이 적용된 문자열("[red]85%[/red]" 등) 또는 원본 문자열
    """
    if value in ["N/A", "-", None]:
        return value or "N/A"
    try:
        stripped = value.strip('%')
        percentage = float(stripped)
        if percentage >= 85:
            return f"[red]{value}[/red]"
        elif percentage >= 60:
            return f"[yellow]{value}[/yellow]"
        else:
            return f"[green]{value}[/green]"
    except ValueError:
        return value


def parse_memory_value(value: str) -> float:
    """
    메모리 수치를 Gi, Mi, Ki, G, M, K 등으로 표기했을 때,
    Gigabyte 단위로 변환해 주는 함수.

    Args:
        value (str): 예) "1.2Gi", "512Mi", "1024K" 등

    Returns:
        float: Gi 단위로 변환한 값
    """
    if value.endswith('Gi'):
        return float(value[:-2])
    elif value.endswith('Mi'):
        return float(value[:-2]) / 1024
    elif value.endswith('Ki'):
        return float(value[:-2]) / 1024 / 1024
    elif value.endswith('G'):
        return float(value[:-1])
    elif value.endswith('M'):
        return float(value[:-1]) / 1024
    elif value.endswith('K'):
        return float(value[:-1]) / 1024 / 1024
    else:
        # 숫자만 들어올 경우
        return float(value)

# -----------------------------------------------------------------------------
# SSH 처리 클래스
# -----------------------------------------------------------------------------
class ServerInfoRetriever:
    def __init__(self, hostname: str, username: str, private_key_path: str, port: int) -> None:
        self.hostname = hostname
        self.username = username
        self.private_key_path = private_key_path
        self.port = port
        self.ssh = self._establish_ssh_connection()

    def _establish_ssh_connection(self): # -> paramiko.SSHClient:
        try:
            private_key = paramiko.RSAKey(filename=self.private_key_path)
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.hostname,
                username=self.username,
                pkey=private_key,
                port=self.port,
                timeout=SSH_TIMEOUT
            )
            logger.info(f"SSH 연결 성공: {self.hostname}")
            return ssh
        except paramiko.SSHException as e:
            logger.exception(f"에러 발생: SSH connection failed for {self.hostname}: {e}")
            #console.print(f"[bold red]에러:[/bold red] SSH connection failed for {self.hostname}: {e}")
            return None
        except Exception as e:
            logger.exception(f"에러 발생: Failed to establish SSH connection for {self.hostname}: {e}")
            #console.print(f"[bold red]에러:[/bold red] Failed to establish SSH connection for {self.hostname}: {e}")
            return None

    def _execute_ssh_command(self, command: str) -> str:
        # if not self.ssh:
        #     return None
        # try:
        #     stdin, stdout, stderr = self.ssh.exec_command(command, get_pty=False)
        #     return stdout.read().decode('utf-8').strip()
        # except Exception as e:
        #     logger.error(f"Failed to execute command '{command}' on {self.hostname}: {e}")
        #     #console.print(f"[bold red]에러:[/bold red] 명령 실행 실패({self.hostname}): {command}, {e}")
        #     return None
        if not self.ssh:
            return None
        try:
            _, stdout, _ = self.ssh.exec_command(command, get_pty=False)
            raw_output = stdout.read().decode('utf-8', errors='replace')

            # 첫 글자로 배너로 판단할 문자들(예: '_', '|', ''') 정의
            banner_start_chars = ("_", "|", "'", "^", "-")

            filtered_lines = []
            for line in raw_output.split('\n'):
                # 공백 제거
                stripped_line = line.strip()

                # 만약 이 줄이 비어 있거나, 특정 문자들로 시작하면 배너라고 가정하고 스킵
                if not stripped_line:
                    continue
                if stripped_line[0] in banner_start_chars:
                    continue

                filtered_lines.append(stripped_line)

            filtered_output = "\n".join(filtered_lines)
            
            # 디버그용으로 확인
            logger.debug(f"[{self.hostname}] Command: {command}\nFiltered output:\n{filtered_output}")

            return filtered_output
        except Exception as e:
            logger.error(f"Failed to execute command '{command}' on {self.hostname}: {e}")
            return None
        

    def get_device_info(self): # -> tuple or None:
        if self.ssh is None:
            return None

        # 디스크 Usage
        df_root_output = self._execute_ssh_command('df -h /')
        df_app_output = self._execute_ssh_command('df -h /app')
        df_data_output = self._execute_ssh_command('df -h /data')

        # CPU
        cpu_num_output = self._execute_ssh_command('nproc')
        cpu_output = self._execute_ssh_command('top -bn1 | grep "Cpu(s)"')

        # 메모리
        memory_output = self._execute_ssh_command('free -h')

        # 기본 인터페이스 & IP
        default_interface = self._execute_ssh_command("sudo ip route | grep default | awk '{print $5}' | head -n 1")
        ip_output = None
        if default_interface:
            ip_output = self._execute_ssh_command(f"sudo ip addr show {default_interface} | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1")

        # 결과 검증
        if None in [
            df_root_output, df_app_output, df_data_output,
            cpu_num_output, cpu_output, memory_output, ip_output
        ]:
            logger.warning(f"정보 수집 실패: {self.hostname}")
            return None

        return (
            df_root_output,
            df_app_output,
            df_data_output,
            cpu_num_output,
            cpu_output,
            memory_output,
            ip_output
        )

    def close_connection(self) -> None:
        """
        SSH 연결 해제
        """
        if self.ssh:
            self.ssh.close()
            logger.info(f"SSH 연결 종료: {self.hostname}")

# -----------------------------------------------------------------------------
# SSH Config 파싱
# -----------------------------------------------------------------------------
def parse_ssh_config() -> list:
    """
    ~/.ssh/config 파일을 파싱하여 서버 리스트를 반환한다.

    Returns:
        list[dict]: 
            [
                {
                    "servername": <Host alias>,
                    "hostname": <실제 접속 호스트>,
                    "username": <사용자>,
                    "port": <포트>,
                    "private_key_path": <private key 경로>
                },
                ...
            ]
    """
    config_path = os.path.expanduser(SSH_CONFIG_FILE)
    ssh_config = paramiko.SSHConfig()

    try:
        with open(config_path, 'r', encoding='utf-8') as config_file:
            ssh_config.parse(config_file)
    except FileNotFoundError:
        logger.exception(f".ssh/config 파일을 찾을 수 없음: {config_path}")
        console.print(f"[bold red]에러:[/bold red] .ssh/config 파일을 찾을 수 없습니다: {config_path}")
        return []

    servers = []
    for host_info in ssh_config.get_hostnames():
        # '*'인 경우는 매칭 제외
        if '*' in host_info:
            continue
        config = ssh_config.lookup(host_info)

        # identityfile이 여러 개인 경우 첫 번째 경로만 사용
        identity_files = config.get("identityfile", [])
        private_key = identity_files[0] if identity_files else None

        # user가 없으면 현재 로그인한 사용자명 사용
        user = config.get("user", getpass.getuser())

        # 포트 설정
        port = config.get("port", 22)

        servers.append({
            "servername": host_info,
            "hostname": config.get("hostname"),
            "username": user,
            "port": int(port),
            "private_key_path": private_key
        })

    logger.info(f"ssh_config 파싱 완료 (총 {len(servers)}개 호스트)")
    return servers

# -----------------------------------------------------------------------------
# 서버 정보 수집 함수
# -----------------------------------------------------------------------------
def fetch_server_info(config: dict) -> tuple:
    """
    단일 서버에 대해 ServerInfoRetriever로 정보를 수집한 뒤 결과를 반환한다.

    Args:
        config (dict): SSH 접속 정보 (servername, hostname, username, port, private_key_path)

    Returns:
        tuple: (servername, hostname, ip_output,
                df_root_output, df_app_output, df_data_output,
                cpu_num_output, cpu_output, memory_output)
               실패 시 Connection Fail 표기
    """
    retriever = ServerInfoRetriever(
        config["hostname"],
        config["username"],
        config["private_key_path"],
        config["port"]
    )
    device_info = retriever.get_device_info()
    retriever.close_connection()

    if device_info is None:
        return (
            config['servername'],
            config['hostname'],
            "Connection Fail",
            "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
        )
    else:
        df_root_output, df_app_output, df_data_output, cpu_num_output, cpu_output, memory_output, ip_output = device_info
        return (
            config['servername'],
            config['hostname'],
            ip_output,
            df_root_output,
            df_app_output,
            df_data_output,
            cpu_num_output,
            cpu_output,
            memory_output
        )

# -----------------------------------------------------------------------------
# 결과 파싱
# -----------------------------------------------------------------------------
def parse_df_output(df_output: str) -> tuple:
    """
    df -h 명령 결과 문자열에서 총 용량, 사용 퍼센트만 파싱.

    Args:
        df_output (str): df -h 결과 문자열

    Returns:
        tuple: (total_capacity, usage_percentage)
    """
    total_capacity = '-'
    usage_percentage = '-'
    if not df_output:
        return total_capacity, usage_percentage

    lines = df_output.split('\n')
    for line in lines:
        if '/' in line:
            df_columns = re.split(r'\s+', line)
            if len(df_columns) >= 5:
                total_capacity = df_columns[1]
                usage_percentage = df_columns[4]
                break
    return total_capacity, usage_percentage


def parse_cpu_usage(cpu_output: str) -> str:
    """
    top -bn1 | grep "Cpu(s)" 결과에서 idle 값을 추출해 CPU 사용률(=100-idle)을 구함

    Args:
        cpu_output (str): "Cpu(s):  2.5 us,  1.0 sy, 96.5 id, ..." 형태의 문자열

    Returns:
        str: "15.0%" 형태의 CPU 사용률
    """
    if not cpu_output:
        return "N/A"
    cpu_output = cpu_output.replace(',', ' ')
    cpu_columns = re.split(r'\s+', cpu_output)
    try:
        idle_cpu = float(cpu_columns[7])
        usage = 100.0 - idle_cpu
        return f"{usage:.1f}%"
    except:
        return "N/A"


def parse_memory_info(memory_output: str) -> tuple:
    """
    free -h 결과에서 총 메모리, 메모리 사용 퍼센트 등을 파싱

    Args:
        memory_output (str): free -h 명령 결과 문자열

    Returns:
        tuple: (total_memory_str, memory_percentage_str)
    """
    if not memory_output:
        return ("N/A", "N/A")

    lines = memory_output.split('\n')
    try:
        # 보통 lines[1]이 Mem: ... 형태
        memory_columns = re.split(r'\s+', lines[1])
        total_memory_str = memory_columns[1]
        used_memory_str = memory_columns[2]

        total_memory = parse_memory_value(total_memory_str)
        used_memory = parse_memory_value(used_memory_str)

        if total_memory > 0:
            memory_percentage = (used_memory / total_memory) * 100
        else:
            memory_percentage = 0.0
        return (total_memory_str, f"{memory_percentage:.2f}%")
    except:
        return ("N/A", "N/A")

# -----------------------------------------------------------------------------
# 결과 출력
# -----------------------------------------------------------------------------
def display_server_info(results: list, headers: list) -> None:
    """
    서버 정보 결과를 rich.Table로 출력한다.

    Args:
        results (list): fetch_server_info를 통해 수집된 튜플들의 리스트
        headers (list): 컬럼 헤더
    """
    # 예시: [22, 15, 15, 7, 6, 8, 7, 9, 7, 4, 9, 8, 7]
    column_widths = [22, 15, 15, 7, 6, 8, 7, 9, 7, 4, 9, 8, 7]

    table = Table(title="서버 정보 결과", show_lines=False)
    for idx, header in enumerate(headers):
        table.add_column(header, width=column_widths[idx], no_wrap=True)

    sorted_result = sorted(results, key=lambda x: x[0])
    failed_servers = []

    for data in sorted_result:
        (servername, hostname, ip_output,
         df_root_output, df_app_output, df_data_output,
         cpu_num_output, cpu_output, memory_output) = data

        if ip_output == "Connection Fail":
            # 연결 실패
            root_total_capacity = root_percentage = "N/A"
            app_total_capacity = app_percentage = "N/A"
            data_total_capacity = data_percentage = "N/A"
            cpu_num = "N/A"
            cpu_usage = "N/A"
            total_memory_str = "N/A"
            memory_percentage = "N/A"
            ip_colored = f"[red]{ip_output}[/red]"
            failed_servers.append(data)
        else:
            # 디스크
            root_total_capacity, root_percentage = parse_df_output(df_root_output)
            app_total_capacity, app_percentage = parse_df_output(df_app_output)
            data_total_capacity, data_percentage = parse_df_output(df_data_output)

            # CPU
            cpu_num = cpu_num_output
            cpu_usage = parse_cpu_usage(cpu_output)

            # 메모리
            total_memory_str, memory_percentage = parse_memory_info(memory_output)

            # IP 색상
            ip_colored = f"[blue]{ip_output}[/blue]"

        # 색상 적용
        root_percentage_colored = color_percentage(root_percentage)
        app_percentage_colored = color_percentage(app_percentage)
        data_percentage_colored = color_percentage(data_percentage)
        cpu_usage_colored = color_percentage(cpu_usage)
        memory_percentage_colored = color_percentage(memory_percentage)

        table.add_row(
            servername,
            hostname,
            ip_colored,
            root_total_capacity,
            root_percentage_colored,
            app_total_capacity,
            app_percentage_colored,
            data_total_capacity,
            data_percentage_colored,
            str(cpu_num),
            cpu_usage_colored,
            total_memory_str,
            memory_percentage_colored
        )

    console.print(table)

    if failed_servers:
        console.print("\n[red]문제가 있는 서버 목록:[/red]")
        for fs in failed_servers:
            console.print(f"- {fs[0]} ({fs[1]})")

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
def main() -> None:
    """
    main 함수
    1) SSH Config 파싱
    2) ThreadPoolExecutor로 병렬 서버 정보 조회
    3) 결과 테이블 출력
    """
    logger.info("server_info 스크립트 시작")
    server_configs = parse_ssh_config()
    if not server_configs:
        logger.warning("서버 설정이 비어있어 종료합니다.")
        return

    # "Memory"로 헤더 변경
    headers = [
        "Server Name",
        "Access IP",
        "Internal IP",
        "/ Tot",
        "/ %",
        "/app Tot",
        "/app %",
        "/data Tot",
        "/data %",
        "vCPU",
        "CPU %",
        "Memory",
        "Mem %"
    ]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKER) as executor:
        future_to_server = {
            executor.submit(fetch_server_info, config): config for config in server_configs
        }
        for future in concurrent.futures.as_completed(future_to_server):
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                cfg = future_to_server[future]
                logger.exception(f"에러 발생: {cfg['servername']} 처리 중 오류: {e}")
                console.print(f"[bold red]에러:[/bold red] {cfg['servername']} 처리 중 오류: {e}")

    display_server_info(results, headers)
    logger.info("server_info 스크립트 완료")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(f"에러 발생: {e}")
        console.print(f"[bold red]에러:[/bold red] 스크립트 실행 중 예기치 못한 오류가 발생했습니다: {e}")
        exit(1)