import concurrent.futures
import paramiko
import re
import os

# ANSI escape codes for colors
RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BLUE = "\033[34m"
CYAN = "\033[36m"

# 색상 코드를 제거한 텍스트의 길이를 반환하는 함수
def text_length(text):
    return len(re.sub(r'\033\[\d+m', '', text))

# 색상 코드를 포함한 텍스트를 주어진 너비에 맞게 패딩하는 함수
def pad_text(text, width):
    text_len = text_length(text)
    padding = width - text_len
    return text + ' ' * padding

class ServerInfoRetriever:
    def __init__(self, hostname, username, private_key_path, port):
        self.hostname = hostname
        self.username = username
        self.private_key_path = private_key_path
        self.port = port
        self.ssh = self._establish_ssh_connection()

    def _establish_ssh_connection(self):
        try:
            private_key = paramiko.RSAKey(filename=self.private_key_path)
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.hostname, username=self.username, pkey=private_key, port=self.port, timeout=4)
            return ssh
        except paramiko.ssh_exception.SSHException as e:
            print(f"SSH connection failed for {self.hostname}: {e}")
            return None
        except Exception as e:
            print(f"Failed to establish SSH connection for {self.hostname}: {e}")
            return None

    def _execute_ssh_command(self, command):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            return stdout.read().decode('utf-8').strip()
        except Exception as e:
            print(f"Failed to execute command '{command}' on {self.hostname}: {e}")
            return None

    def get_device_info(self):
        if self.ssh is None:
            return None

        df_root_output = self._execute_ssh_command('df -h /')
        df_app_output = self._execute_ssh_command('df -h /app')
        df_data_output = self._execute_ssh_command('df -h /data')
        cpu_output = self._execute_ssh_command('top -bn1 | grep "Cpu(s)"')
        memory_output = self._execute_ssh_command('free -h')
        default_interface = self._execute_ssh_command("sudo ip route | grep default | awk '{print $5}' | head -n 1")
        ip_output = self._execute_ssh_command(f"sudo ip addr show {default_interface} | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1")

        if None in [df_root_output, df_app_output, df_data_output, cpu_output, memory_output, ip_output]:
            print(f"Error retrieving information for server: {self.hostname}")
            return None

        return df_root_output, df_app_output, df_data_output, cpu_output, memory_output, ip_output

    def close_connection(self):
        if self.ssh:
            self.ssh.close()

def parse_ssh_config():
    config_path = os.path.expanduser("~/.ssh/config_server")
    ssh_config = paramiko.SSHConfig()
    with open(config_path) as config_file:
        ssh_config.parse(config_file)

    servers = []
    for host_info in ssh_config.get_hostnames():
        if '*' in host_info:
            continue
        config = ssh_config.lookup(host_info)
        servers.append({
            "servername": host_info,
            "hostname": config.get("hostname"),
            "username": config.get("user", os.getlogin()),
            "port": config.get("port"),
            "private_key_path": config.get("identityfile", [])[0] if config.get("identityfile") else None
        })
    return servers

def fetch_server_info(config):
    retriever = ServerInfoRetriever(config["hostname"], config["username"], config["private_key_path"], config["port"])
    device_info = retriever.get_device_info()
    retriever.close_connection()

    if device_info is None:
        return config['servername'], config['hostname'], "Connection Fail", "N/A", "N/A", "N/A", "N/A", "N/A"
    else:
        df_root_output, df_app_output, df_data_output, cpu_output, memory_output, ip_output = device_info
        return config['servername'], config['hostname'], ip_output, df_root_output, df_app_output, df_data_output, cpu_output, memory_output

def color_percentage(value):
    if value == "N/A" or value == "-":
        return value
    try:
        percentage = float(value.strip('%'))
        if percentage >= 85:
            return f"{RED}{value}{RESET}"
        elif percentage >= 60:
            return f"{YELLOW}{value}{RESET}"
        else:
            return f"{GREEN}{value}{RESET}"
    except ValueError:
        return value

def display_server_info(results, headers):
    # 사용자가 원래 넣어놓은 열 너비를 유지
    widths = [22, 15, 15, 7, 7, 7, 8, 8, 8, 9, 9, 7, 9, 12, 11, 11, 9]
    header_format = " | ".join([f"{{:<{width}}}" for width in widths])
    
    # 헤더에 청록색 적용
    header_line = f"{CYAN}" + header_format.format(*headers) + f"{RESET}"
    print(header_line)
    print("-" * (sum(widths) + 3 * (len(widths) - 1)))

    sorted_result = sorted(results, key=lambda x: x[0])

    for data in sorted_result:
        servername, hostname, ip_output, df_root_output, df_app_output, df_data_output, cpu_output, memory_output = data

        if ip_output == "Connection Fail":
            root_total_capacity = root_current_capacity = root_percentage = "N/A"
            app_total_capacity = app_current_capacity = app_percentage = "N/A"
            data_total_capacity = data_current_capacity = data_percentage = "N/A"
            cpu_usage = "N/A"
            total_memory_str = used_memory_str = free_memory_str = "N/A"
            memory_percentage = "N/A"
            ip_output_colored = f"{RED}{ip_output}{RESET}"
        else:
            # Extracting disk information
            root_total_capacity = root_current_capacity = root_percentage = '-'
            app_total_capacity = app_current_capacity = app_percentage = '-'
            data_total_capacity = data_current_capacity = data_percentage = '-'

            df_lines = df_root_output.split('\n')
            for line in df_lines:
                if '/' in line:
                    df_columns = re.split('\s+', line)
                    if len(df_columns) >= 5:
                        root_total_capacity = df_columns[1]
                        root_current_capacity = df_columns[2]
                        root_percentage = df_columns[4]

            df_lines = df_app_output.split('\n')
            for line in df_lines:
                if '/' in line:
                    df_columns = re.split('\s+', line)
                    if len(df_columns) >= 5:
                        app_total_capacity = df_columns[1]
                        app_current_capacity = df_columns[2]
                        app_percentage = df_columns[4]

            df_lines = df_data_output.split('\n')
            for line in df_lines:
                if '/' in line:
                    df_columns = re.split('\s+', line)
                    if len(df_columns) >= 5:
                        data_total_capacity = df_columns[1]
                        data_current_capacity = df_columns[2]
                        data_percentage = df_columns[4]

            # Extracting CPU information
            cpu_columns = re.split('\s+', cpu_output)
            cpu_usage = cpu_columns[1] + '%'

            # 메모리 값 파싱 함수
            def parse_memory_value(value):
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
                    return float(value)

            # Extracting memory information
            memory_lines = memory_output.split('\n')
            memory_columns = re.split('\s+', memory_lines[1])
            total_memory_str = memory_columns[1]
            used_memory_str = memory_columns[2]
            free_memory_str = memory_columns[3]

            total_memory = parse_memory_value(total_memory_str)
            used_memory = parse_memory_value(used_memory_str)

            # 메모리 사용량 퍼센트 계산
            if total_memory > 0:
                memory_percentage = (used_memory / total_memory) * 100
            else:
                memory_percentage = 0
            memory_percentage = f"{memory_percentage:.2f}%"

            # IP 주소에 파란색 적용
            ip_output_colored = f"{BLUE}{ip_output}{RESET}"

        # 색상 적용
        root_percentage_colored = color_percentage(root_percentage)
        app_percentage_colored = color_percentage(app_percentage)
        data_percentage_colored = color_percentage(data_percentage)
        memory_percentage_colored = color_percentage(memory_percentage)
        cpu_usage_colored = color_percentage(cpu_usage)

        # 패딩 적용하여 열 너비 맞춤
        data_line = " | ".join([
            pad_text(servername, widths[0]),
            pad_text(hostname, widths[1]),
            pad_text(ip_output_colored, widths[2]),
            pad_text(root_total_capacity, widths[3]),
            pad_text(root_current_capacity, widths[4]),
            pad_text(root_percentage_colored, widths[5]),
            pad_text(app_total_capacity, widths[6]),
            pad_text(app_current_capacity, widths[7]),
            pad_text(app_percentage_colored, widths[8]),
            pad_text(data_total_capacity, widths[9]),
            pad_text(data_current_capacity, widths[10]),
            pad_text(data_percentage_colored, widths[11]),
            pad_text(cpu_usage_colored, widths[12]),
            pad_text(total_memory_str, widths[13]),
            pad_text(used_memory_str, widths[14]),
            pad_text(free_memory_str, widths[15]),
            pad_text(memory_percentage_colored, widths[16])
        ])
        print(data_line)

    failed_servers = [data for data in results if data[2] == "Connection Fail"]
    if failed_servers:
        print(f"\n{RED}문제가 있는 서버 목록:{RESET}")
        for server in failed_servers:
            print(f"- {server[0]} ({server[1]})")

def main():
    server_configs = parse_ssh_config()
    headers = ["Server Name", "Host Name", "Internal IP", "/ Tot", "/ Cur", "/ %", '/app Tot', '/app Cur', '/app %', '/data Tot', '/data Cur', '/data %', "CPU Usage", "Total Memory", "Used Memory", "Free Memory", "Memory %"]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_server = {executor.submit(fetch_server_info, config): config for config in server_configs}
        results = []
        for future in concurrent.futures.as_completed(future_to_server):
            results.append(future.result())
    
    display_server_info(results, headers)

if __name__ == "__main__":
    main()