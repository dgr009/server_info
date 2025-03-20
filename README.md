# SSH 서버 정보 조회 스크립트

## 개요
이 스크립트는 `~/.ssh/config` 파일에서 서버 목록을 읽고, 각 서버에 SSH 접속하여 CPU, 메모리, 디스크 사용량 등의 정보를 수집한 후 터미널에 보기 좋게 출력하는 기능을 수행합니다.

## 주요 기능
- **서버 목록 자동 추출**: `~/.ssh/config`에서 SSH 접속 가능한 서버 정보를 자동으로 가져옵니다.
- **SSH 접속 및 정보 조회**: 병렬로 SSH 접속하여 서버의 리소스 상태(CPU, 메모리, 디스크 등)를 가져옵니다.
- **컬러 및 정렬된 출력**: 가독성을 높이기 위해 ANSI 컬러를 적용하여 서버 상태를 시각적으로 표현합니다.

## 설치 및 실행 방법
### 1. 필요한 패키지 설치
```bash
pip install paramiko
```

### 2. 실행 방법
```bash
python script.py
```

## SSH 설정 요구사항
이 스크립트는 `~/.ssh/config` 파일을 기반으로 동작하므로, 해당 파일에 SSH 접속 정보가 등록되어 있어야 합니다. 예제:
```ini
Host my-server
    HostName 192.168.1.10
    User ubuntu
    Port 22
    IdentityFile ~/.ssh/my-key.pem
```

## 환경 변수
| 환경 변수               | 기본값            | 설명             |
|-----------------------|-----------------|-----------------|
| `SSH_CONFIG_FILE`     | `~/.ssh/config` | SSH 설정 파일 경로 |
| `SSH_TIMEOUT`         | 3               | SSH TimeOut 시간 |

## 상세 기능 설명
### 1. SSH 설정 파일 파싱 (`parse_ssh_config()`)
- `~/.ssh/config`에서 호스트 정보를 읽어와 서버 목록을 생성합니다.
- `hostname`, `user`, `port`, `identityfile` 정보를 추출합니다.

### 2. 병렬 SSH 접속 및 서버 정보 수집 (`fetch_server_info()`)
- `paramiko`를 이용해 병렬로 각 서버에 접속합니다.
- CPU 개수, 사용률, 메모리 상태, 디스크 사용량을 가져옵니다.

### 3. 가독성을 위한 컬러 출력 (`display_server_info()`)
- CPU 및 메모리 사용량을 기준으로 색상을 적용하여 한눈에 상태를 확인할 수 있도록 합니다.
- 서버명을 기준으로 정렬하여 출력합니다.

## 실행 예시
```bash
python script.py
```

출력 예시:
```
Server Name       | Access IP      | Internal IP    | / Tot  | / %   | /app Tot | /app % | /data Tot | /data % | vCPU | CPU Usage | Total Mem | Mem %  
-------------------------------------------------------------------------------------------
my-server        | 192.168.1.10   | 10.0.0.5      | 100G   | 40%   | 200G     | 60%   | 500G      | 80%   | 4    | 25.0%     | 16G       | 50%   
...
```

## 주의사항
- 서버에 SSH 접속할 수 있는 권한이 있어야 합니다.
- `.ssh/config`에 IdentityFile이 명시되지 않은 경우 기본 SSH 키가 사용됩니다.
- 많은 서버를 조회할 경우 병렬 실행으로 인해 서버 부하가 발생할 수 있습니다.
- **Verification Code (2MFA)가 동작하는 서버가 config 파일에 포함될 경우 정상적인 작동이 불가능합니다.**

## 개선 가능 사항
- JSON 또는 CSV 형식의 출력 지원
- Slack/Webhook을 통한 서버 상태 알림
- SSH 비밀번호 인증 지원 (현재는 키 기반 인증만 지원)

## 라이선스
MIT License

