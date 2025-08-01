# ICS Network Monitor 사용 가이드

## 개요

ICS Network Monitor는 TCPDUMP를 기반으로 한 네트워크 패킷 분석 도구로, ICS(산업제어시스템) 환경에서 편리한 네트워크 모니터링을 제공합니다.

## 주요 기능

### 1. HMI 설정 제어 기능
- **락 메커니즘**: 하나의 HMI에서만 설정 변경 가능
- **HMI1**: 새로운 설정 모드 추가 (C 키로 진입)
- **HMI2**: 기존 기능에 락 제어 통합 (L 키로 락 획득/해제)

### 2. 네트워크 패킷 분석 기능
- **실시간 패킷 캡처**: TCPDUMP 기반 실시간 모니터링
- **다양한 필터링**: Modbus, 보안, 프로토콜별 필터 제공
- **자동 분석**: 기본, Modbus, 보안 분석 지원
- **사전 정의된 프리셋**: 빠른 모니터링을 위한 설정 템플릿

## 설치 및 설정

### Docker 환경에서 실행

1. **컨테이너 시작**
```bash
cd ICSSIM/deployments
./init.sh
```

2. **네트워크 모니터 실행**
```bash
./network_monitor.sh
```

## HMI 설정 제어 사용법

### HMI1에서 설정 변경

1. **HMI1 컨테이너 접속**
```bash
./hmi1.sh
```

2. **설정 모드 진입**
- 메인 화면에서 `C` 키 입력
- 설정 락 자동 획득

3. **설정 변경**
- 1-3: 수치 설정 (Tank Level Min/Max, Bottle Level Max)
- 4-6: 모드 설정 (Valve, Engine 모드)
- E: 설정 모드 종료
- R: 락 시간 연장

### HMI2에서 설정 변경

1. **HMI2 컨테이너 접속**
```bash
./hmi2.sh
```

2. **설정 락 획득**
- `L` 키 입력으로 락 획득/해제

3. **설정 변경**
- 락 보유 시에만 1-6 번 메뉴 사용 가능
- 다른 HMI가 락을 보유한 경우 변경 불가

### 락 메커니즘 특징

- **자동 만료**: 10분 후 자동 해제
- **상호 배제**: 하나의 HMI에서만 설정 변경 가능
- **상태 표시**: 현재 락 상태 실시간 표시
- **파일 기반**: `storage/config_lock.json`에 상태 저장

## 네트워크 모니터링 사용법

### 1. 대화형 모드

```bash
python3 network_monitor_cli.py --interactive
```

**메뉴 옵션:**
- 1) 패킷 캡처 시작
- 2) 패킷 캡처 중지
- 3) 실행 중인 캡처 목록
- 4) PCAP 파일 분석
- 5) 사전 정의된 필터 보기
- 6) 빠른 캡처 프리셋

### 2. 명령행 모드

**패킷 캡처 시작:**
```bash
python3 network_monitor_cli.py --capture my_capture --filter "port 502" --duration 60
```

**PCAP 파일 분석:**
```bash
python3 network_monitor_cli.py --analyze capture.pcap --analysis-type modbus
```

**실행 중인 캡처 목록:**
```bash
python3 network_monitor_cli.py --list-captures
```

### 3. 사전 정의된 필터

| 필터 이름 | 필터 표현식 | 설명 |
|-----------|-------------|------|
| modbus_traffic | port 502 | Modbus 통신 |
| plc1_traffic | host 192.168.0.11 | PLC1 통신 |
| plc2_traffic | host 192.168.0.12 | PLC2 통신 |
| hmi_traffic | host 192.168.0.21 or host 192.168.0.22 | HMI 통신 |
| attacker_traffic | host 192.168.0.41 or host 192.168.0.42 or host 192.168.0.43 | 공격자 통신 |
| tcp_syn_scan | tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 | TCP SYN 스캔 |

### 4. 빠른 캡처 프리셋

1. **Modbus 트래픽 모니터링 (30초)**
2. **PLC1 트래픽 모니터링 (60초)**
3. **PLC2 트래픽 모니터링 (60초)**
4. **HMI 트래픽 모니터링 (60초)**
5. **공격자 트래픽 모니터링 (60초)**
6. **보안 스캔 탐지 (300초)**

## 분석 유형

### 1. 기본 분석 (Basic)
- 총 패킷 수
- 프로토콜 분포 (IP, TCP, UDP)
- 기본 통계 정보

### 2. Modbus 분석
- Modbus 패킷 수
- 통신 디바이스 목록
- 기능 코드 분석
- 의심스러운 활동 탐지

### 3. 보안 분석 (Security)
- 포트 스캔 탐지
- 비정상 트래픽 분석
- 보안 경고 생성
- 포트 활동 분석

## 파일 구조

```
logs/network_monitor/
├── network_monitor.log          # 모니터 로그
├── capture_20231201_143022.pcap # 캡처 파일
└── analysis_report_20231201_143055.json # 분석 보고서

storage/
└── config_lock.json            # 설정 락 상태
```

## Docker 환경에서의 사용

### 네트워크 모니터 스크립트 실행
```bash
cd deployments
./network_monitor.sh
```

### 컨테이너별 직접 접근
```bash
# HMI1에서 네트워크 모니터링
docker exec -it hmi1 python3 network_monitor_cli.py --interactive

# HMI2에서 네트워크 모니터링
docker exec -it hmi2 python3 network_monitor_cli.py --interactive
```

## 실사용 예시

### 1. Modbus 통신 모니터링
```bash
# 30초간 Modbus 트래픽 캡처
python3 network_monitor_cli.py --capture modbus_test --filter "port 502" --duration 30

# 캡처 완료 후 분석
python3 network_monitor_cli.py --analyze logs/network_monitor/modbus_test_*.pcap --analysis-type modbus
```

### 2. 보안 스캔 탐지
```bash
# 5분간 SYN 스캔 탐지
python3 network_monitor_cli.py --capture security_scan --filter "tcp[tcpflags] & tcp-syn != 0" --duration 300

# 보안 분석 수행
python3 network_monitor_cli.py --analyze logs/network_monitor/security_scan_*.pcap --analysis-type security
```

### 3. PLC 통신 분석
```bash
# PLC1과 PLC2 간 통신 모니터링
python3 network_monitor_cli.py --capture plc_comm --filter "host 192.168.0.11 or host 192.168.0.12" --duration 120
```

## 주의사항

1. **권한**: tcpdump 실행을 위해 root 권한 또는 적절한 네트워크 권한 필요
2. **디스크 공간**: 장시간 캡처 시 충분한 디스크 공간 확보
3. **성능**: 대용량 트래픽 환경에서는 필터 사용 권장
4. **보안**: 캡처 파일에는 민감한 정보가 포함될 수 있음

## 문제 해결

### tcpdump 권한 오류
```bash
# Docker 컨테이너에서 privileged 모드 확인
docker-compose.yml에서 privileged: true 설정 확인
```

### 네트워크 인터페이스 확인
```bash
# 사용 가능한 인터페이스 목록
ip link show
```

### 캡처 파일 위치 확인
```bash
# 로그 디렉토리 확인
ls -la logs/network_monitor/
```

## 추가 기능

### 실시간 분석 콜백
사용자 정의 실시간 분석 함수를 작성하여 패킷 캡처 중 실시간 처리 가능

### 사용자 정의 필터
복잡한 네트워크 환경에 맞는 사용자 정의 필터 표현식 작성 가능

### 분석 보고서 자동화
JSON 형태의 분석 보고서를 다른 시스템과 연동하여 자동화된 보안 모니터링 구축 가능