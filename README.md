
# ICSSIM
This is the ICSSIM source code and user manual for simulating industrial control system testbed for cybersecurity experiments.

The ICSSIM framework enables cyber threats and attacks to be investigated and mitigated by building a virtual ICS security testbed customized to suit their needs. As ICSSIM runs on separate private operating system kernels, it provides realistic network emulation and runs ICS components on Docker container technology. 

ICSSIM can also be used to simulate any other open-loop controlling process, such as bottle filling, and allows us to build a testbed for any open-loop controlling process.

# Sample Bottle Filling Factory
A water tank repository is used to fill bottles during the bottle-filling factory control process. The below figure shows the overall scenario including process and hardware. The proposed control process consists of two main hardware zones, each managed by a standalone PLC, called PLC-1 and PLC-2. The water tank and valves are controlled by PLC-1. The conveyor belts are controlled by PLC-2 to switch out filled bottles with empty ones.

![The Sample bottle filling factory](Images/physical_process.png)
An overview of the bottle filling factory network architecture is presented below. In the proposed network architecture, the first three layers of the Purdue reference architecture are realized. In Docker container technology, shared memory is used to implement the hard wired connection between Tiers 1 and 2. To simulate the network between Tiers 2 and 3, a Local Area Network (LAN) is created in a simulation environment. The attacker is also assumed to have access to this network as a malicious HMI, therefore we consider this node as an additional attacker in this architecture.


![Network architecture for the sample bottle filling plant](Images/sample_architecture.png)

# Run a Sample Bottle Filling Factory

## Run in Docker container Environement

### Pre steps
Make sure that you have already installed the following applications and tools. 

* git
* Docker
* Docker-Compose

### Getting ICSSIM and the sample project
Clone The probject into your local directory using following git command.
```
git clone https://github.com/AlirezaDehlaghi/ICSSIM ICSSIM
```

check the file [Configs.py](src/Configs.py) and make sure that EXECUTION_MODE varibale is set to EXECUTION_MODE_DOCKER as follow:
```
EXECUTION_MODE = EXECUTION_MODE_DOCKER
```

### Running the sample project 
Run the sample project using the prepared script 
[init.sh](deployments/init.sh)
```
cd ICSSIM/deployments
./init.sh
```
### Check successful running
If *init.sh* commands runs to the end, it will show the status of all containers. In the case that all containers are 'Up', then project is running successfully.
You could also see the status of containers with following command:
```
sudo docker-compose ps
```

### Operating the control system and apply cyberattacks
In the directory [deployments](deployments/) there exist some scripts such as [hmi1.sh](deployments/hmi1.sh), [hmi2.sh](deployments/hmi2.sh) or [attacker.sh](deployments/attacker.sh) which can attach user to the container.

## Run in GNS3
To run the ICSSIM and the sample Bottle Filling factory clone the prject and use the portable GNS3 file to create a new project in GNS3.

### Getting ICSSIM and the sample project
Clone The probject into your local directory using following git command.
```
git clone https://github.com/AlirezaDehlaghi/ICSSIM ICSSIM
```

### Import Project in GNS3
Import the portable project ([deployments/GNS3/ICSSIM-GNS3-Portable.gns3project](deployments/GNS3/ICSSIM-GNS3-Portable.gns3project)) using menu **File->Import Portable Project**

## RUN as a single Python project

### Pre steps
Make sure that you have already installed the following applications and tools. 

* git
* Python
* pip

Make sure that you installed required packages: pyModbusTCP, memcache
```
pip install pyModbusTCP
pip install memcache

```


### Getting ICSSIM and the sample project
Clone The probject into your local directory using following git command.
```
git clone https://github.com/AlirezaDehlaghi/ICSSIM ICSSIM
```

check the file [Configs.py](src/Configs.py) and make sure that EXECUTION_MODE varibale is set to EXECUTION_MODE_DOCKER as follow:
```
EXECUTION_MODE = EXECUTION_MODE_LOCAL
```

### Running the sample project 
Run the sample project using the running start.py
```
cd ICSSIM/src
python3 start.py
```

# PCAP Analyzer for Modbus/TCP, TCP, and MDNS Protocols

이 도구는 .pcap 파일을 분석하여 네트워크 패킷 정보를 CSV 파일로 추출하고, Modbus/TCP 프로토콜의 쿼리-응답 분석을 수행합니다.

## 주요 기능

1. **개별 패킷 분석**: 모든 네트워크 패킷의 상세 정보를 CSV로 저장
2. **Modbus/TCP 트랜잭션 분석**: 쿼리-응답 쌍을 매칭하여 응답 시간 분석
3. **네트워크 행위 분석**: 전체적인 네트워크 통신 패턴 분석 리포트

## 필요 사항

- Python 3.6 이상
- Windows 환경 (개발 목적)

## 설치 방법

1. 필요한 패키지 설치:
```bash
pip install -r requirements.txt
```

또는 개별 설치:
```bash
pip install scapy
```

## 사용 방법

### 기본 사용법
```bash
python pcap_analyzer.py your_file.pcap
```

### 출력 디렉토리 지정
```bash
python pcap_analyzer.py your_file.pcap -o custom_output_folder
```

### 도움말
```bash
python pcap_analyzer.py -h
```

## 출력 파일

분석 완료 후 다음 파일들이 생성됩니다:

### 1. network_packets.csv
모든 패킷의 개별 정보:
- 패킷 번호, 타임스탬프, 프로토콜
- 소스/목적지 IP 및 포트
- MAC 주소
- TCP 플래그, 시퀀스 번호, ACK 번호
- 페이로드 크기 및 16진수 데이터
- Modbus/TCP 패킷 여부 및 상세 정보

### 2. modbus_transactions.csv
Modbus/TCP 쿼리-응답 분석:
- 트랜잭션 ID
- 쿼리/응답 패킷 번호
- 응답 시간 (밀리초)
- 클라이언트/서버 IP
- 함수 코드 및 이름
- 유닛 ID
- 시작 주소 및 레지스터 개수
- 쿼리/응답 데이터

### 3. network_analysis.json
네트워크 분석 결과 (JSON 형식):
- 전체 통계 (패킷 수, 크기, 지속 시간)
- 프로토콜 분포
- 상위 IP 연결
- 상위 포트 사용량

### 4. network_analysis_report.txt
사람이 읽기 쉬운 분석 리포트:
- 요약 정보
- 프로토콜 분포 (백분율 포함)
- 주요 IP 연결
- 주요 포트 사용량

## 지원 프로토콜

- **TCP**: 일반 TCP 패킷 분석
- **Modbus/TCP**: 포트 502를 사용하는 Modbus 프로토콜 분석
  - 함수 코드 1, 2, 3, 4, 5, 6, 15, 16 지원
  - 트랜잭션 ID를 통한 쿼리-응답 매칭
  - 응답 시간 계산
- **MDNS**: 포트 5353을 사용하는 멀티캐스트 DNS 패킷 식별
- **UDP**: 일반 UDP 패킷 분석

## Modbus/TCP 함수 코드

지원되는 Modbus 함수 코드:
- 1: Read Coils
- 2: Read Discrete Inputs
- 3: Read Holding Registers
- 4: Read Input Registers
- 5: Write Single Coil
- 6: Write Single Register
- 15: Write Multiple Coils
- 16: Write Multiple Registers

## 예제

```bash
# 기본 분석
python pcap_analyzer.py network_capture.pcap

# 커스텀 출력 폴더 사용
python pcap_analyzer.py network_capture.pcap -o analysis_results

# 결과 확인
ls output/
# network_packets.csv
# modbus_transactions.csv
# network_analysis.json
# network_analysis_report.txt
```

## 주의 사항

1. 큰 PCAP 파일의 경우 분석에 시간이 걸릴 수 있습니다.
2. Modbus/TCP 분석은 포트 502를 사용하는 패킷만 대상으로 합니다.
3. 암호화된 패킷은 페이로드 분석이 제한됩니다.
4. Windows 환경에서 Scapy 사용 시 관리자 권한이 필요할 수 있습니다.

## 문제 해결

### Scapy 설치 문제
```bash
# Windows에서 Scapy 설치 시 문제가 있는 경우
pip install --user scapy
```

### 권한 문제
- Windows에서는 관리자 권한으로 명령 프롬프트를 실행해야 할 수 있습니다.

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.
