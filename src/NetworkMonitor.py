import os
import sys
import time
import json
import subprocess
import threading
import signal
from datetime import datetime
from typing import Dict, List, Optional, Callable
import logging

class NetworkMonitor:
    """
    TCPDUMP를 이용한 네트워크 패킷 분석 클래스
    ICS 환경에서 편리한 네트워크 모니터링을 제공
    """
    
    def __init__(self, log_dir='logs/network_monitor'):
        self.log_dir = log_dir
        self.running_captures = {}  # 실행 중인 캡처 프로세스들
        self.capture_configs = {}   # 캡처 설정들
        self.analysis_results = {}  # 분석 결과들
        
        # 로그 디렉토리 생성
        os.makedirs(log_dir, exist_ok=True)
        
        # 로거 설정
        self.logger = self._setup_logger()
        
        # 시그널 핸들러 등록 (프로그램 종료 시 모든 캡처 중지)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _setup_logger(self):
        """로거 설정"""
        logger = logging.getLogger('NetworkMonitor')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            # 파일 핸들러
            file_handler = logging.FileHandler(
                os.path.join(self.log_dir, 'network_monitor.log')
            )
            file_handler.setLevel(logging.INFO)
            
            # 콘솔 핸들러
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # 포매터
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
        
        return logger
    
    def _signal_handler(self, signum, frame):
        """시그널 핸들러 - 프로그램 종료 시 모든 캡처 중지"""
        self.logger.info("Received signal, stopping all captures...")
        self.stop_all_captures()
        sys.exit(0)
    
    def start_capture(self, 
                     capture_name: str,
                     interface: str = 'any',
                     filter_expression: str = '',
                     output_file: Optional[str] = None,
                     packet_count: Optional[int] = None,
                     duration: Optional[int] = None,
                     real_time_analysis: bool = False,
                     analysis_callback: Optional[Callable] = None) -> bool:
        """
        패킷 캡처 시작
        
        Args:
            capture_name: 캡처 이름 (고유 식별자)
            interface: 네트워크 인터페이스 ('any', 'eth0', 'br_icsnet' 등)
            filter_expression: tcpdump 필터 표현식
            output_file: 출력 파일 경로 (지정하지 않으면 자동 생성)
            packet_count: 캡처할 패킷 수 제한
            duration: 캡처 지속 시간 (초)
            real_time_analysis: 실시간 분석 여부
            analysis_callback: 실시간 분석 콜백 함수
            
        Returns:
            bool: 캡처 시작 성공 여부
        """
        
        if capture_name in self.running_captures:
            self.logger.warning(f"Capture '{capture_name}' is already running")
            return False
        
        # 출력 파일 설정
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.log_dir, f'{capture_name}_{timestamp}.pcap')
        
        # tcpdump 명령어 구성
        cmd = ['tcpdump', '-i', interface]
        
        # 출력 파일 지정
        cmd.extend(['-w', output_file])
        
        # 패킷 수 제한
        if packet_count:
            cmd.extend(['-c', str(packet_count)])
        
        # 필터 표현식 추가
        if filter_expression:
            cmd.append(filter_expression)
        
        try:
            # tcpdump 프로세스 시작
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # 캡처 정보 저장
            self.running_captures[capture_name] = {
                'process': process,
                'output_file': output_file,
                'start_time': datetime.now(),
                'interface': interface,
                'filter': filter_expression,
                'packet_count': packet_count,
                'duration': duration
            }
            
            self.capture_configs[capture_name] = {
                'interface': interface,
                'filter_expression': filter_expression,
                'output_file': output_file,
                'packet_count': packet_count,
                'duration': duration,
                'real_time_analysis': real_time_analysis,
                'analysis_callback': analysis_callback
            }
            
            self.logger.info(f"Started capture '{capture_name}' on interface '{interface}'")
            self.logger.info(f"Output file: {output_file}")
            
            # 지속 시간이 설정된 경우 타이머 시작
            if duration:
                timer = threading.Timer(duration, self._stop_capture_by_timer, [capture_name])
                timer.start()
                self.running_captures[capture_name]['timer'] = timer
            
            # 실시간 분석이 활성화된 경우
            if real_time_analysis:
                analysis_thread = threading.Thread(
                    target=self._real_time_analysis,
                    args=(capture_name, analysis_callback)
                )
                analysis_thread.daemon = True
                analysis_thread.start()
                self.running_captures[capture_name]['analysis_thread'] = analysis_thread
            
            return True
            
        except FileNotFoundError:
            self.logger.error("tcpdump not found. Please install tcpdump.")
            return False
        except PermissionError:
            self.logger.error("Permission denied. Please run with sudo or proper privileges.")
            return False
        except Exception as e:
            self.logger.error(f"Failed to start capture '{capture_name}': {e}")
            return False
    
    def stop_capture(self, capture_name: str) -> bool:
        """
        특정 캡처 중지
        
        Args:
            capture_name: 중지할 캡처 이름
            
        Returns:
            bool: 중지 성공 여부
        """
        
        if capture_name not in self.running_captures:
            self.logger.warning(f"Capture '{capture_name}' is not running")
            return False
        
        try:
            capture_info = self.running_captures[capture_name]
            process = capture_info['process']
            
            # 프로세스 종료
            process.terminate()
            
            # 타이머가 있다면 취소
            if 'timer' in capture_info:
                capture_info['timer'].cancel()
            
            # 프로세스 종료 대기
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            
            # 캡처 정보에서 제거
            del self.running_captures[capture_name]
            
            self.logger.info(f"Stopped capture '{capture_name}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop capture '{capture_name}': {e}")
            return False
    
    def stop_all_captures(self):
        """모든 캡처 중지"""
        capture_names = list(self.running_captures.keys())
        for capture_name in capture_names:
            self.stop_capture(capture_name)
    
    def _stop_capture_by_timer(self, capture_name: str):
        """타이머에 의한 캡처 중지"""
        self.logger.info(f"Stopping capture '{capture_name}' due to duration limit")
        self.stop_capture(capture_name)
    
    def get_running_captures(self) -> Dict:
        """실행 중인 캡처 목록 반환"""
        result = {}
        for name, info in self.running_captures.items():
            result[name] = {
                'start_time': info['start_time'],
                'interface': info['interface'],
                'filter': info['filter'],
                'output_file': info['output_file'],
                'packet_count': info['packet_count'],
                'duration': info['duration']
            }
        return result
    
    def analyze_pcap_file(self, pcap_file: str, analysis_type: str = 'basic') -> Dict:
        """
        PCAP 파일 분석
        
        Args:
            pcap_file: 분석할 PCAP 파일 경로
            analysis_type: 분석 유형 ('basic', 'modbus', 'security')
            
        Returns:
            Dict: 분석 결과
        """
        
        if not os.path.exists(pcap_file):
            self.logger.error(f"PCAP file not found: {pcap_file}")
            return {}
        
        try:
            if analysis_type == 'basic':
                return self._basic_analysis(pcap_file)
            elif analysis_type == 'modbus':
                return self._modbus_analysis(pcap_file)
            elif analysis_type == 'security':
                return self._security_analysis(pcap_file)
            else:
                self.logger.error(f"Unknown analysis type: {analysis_type}")
                return {}
                
        except Exception as e:
            self.logger.error(f"Failed to analyze PCAP file '{pcap_file}': {e}")
            return {}
    
    def _basic_analysis(self, pcap_file: str) -> Dict:
        """기본 패킷 분석"""
        result = {
            'file': pcap_file,
            'analysis_type': 'basic',
            'timestamp': datetime.now().isoformat(),
            'total_packets': 0,
            'protocols': {},
            'top_sources': {},
            'top_destinations': {},
            'packet_sizes': []
        }
        
        try:
            # tcpdump를 이용한 기본 통계
            cmd = ['tcpdump', '-r', pcap_file, '-q']
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                lines = process.stdout.strip().split('\n')
                result['total_packets'] = len([line for line in lines if line.strip()])
                
                # 간단한 프로토콜 분석
                for line in lines:
                    if 'IP' in line:
                        result['protocols']['IP'] = result['protocols'].get('IP', 0) + 1
                    if 'TCP' in line:
                        result['protocols']['TCP'] = result['protocols'].get('TCP', 0) + 1
                    if 'UDP' in line:
                        result['protocols']['UDP'] = result['protocols'].get('UDP', 0) + 1
            
        except Exception as e:
            self.logger.error(f"Basic analysis failed: {e}")
        
        return result
    
    def _modbus_analysis(self, pcap_file: str) -> Dict:
        """Modbus 프로토콜 특화 분석"""
        result = {
            'file': pcap_file,
            'analysis_type': 'modbus',
            'timestamp': datetime.now().isoformat(),
            'modbus_packets': 0,
            'function_codes': {},
            'devices': {},
            'suspicious_activities': []
        }
        
        try:
            # Modbus 패킷 필터링 (포트 502)
            cmd = ['tcpdump', '-r', pcap_file, '-n', 'port 502']
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                lines = process.stdout.strip().split('\n')
                result['modbus_packets'] = len([line for line in lines if line.strip()])
                
                # 기본적인 Modbus 통신 분석
                for line in lines:
                    if '>' in line:
                        parts = line.split('>')
                        if len(parts) >= 2:
                            src = parts[0].strip().split()[-1]
                            dst = parts[1].strip().split()[0]
                            
                            result['devices'][src] = result['devices'].get(src, 0) + 1
                            result['devices'][dst] = result['devices'].get(dst, 0) + 1
            
        except Exception as e:
            self.logger.error(f"Modbus analysis failed: {e}")
        
        return result
    
    def _security_analysis(self, pcap_file: str) -> Dict:
        """보안 중심 분석"""
        result = {
            'file': pcap_file,
            'analysis_type': 'security',
            'timestamp': datetime.now().isoformat(),
            'alerts': [],
            'scan_attempts': 0,
            'unusual_traffic': [],
            'port_activity': {}
        }
        
        try:
            # 포트 스캔 탐지
            cmd = ['tcpdump', '-r', pcap_file, '-n', 'tcp[tcpflags] & tcp-syn != 0']
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                syn_packets = process.stdout.strip().split('\n')
                result['scan_attempts'] = len([line for line in syn_packets if line.strip()])
                
                if result['scan_attempts'] > 100:
                    result['alerts'].append({
                        'type': 'potential_port_scan',
                        'severity': 'high',
                        'description': f'High number of SYN packets detected: {result["scan_attempts"]}'
                    })
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
        
        return result
    
    def _real_time_analysis(self, capture_name: str, callback: Optional[Callable]):
        """실시간 패킷 분석"""
        if capture_name not in self.running_captures:
            return
        
        capture_info = self.running_captures[capture_name]
        output_file = capture_info['output_file']
        
        # 실시간 분석 로직 (간단한 예시)
        packet_count = 0
        while capture_name in self.running_captures:
            try:
                # 파일 크기 체크로 새 패킷 감지
                if os.path.exists(output_file):
                    current_size = os.path.getsize(output_file)
                    if current_size > packet_count * 100:  # 대략적인 패킷 크기 추정
                        packet_count += 1
                        
                        if callback:
                            callback(capture_name, packet_count)
                        
                        if packet_count % 100 == 0:
                            self.logger.info(f"Capture '{capture_name}': {packet_count} packets captured")
                
                time.sleep(1)  # 1초마다 체크
                
            except Exception as e:
                self.logger.error(f"Real-time analysis error for '{capture_name}': {e}")
                break
    
    def get_predefined_filters(self) -> Dict[str, str]:
        """사전 정의된 필터 표현식들"""
        return {
            'modbus_traffic': 'port 502',
            'http_traffic': 'port 80 or port 8080',
            'ssh_traffic': 'port 22',
            'dns_traffic': 'port 53',
            'icmp_traffic': 'icmp',
            'arp_traffic': 'arp',
            'broadcast_traffic': 'broadcast',
            'tcp_syn_scan': 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0',
            'large_packets': 'greater 1000',
            'small_packets': 'less 100',
            'plc1_traffic': 'host 192.168.0.11',
            'plc2_traffic': 'host 192.168.0.12',
            'hmi_traffic': 'host 192.168.0.21 or host 192.168.0.22',
            'attacker_traffic': 'host 192.168.0.41 or host 192.168.0.42 or host 192.168.0.43'
        }
    
    def save_analysis_report(self, analysis_result: Dict, report_file: Optional[str] = None):
        """분석 결과를 파일로 저장"""
        if report_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(self.log_dir, f'analysis_report_{timestamp}.json')
        
        try:
            with open(report_file, 'w') as f:
                json.dump(analysis_result, f, indent=2, default=str)
            
            self.logger.info(f"Analysis report saved to: {report_file}")
            return report_file
            
        except Exception as e:
            self.logger.error(f"Failed to save analysis report: {e}")
            return None


# 전역 네트워크 모니터 인스턴스
network_monitor = NetworkMonitor()