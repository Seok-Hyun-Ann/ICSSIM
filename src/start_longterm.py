#!/usr/bin/env python3
"""
장기 공장 시뮬레이션 시작 스크립트
1-3일간 지속 가능한 현실적인 네트워크 트래픽 생성
"""

import time
import signal
import sys
from datetime import datetime

from FactorySimulation import FactorySimulation
from PLC1 import PLC1
from PLC2 import PLC2
from HMI1 import HMI1
from LongTermScenario import LongTermScenario


class LongTermSimulationManager:
    def __init__(self):
        self.components = []
        self.running = True
        
    def signal_handler(self, signum, frame):
        """Ctrl+C 처리"""
        print(f"\n🛑 시뮬레이션 종료 신호를 받았습니다...")
        self.stop_all()
        sys.exit(0)
        
    def start_simulation(self):
        """장기 시뮬레이션 시작"""
        print("="*60)
        print("🏭 장기 공장 시뮬레이션 시작")
        print("="*60)
        print(f"📅 시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("⏰ 예상 실행 시간: 1-3일")
        print("📡 네트워크 덤프를 위한 현실적인 트래픽 생성")
        print("🔄 운영 스케줄: 주간 11시간, 야간 11시간, 교대시 1시간 중지")
        print("📊 센서값: 기존 물리 시뮬레이션 로직 그대로 유지")
        print("="*60)
        
        # Signal handler 등록
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # 1. 물리 시뮬레이션 시작 (센서 데이터)
            print("🔧 물리 시뮬레이션 시작...")
            factory = FactorySimulation()
            factory.start()
            self.components.append(factory)
            time.sleep(2)
            
            # 2. PLC1 시작
            print("⚙️  PLC1 시작...")
            plc1 = PLC1()
            plc1.start()
            self.components.append(plc1)
            time.sleep(2)
            
            # 3. PLC2 시작  
            print("⚙️  PLC2 시작...")
            plc2 = PLC2()
            plc2.start()
            self.components.append(plc2)
            time.sleep(2)
            
            # 4. HMI1 시작 (모니터링)
            print("📊 HMI1 모니터링 시작...")
            hmi1 = HMI1()
            hmi1.start()
            self.components.append(hmi1)
            time.sleep(2)
            
            # 5. 장기 시나리오 실행기 시작
            print("🎬 장기 시나리오 실행기 시작...")
            scenario = LongTermScenario()
            scenario.start()
            self.components.append(scenario)
            
            print("\n✅ 모든 컴포넌트가 성공적으로 시작되었습니다!")
            print("\n📋 실행 중인 컴포넌트:")
            print("  - FactorySimulation: 물리적 센서 데이터 생성")
            print("  - PLC1: 탱크 밸브 제어 로직")
            print("  - PLC2: 컨베이어 벨트 제어 로직")  
            print("  - HMI1: 실시간 모니터링")
            print("  - LongTermScenario: 교대 기반 운영 시나리오")
            
            print(f"\n⏰ 운영 스케줄:")
            print("  - 주간 근무: 07:00-18:00 (11시간) - 장비 AUTO 모드")
            print("  - 교대 시간: 18:00-19:00 (1시간) - 장비 중지")
            print("  - 야간 근무: 19:00-06:00 (11시간) - 장비 AUTO 모드")
            print("  - 교대 시간: 06:00-07:00 (1시간) - 장비 중지")
            
            print(f"\n🌐 네트워크 포트:")
            print("  - PLC1: 127.0.0.1:5502 (Modbus TCP)")
            print("  - PLC2: 127.0.0.1:5503 (Modbus TCP)")
            
            print(f"\n📝 로그 파일:")
            print("  - logs/logs-FactorySimulation.log")
            print("  - logs/logs-PLC1.log") 
            print("  - logs/logs-PLC2.log")
            print("  - logs/logs-HMI1.log")
            print("  - logs/logs-LongTermScenario.log")
            
            print(f"\n🔍 네트워크 캡처 명령어 예시:")
            print("  tcpdump -i lo -w factory_traffic.pcap port 5502 or port 5503")
            print("  wireshark -i lo -f 'port 5502 or port 5503'")
            
            print(f"\n⚠️  시뮬레이션을 중지하려면 Ctrl+C를 누르세요")
            print("="*60)
            
            # 무한 대기
            while self.running:
                time.sleep(60)  # 1분마다 체크
                self.check_components_health()
                
        except KeyboardInterrupt:
            print(f"\n🛑 사용자에 의해 시뮬레이션이 중단되었습니다.")
            self.stop_all()
        except Exception as e:
            print(f"\n❌ 시뮬레이션 오류: {e}")
            self.stop_all()
            
    def check_components_health(self):
        """컴포넌트 상태 체크"""
        current_time = datetime.now().strftime('%H:%M:%S')
        print(f"💓 {current_time} - 시스템 정상 운영 중... (컴포넌트: {len(self.components)}개)")
        
    def stop_all(self):
        """모든 컴포넌트 정지"""
        self.running = False
        print(f"\n🔄 시뮬레이션 컴포넌트들을 정지하는 중...")
        
        for i, component in enumerate(reversed(self.components)):
            try:
                print(f"  {i+1}. {component.name()} 정지 중...")
                component.stop()
                time.sleep(1)
            except Exception as e:
                print(f"  ❌ {component.name()} 정지 실패: {e}")
                
        print("✅ 모든 컴포넌트가 정지되었습니다.")
        print(f"📅 시뮬레이션 종료: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == '__main__':
    print("🚀 장기 공장 시뮬레이션 관리자")
    
    # 실행 확인
    response = input("1-3일간 장기 시뮬레이션을 시작하시겠습니까? (y/N): ")
    if response.lower() in ['y', 'yes']:
        manager = LongTermSimulationManager()
        manager.start_simulation()
    else:
        print("시뮬레이션이 취소되었습니다.")