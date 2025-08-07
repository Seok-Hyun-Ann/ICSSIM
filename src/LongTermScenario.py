import logging
import time
from datetime import datetime, timedelta
from ics_sim.Device import HMI
from Configs import TAG, Controllers


class LongTermScenario(HMI):
    """
    1-3일간 지속 가능한 현실적인 공장 운영 시나리오
    - 모드 변경을 최소화하고 센서 기반 자동 동작 위주
    - 실제 공장의 운영 패턴을 모방
    """
    
    def __init__(self):
        super().__init__('LongTermScenario', TAG.TAG_LIST, Controllers.PLCs, 5000)  # 5초 주기
        
        # 시나리오 상태
        self.scenario_start_time = None
        self.current_shift = "day"  # day, night, maintenance
        self.last_shift_change = None
        self.last_maintenance = None
        self.last_parameter_adjustment = None
        
        # 운영 모드 (한번 설정하면 오랫동안 유지)
        self.operation_mode = "normal"  # normal, maintenance, emergency
        
        # 실제 공장과 같은 운영 스케줄
        self.shift_schedule = {
            "day_shift": {"start": 6, "end": 18},      # 06:00 - 18:00
            "night_shift": {"start": 18, "end": 6},   # 18:00 - 06:00
            "maintenance": {"start": 2, "end": 4}     # 02:00 - 04:00 (주간 유지보수)
        }
        
    def _before_start(self):
        super()._before_start()
        self._set_clear_scr(True)
        self.scenario_start_time = datetime.now()
        self.last_shift_change = datetime.now()
        self.last_maintenance = datetime.now()
        self.last_parameter_adjustment = datetime.now()
        
        # 초기 설정: 모든 장치를 AUTO 모드로 설정 (한번만!)
        self._initialize_factory()
        
        self.report("🏭 장기 공장 시뮬레이션을 시작합니다.", logging.INFO)
        self.report("📅 시뮬레이션 시작 시간: " + self.scenario_start_time.strftime("%Y-%m-%d %H:%M:%S"), logging.INFO)
        
    def _initialize_factory(self):
        """공장 초기화 - 모든 장치를 자동 모드로 설정"""
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 3)      # AUTO
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 3)     # AUTO  
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 3)  # AUTO
        
        # 초기 설정값 (현실적인 값들)
        self._send(TAG.TAG_TANK_LEVEL_MIN, 3.0)
        self._send(TAG.TAG_TANK_LEVEL_MAX, 7.0)
        self._send(TAG.TAG_BOTTLE_LEVEL_MAX, 1.8)
        
        self.operation_mode = "normal"
        self.report("✅ 모든 장치가 자동 모드로 설정되었습니다.", logging.INFO)
        
    def _display(self):
        """현재 상태 표시"""
        now = datetime.now()
        elapsed = now - self.scenario_start_time
        
        # 기본 정보
        status = f"\n{'='*60}\n"
        status += f"🏭 장기 공장 시뮬레이션 - 운영 중\n"
        status += f"{'='*60}\n"
        status += f"📅 시작 시간: {self.scenario_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        status += f"⏰ 경과 시간: {self._format_duration(elapsed)}\n"
        status += f"🔄 현재 교대: {self._get_current_shift_name()}\n"
        status += f"⚙️  운영 모드: {self.operation_mode.upper()}\n"
        
        # 시스템 상태
        status += f"\n📊 현재 시스템 상태:\n"
        try:
            tank_level = self._receive(TAG.TAG_TANK_LEVEL_VALUE)
            bottle_level = self._receive(TAG.TAG_BOTTLE_LEVEL_VALUE)
            tank_flow = self._receive(TAG.TAG_TANK_OUTPUT_FLOW_VALUE)
            belt_distance = self._receive(TAG.TAG_BOTTLE_DISTANCE_TO_FILLER_VALUE)
            
            # 장치 모드 (거의 변하지 않음)
            input_mode = self._receive(TAG.TAG_TANK_INPUT_VALVE_MODE)
            output_mode = self._receive(TAG.TAG_TANK_OUTPUT_VALVE_MODE)
            belt_mode = self._receive(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE)
            
            status += f"🚰 탱크 수위: {tank_level:.2f}L\n"
            status += f"🍼 병 수위: {bottle_level:.2f}L\n"
            status += f"💧 출력 유량: {tank_flow:.4f}L/ms\n"
            status += f"📦 병 위치: {belt_distance:.1f}cm\n"
            status += f"⚙️  장치 모드: 입력밸브({self._mode_name(input_mode)}) | "
            status += f"출력밸브({self._mode_name(output_mode)}) | "
            status += f"컨베이어({self._mode_name(belt_mode)})\n"
            
        except Exception as e:
            status += f"❌ 상태 정보 오류: {str(e)}\n"
        
        # 다음 이벤트 예고
        status += f"\n📋 다음 예정 이벤트:\n"
        status += self._get_next_events()
        status += f"{'='*60}\n"
        
        self.report(status)
        
    def _operate(self):
        """장기 운영 로직 - 현실적인 공장 운영 패턴"""
        now = datetime.now()
        
        # 1. 교대 시간 체크 및 변경 (하루 2번)
        self._check_shift_change(now)
        
        # 2. 주간 유지보수 체크 (일주일에 1번)
        self._check_maintenance_schedule(now)
        
        # 3. 매개변수 조정 (하루에 1-2번, 필요시에만)
        self._check_parameter_adjustment(now)
        
        # 4. 비상 상황 시뮬레이션 (매우 드물게, 월 1회 정도)
        self._check_emergency_simulation(now)
        
        # 5. 상태 로깅 (정기적으로)
        self._periodic_logging(now)
        
    def _check_shift_change(self, now):
        """교대 시간 체크 - 하루 2번만 변경"""
        current_hour = now.hour
        time_since_last_change = now - self.last_shift_change
        
        # 최소 4시간 간격으로만 교대 변경 체크
        if time_since_last_change < timedelta(hours=4):
            return
            
        new_shift = None
        
        if 6 <= current_hour < 18 and self.current_shift != "day":
            new_shift = "day"
        elif (current_hour >= 18 or current_hour < 6) and self.current_shift != "night":
            new_shift = "night"
            
        if new_shift and new_shift != self.current_shift:
            self.current_shift = new_shift
            self.last_shift_change = now
            self.report(f"🔄 교대 변경: {new_shift.upper()} 근무 시작", logging.INFO)
            
            # 교대 시에만 매우 드물게 설정 조정
            if new_shift == "day":
                # 주간: 생산량 증가를 위한 약간의 조정
                self._send(TAG.TAG_TANK_LEVEL_MAX, 7.2)
            elif new_shift == "night":
                # 야간: 안정적 운영을 위한 보수적 설정
                self._send(TAG.TAG_TANK_LEVEL_MAX, 6.8)
                
    def _check_maintenance_schedule(self, now):
        """주간 유지보수 스케줄 체크"""
        time_since_maintenance = now - self.last_maintenance
        current_hour = now.hour
        
        # 일주일에 한번, 새벽 2-4시에 유지보수
        if (time_since_maintenance > timedelta(days=7) and 
            2 <= current_hour <= 4 and 
            self.operation_mode != "maintenance"):
            
            self._start_maintenance_mode()
            
        # 유지보수 모드 종료 체크
        elif (self.operation_mode == "maintenance" and 
              time_since_maintenance > timedelta(hours=2)):
            
            self._end_maintenance_mode()
            
    def _start_maintenance_mode(self):
        """유지보수 모드 시작"""
        self.operation_mode = "maintenance"
        self.last_maintenance = datetime.now()
        
        self.report("🔧 주간 유지보수를 시작합니다.", logging.INFO)
        
        # 유지보수 중에는 모든 장치를 수동 OFF (안전을 위해)
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 1)   # Manual OFF
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 1)  # Manual OFF
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 1)  # Manual OFF
        
        self.report("⚠️ 유지보수를 위해 모든 장치가 정지되었습니다.", logging.INFO)
        
    def _end_maintenance_mode(self):
        """유지보수 모드 종료"""
        self.operation_mode = "normal"
        
        self.report("✅ 주간 유지보수가 완료되었습니다.", logging.INFO)
        
        # 유지보수 후 모든 장치를 다시 AUTO 모드로
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 3)   # AUTO
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 3)  # AUTO
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 3)  # AUTO
        
        # 유지보수 후 설정값 최적화
        self._send(TAG.TAG_TANK_LEVEL_MIN, 3.2)
        self._send(TAG.TAG_TANK_LEVEL_MAX, 7.0)
        
        self.report("🔄 모든 장치가 정상 운영으로 복귀했습니다.", logging.INFO)
        
    def _check_parameter_adjustment(self, now):
        """매개변수 조정 - 하루에 1-2번만"""
        time_since_adjustment = now - self.last_parameter_adjustment
        
        # 최소 12시간 간격으로만 조정
        if time_since_adjustment < timedelta(hours=12):
            return
            
        # 현실적인 소폭 조정만 수행
        if self.operation_mode == "normal":
            try:
                current_tank_level = self._receive(TAG.TAG_TANK_LEVEL_VALUE)
                
                # 탱크 수위에 따른 미세 조정
                if current_tank_level > 8.0:
                    # 수위가 높으면 최대값을 약간 낮춤
                    self._send(TAG.TAG_TANK_LEVEL_MAX, 6.5)
                    self.report("📊 탱크 수위가 높아 최대값을 6.5로 조정", logging.INFO)
                elif current_tank_level < 2.0:
                    # 수위가 낮으면 최소값을 약간 낮춤
                    self._send(TAG.TAG_TANK_LEVEL_MIN, 2.5)
                    self.report("📊 탱크 수위가 낮아 최소값을 2.5로 조정", logging.INFO)
                    
                self.last_parameter_adjustment = now
                
            except:
                pass  # 센서 오류시 조정하지 않음
                
    def _check_emergency_simulation(self, now):
        """비상 상황 시뮬레이션 - 매우 드물게"""
        # 30일에 한번 정도만 비상 상황 발생
        if (now - self.scenario_start_time).days > 0 and (now - self.scenario_start_time).days % 30 == 0:
            current_hour = now.hour
            
            # 특정 시간대에만 비상 상황 시뮬레이션
            if current_hour == 14 and self.operation_mode != "emergency":
                self._simulate_emergency()
                
    def _simulate_emergency(self):
        """비상 상황 시뮬레이션"""
        self.operation_mode = "emergency"
        
        self.report("🚨 비상 상황 시뮬레이션을 시작합니다!", logging.WARNING)
        
        # 모든 장치 즉시 정지
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 1)   # Manual OFF
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 1)  # Manual OFF
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 1)  # Manual OFF
        
        self.report("⚠️ 모든 장치가 비상 정지되었습니다.", logging.WARNING)
        
        # 10분 후 정상 복귀 (실제로는 더 짧게)
        time.sleep(10)  # 10초 대기 (시뮬레이션에서는)
        
        self.operation_mode = "normal"
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 3)   # AUTO
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 3)  # AUTO
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 3)  # AUTO
        
        self.report("✅ 비상 상황이 해제되고 정상 운영으로 복귀했습니다.", logging.INFO)
        
    def _periodic_logging(self, now):
        """정기적인 상태 로깅"""
        # 1시간마다 상세 로그 기록
        if now.minute == 0:
            try:
                tank_level = self._receive(TAG.TAG_TANK_LEVEL_VALUE)
                bottle_level = self._receive(TAG.TAG_BOTTLE_LEVEL_VALUE)
                
                log_msg = f"📊 정시 상태: 탱크={tank_level:.2f}L, 병={bottle_level:.2f}L, 모드={self.operation_mode}"
                self.report(log_msg, logging.INFO)
            except:
                pass
                
    def _get_current_shift_name(self):
        """현재 교대 이름 반환"""
        shift_names = {
            "day": "주간 근무 (06:00-18:00)",
            "night": "야간 근무 (18:00-06:00)",
            "maintenance": "유지보수 시간"
        }
        return shift_names.get(self.current_shift, "알 수 없음")
        
    def _mode_name(self, mode):
        """모드 번호를 이름으로 변환"""
        names = {1: "수동OFF", 2: "수동ON", 3: "자동"}
        return names.get(mode, f"알수없음({mode})")
        
    def _format_duration(self, duration):
        """시간 간격을 읽기 쉽게 포맷"""
        days = duration.days
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        
        if days > 0:
            return f"{days}일 {hours}시간 {minutes}분"
        elif hours > 0:
            return f"{hours}시간 {minutes}분"
        else:
            return f"{minutes}분"
            
    def _get_next_events(self):
        """다음 예정 이벤트들"""
        now = datetime.now()
        events = []
        
        # 다음 교대 시간
        if self.current_shift == "day":
            next_shift = now.replace(hour=18, minute=0, second=0)
            if next_shift <= now:
                next_shift += timedelta(days=1)
            events.append(f"⏰ 야간 교대: {next_shift.strftime('%H:%M')}")
        else:
            next_shift = (now + timedelta(days=1)).replace(hour=6, minute=0, second=0)
            events.append(f"⏰ 주간 교대: {next_shift.strftime('%H:%M')}")
            
        # 다음 유지보수
        next_maintenance = self.last_maintenance + timedelta(days=7)
        maintenance_days = (next_maintenance - now).days
        if maintenance_days >= 0:
            events.append(f"🔧 다음 유지보수: {maintenance_days}일 후")
            
        return "\n".join(events) + "\n" if events else "예정된 이벤트 없음\n"


if __name__ == '__main__':
    scenario = LongTermScenario()
    scenario.start()