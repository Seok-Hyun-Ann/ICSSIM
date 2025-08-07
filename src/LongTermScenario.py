import logging
import time
from datetime import datetime, timedelta
from ics_sim.Device import HMI
from Configs import TAG, Controllers


class LongTermScenario(HMI):
    """
    1-3일간 지속 가능한 현실적인 공장 운영 시나리오
    - 주간 11시간, 야간 11시간, 교대시 1시간씩 중지
    - 센서값은 기존 물리 시뮬레이션 그대로 유지
    - 비상상황 및 유지보수 기능 제거
    """
    
    def __init__(self):
        super().__init__('LongTermScenario', TAG.TAG_LIST, Controllers.PLCs, 5000)  # 5초 주기
        
        # 시나리오 상태
        self.scenario_start_time = None
        self.current_shift = "day"  # day, night, shift_change
        self.last_shift_change = None
        
        # 운영 모드 (간소화)
        self.operation_mode = "normal"  # normal, shift_change
        
        # 새로운 운영 스케줄: 주간 11시간, 야간 11시간, 교대 1시간씩
        self.shift_schedule = {
            "day_shift": {"start": 7, "end": 18},        # 07:00 - 18:00 (11시간)
            "shift_change_1": {"start": 18, "end": 19},  # 18:00 - 19:00 (1시간 중지)
            "night_shift": {"start": 19, "end": 6},      # 19:00 - 06:00 (11시간)
            "shift_change_2": {"start": 6, "end": 7}     # 06:00 - 07:00 (1시간 중지)
        }
        
    def _before_start(self):
        super()._before_start()
        self._set_clear_scr(True)
        self.scenario_start_time = datetime.now()
        self.last_shift_change = datetime.now()
        
        # 초기 설정: 모든 장치를 AUTO 모드로 설정 (한번만!)
        self._initialize_factory()
        
        self.report("🏭 장기 공장 시뮬레이션을 시작합니다.", logging.INFO)
        self.report("📅 시뮬레이션 시작 시간: " + self.scenario_start_time.strftime("%Y-%m-%d %H:%M:%S"), logging.INFO)
        self.report("⏰ 운영 스케줄: 주간 11시간, 야간 11시간, 교대시 1시간 중지", logging.INFO)
        
    def _initialize_factory(self):
        """공장 초기화 - 모든 장치를 자동 모드로 설정"""
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 3)      # AUTO
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 3)     # AUTO  
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 3)  # AUTO
        
        # 초기 설정값 (기본값 유지, 변경하지 않음)
        # 센서값은 기존 물리 시뮬레이션에서 자동으로 처리됨
        
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
        """장기 운영 로직 - 간소화된 교대 시스템"""
        now = datetime.now()
        
        # 1. 교대 시간 체크 및 변경 (하루 4번: 주간시작, 교대중지1, 야간시작, 교대중지2)
        self._check_shift_change(now)
        
        # 2. 상태 로깅 (정기적으로)
        self._periodic_logging(now)
        
    def _check_shift_change(self, now):
        """교대 시간 체크 - 새로운 스케줄: 주간11h, 야간11h, 교대1h씩"""
        current_hour = now.hour
        time_since_last_change = now - self.last_shift_change
        
        # 최소 30분 간격으로만 교대 변경 체크 (더 정확한 시간 체크)
        if time_since_last_change < timedelta(minutes=30):
            return
            
        new_shift = None
        new_operation_mode = "normal"
        
        # 새로운 스케줄에 따른 교대 체크
        if 7 <= current_hour < 18 and self.current_shift != "day":
            new_shift = "day"
            new_operation_mode = "normal"
        elif current_hour == 18 and self.current_shift != "shift_change":
            new_shift = "shift_change"
            new_operation_mode = "shift_change"
        elif 19 <= current_hour < 24 or 0 <= current_hour < 6:
            if self.current_shift != "night":
                new_shift = "night"
                new_operation_mode = "normal"
        elif current_hour == 6 and self.current_shift != "shift_change":
            new_shift = "shift_change"
            new_operation_mode = "shift_change"
            
        if new_shift and new_shift != self.current_shift:
            self.current_shift = new_shift
            self.operation_mode = new_operation_mode
            self.last_shift_change = now
            
            if new_shift == "day":
                self._start_day_shift()
            elif new_shift == "night":
                self._start_night_shift()
            elif new_shift == "shift_change":
                self._start_shift_change()
                
    def _start_day_shift(self):
        """주간 근무 시작 (07:00-18:00, 11시간)"""
        self.report("🌅 주간 근무를 시작합니다. (07:00-18:00)", logging.INFO)
        
        # 모든 장치를 AUTO 모드로 (정상 운영)
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 3)      # AUTO
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 3)     # AUTO
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 3)  # AUTO
        
        self.report("✅ 모든 장치가 자동 모드로 설정되었습니다.", logging.INFO)
        
    def _start_night_shift(self):
        """야간 근무 시작 (19:00-06:00, 11시간)"""
        self.report("🌙 야간 근무를 시작합니다. (19:00-06:00)", logging.INFO)
        
        # 모든 장치를 AUTO 모드로 (정상 운영)
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 3)      # AUTO
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 3)     # AUTO
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 3)  # AUTO
        
        self.report("✅ 모든 장치가 자동 모드로 설정되었습니다.", logging.INFO)
        
    def _start_shift_change(self):
        """교대 시간 (장비 가동 중지, 1시간)"""
        if self.current_shift == "shift_change":
            current_hour = datetime.now().hour
            if current_hour == 18:
                self.report("🔄 주간→야간 교대 시간입니다. (18:00-19:00)", logging.INFO)
            elif current_hour == 6:
                self.report("🔄 야간→주간 교대 시간입니다. (06:00-07:00)", logging.INFO)
                
        # 교대 시간에는 모든 장치를 수동 OFF (안전한 중지)
        self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, 1)      # Manual OFF
        self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, 1)     # Manual OFF
        self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, 1)  # Manual OFF
        
        self.report("⏸️ 교대 시간으로 모든 장치가 안전하게 정지되었습니다.", logging.INFO)
                

        
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
            "day": "주간 근무 (07:00-18:00)",
            "night": "야간 근무 (19:00-06:00)", 
            "shift_change": "교대 시간 (장비 중지)"
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
        current_hour = now.hour
        
        # 다음 이벤트 예측
        if self.current_shift == "day":
            # 주간 근무 중: 다음은 18시 교대 시간
            next_event_time = now.replace(hour=18, minute=0, second=0)
            if next_event_time <= now:
                next_event_time += timedelta(days=1)
            events.append(f"⏰ 교대 시간 (장비 중지): {next_event_time.strftime('%H:%M')}")
            
        elif self.current_shift == "shift_change":
            # 교대 시간 중: 다음 근무 시간 예측
            if current_hour == 18:
                next_event_time = now.replace(hour=19, minute=0, second=0)
                events.append(f"🌙 야간 근무 시작: {next_event_time.strftime('%H:%M')}")
            elif current_hour == 6:
                next_event_time = now.replace(hour=7, minute=0, second=0)
                events.append(f"🌅 주간 근무 시작: {next_event_time.strftime('%H:%M')}")
                
        elif self.current_shift == "night":
            # 야간 근무 중: 다음은 06시 교대 시간
            next_event_time = (now + timedelta(days=1)).replace(hour=6, minute=0, second=0)
            if current_hour < 6:  # 아직 당일 새벽이면
                next_event_time = now.replace(hour=6, minute=0, second=0)
            events.append(f"⏰ 교대 시간 (장비 중지): {next_event_time.strftime('%H:%M')}")
            
        return "\n".join(events) + "\n" if events else "예정된 이벤트 없음\n"


if __name__ == '__main__':
    scenario = LongTermScenario()
    scenario.start()