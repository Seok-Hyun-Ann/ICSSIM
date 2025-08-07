import logging
import time
import json
from datetime import datetime
from ics_sim.Device import HMI
from Configs import TAG, Controllers


class ScenarioRunner(HMI):
    def __init__(self, scenario_file=None):
        super().__init__('ScenarioRunner', TAG.TAG_LIST, Controllers.PLCs, 1000)
        self.scenario_file = scenario_file
        self.scenarios = []
        self.current_scenario_index = 0
        self.scenario_start_time = 0
        self.scenario_running = False
        
        # 기본 시나리오들
        self.default_scenarios = self._create_default_scenarios()
        
        if scenario_file:
            self._load_scenarios_from_file()
        else:
            self.scenarios = self.default_scenarios

    def _create_default_scenarios(self):
        """기본 시나리오들을 정의"""
        return [
            {
                "name": "정상 운영 시나리오",
                "description": "모든 장치를 AUTO 모드로 설정하고 정상 운영",
                "duration": 30,  # 30초 동안
                "steps": [
                    {"time": 0, "action": "set_mode", "device": "tank_input_valve", "value": 3},
                    {"time": 0, "action": "set_mode", "device": "tank_output_valve", "value": 3},
                    {"time": 0, "action": "set_mode", "device": "conveyor_belt_engine", "value": 3},
                    {"time": 5, "action": "log", "message": "모든 시스템이 자동 모드로 전환되었습니다."}
                ]
            },
            {
                "name": "탱크 입력 밸브 수동 제어 테스트",
                "description": "탱크 입력 밸브를 수동으로 제어하여 수위 변화 관찰",
                "duration": 40,
                "steps": [
                    {"time": 0, "action": "set_mode", "device": "tank_input_valve", "value": 2},  # 수동 ON
                    {"time": 0, "action": "log", "message": "탱크 입력 밸브를 수동으로 열었습니다."},
                    {"time": 15, "action": "set_mode", "device": "tank_input_valve", "value": 1},  # 수동 OFF
                    {"time": 15, "action": "log", "message": "탱크 입력 밸브를 수동으로 닫았습니다."},
                    {"time": 30, "action": "set_mode", "device": "tank_input_valve", "value": 3},  # AUTO
                    {"time": 30, "action": "log", "message": "탱크 입력 밸브를 자동 모드로 전환했습니다."}
                ]
            },
            {
                "name": "컨베이어 벨트 제어 시나리오",
                "description": "컨베이어 벨트를 다양한 모드로 제어",
                "duration": 50,
                "steps": [
                    {"time": 0, "action": "set_mode", "device": "conveyor_belt_engine", "value": 2},  # 수동 ON
                    {"time": 0, "action": "log", "message": "컨베이어 벨트를 수동으로 시작했습니다."},
                    {"time": 20, "action": "set_mode", "device": "conveyor_belt_engine", "value": 1},  # 수동 OFF
                    {"time": 20, "action": "log", "message": "컨베이어 벨트를 수동으로 정지했습니다."},
                    {"time": 35, "action": "set_mode", "device": "conveyor_belt_engine", "value": 3},  # AUTO
                    {"time": 35, "action": "log", "message": "컨베이어 벨트를 자동 모드로 전환했습니다."}
                ]
            },
            {
                "name": "비상 상황 시뮬레이션",
                "description": "모든 밸브를 닫고 컨베이어 벨트를 정지하는 비상 상황",
                "duration": 20,
                "steps": [
                    {"time": 0, "action": "set_mode", "device": "tank_input_valve", "value": 1},  # 강제 OFF
                    {"time": 0, "action": "set_mode", "device": "tank_output_valve", "value": 1},  # 강제 OFF
                    {"time": 0, "action": "set_mode", "device": "conveyor_belt_engine", "value": 1},  # 강제 OFF
                    {"time": 0, "action": "log", "message": "⚠️ 비상 상황! 모든 장치를 정지합니다."},
                    {"time": 15, "action": "log", "message": "비상 상황이 해제되었습니다. 수동으로 시스템을 재시작하세요."}
                ]
            },
            {
                "name": "설정값 변경 테스트",
                "description": "탱크와 병의 레벨 설정값을 동적으로 변경",
                "duration": 45,
                "steps": [
                    {"time": 0, "action": "set_parameter", "parameter": "tank_level_max", "value": 8.5},
                    {"time": 0, "action": "set_parameter", "parameter": "tank_level_min", "value": 2.0},
                    {"time": 0, "action": "log", "message": "탱크 레벨 설정값을 변경했습니다. (Min: 2.0, Max: 8.5)"},
                    {"time": 20, "action": "set_parameter", "parameter": "bottle_level_max", "value": 1.5},
                    {"time": 20, "action": "log", "message": "병 레벨 최대값을 1.5로 변경했습니다."},
                    {"time": 40, "action": "log", "message": "설정값 변경 테스트가 완료되었습니다."}
                ]
            }
        ]

    def _load_scenarios_from_file(self):
        """JSON 파일에서 시나리오를 로드"""
        try:
            with open(self.scenario_file, 'r', encoding='utf-8') as f:
                self.scenarios = json.load(f)
            self.report(f"시나리오 파일을 로드했습니다: {self.scenario_file}", logging.INFO)
        except Exception as e:
            self.report(f"시나리오 파일 로드 실패: {e}", logging.ERROR)
            self.scenarios = self.default_scenarios

    def _before_start(self):
        super()._before_start()
        self._set_clear_scr(True)
        self._show_menu()
        
    def _show_menu(self):
        """시나리오 선택 메뉴 표시"""
        menu = "\n" + "="*60 + "\n"
        menu += "🏭 공장 시뮬레이션 시나리오 러너\n"
        menu += "="*60 + "\n"
        
        for i, scenario in enumerate(self.scenarios):
            menu += f"{i+1}. {scenario['name']}\n"
            menu += f"   📝 {scenario['description']}\n"
            menu += f"   ⏱️  소요시간: {scenario['duration']}초\n\n"
        
        menu += f"{len(self.scenarios)+1}. 🔄 모든 시나리오 순차 실행\n"
        menu += f"{len(self.scenarios)+2}. ❌ 종료\n"
        menu += "="*60 + "\n"
        
        self.report(menu)

    def _display(self):
        if self.scenario_running:
            self._display_scenario_status()
        else:
            self._show_menu()

    def _display_scenario_status(self):
        """현재 실행 중인 시나리오 상태 표시"""
        if self.current_scenario_index < len(self.scenarios):
            scenario = self.scenarios[self.current_scenario_index]
            elapsed = time.time() - self.scenario_start_time
            remaining = max(0, scenario['duration'] - elapsed)
            
            status = f"\n🎬 실행 중: {scenario['name']}\n"
            status += f"📊 진행률: {elapsed:.1f}s / {scenario['duration']}s\n"
            status += f"⏰ 남은 시간: {remaining:.1f}s\n"
            status += f"📈 진행률: {(elapsed/scenario['duration']*100):.1f}%\n"
            
            # 현재 시스템 상태 표시
            status += "\n📋 현재 시스템 상태:\n"
            try:
                tank_level = self._receive(TAG.TAG_TANK_LEVEL_VALUE)
                bottle_level = self._receive(TAG.TAG_BOTTLE_LEVEL_VALUE)
                input_valve_mode = self._receive(TAG.TAG_TANK_INPUT_VALVE_MODE)
                output_valve_mode = self._receive(TAG.TAG_TANK_OUTPUT_VALVE_MODE)
                belt_mode = self._receive(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE)
                
                status += f"🚰 탱크 수위: {tank_level:.2f}\n"
                status += f"🍼 병 수위: {bottle_level:.2f}\n"
                status += f"⚙️  입력밸브 모드: {self._mode_to_string(input_valve_mode)}\n"
                status += f"⚙️  출력밸브 모드: {self._mode_to_string(output_valve_mode)}\n"
                status += f"⚙️  컨베이어 모드: {self._mode_to_string(belt_mode)}\n"
            except:
                status += "❌ 시스템 상태 정보를 가져올 수 없습니다.\n"
            
            self.report(status)

    def _mode_to_string(self, mode):
        """모드 값을 문자열로 변환"""
        mode_map = {1: "수동 OFF", 2: "수동 ON", 3: "자동"}
        return mode_map.get(mode, f"알 수 없음({mode})")

    def _operate(self):
        if not self.scenario_running:
            self._handle_menu_selection()
        else:
            self._execute_scenario()

    def _handle_menu_selection(self):
        """메뉴 선택 처리"""
        try:
            choice = input("\n선택하세요 (번호 입력): ")
            choice = int(choice)
            
            if 1 <= choice <= len(self.scenarios):
                self._start_scenario(choice - 1)
            elif choice == len(self.scenarios) + 1:
                self._start_all_scenarios()
            elif choice == len(self.scenarios) + 2:
                self.report("시나리오 러너를 종료합니다.", logging.INFO)
                self.stop()
            else:
                self.report("잘못된 선택입니다.", logging.WARNING)
                
        except ValueError:
            self.report("숫자를 입력해주세요.", logging.WARNING)
        except Exception as e:
            self.report(f"입력 처리 오류: {e}", logging.ERROR)

    def _start_scenario(self, index):
        """특정 시나리오 시작"""
        self.current_scenario_index = index
        self.scenario_start_time = time.time()
        self.scenario_running = True
        
        scenario = self.scenarios[index]
        self.report(f"🎬 시나리오 시작: {scenario['name']}", logging.INFO)
        self.report(f"📝 설명: {scenario['description']}", logging.INFO)

    def _start_all_scenarios(self):
        """모든 시나리오를 순차적으로 실행"""
        self.current_scenario_index = 0
        self._start_scenario(0)

    def _execute_scenario(self):
        """현재 시나리오 실행"""
        if self.current_scenario_index >= len(self.scenarios):
            self.scenario_running = False
            return

        scenario = self.scenarios[self.current_scenario_index]
        elapsed_time = time.time() - self.scenario_start_time
        
        # 시나리오 스텝 실행
        for step in scenario['steps']:
            step_time = step.get('time', 0)
            if abs(elapsed_time - step_time) < 1.0:  # 1초 오차 허용
                self._execute_step(step)
        
        # 시나리오 완료 확인
        if elapsed_time >= scenario['duration']:
            self._finish_current_scenario()

    def _execute_step(self, step):
        """시나리오 스텝 실행"""
        action = step.get('action')
        
        try:
            if action == 'set_mode':
                device = step.get('device')
                value = step.get('value')
                self._set_device_mode(device, value)
                
            elif action == 'set_parameter':
                parameter = step.get('parameter')
                value = step.get('value')
                self._set_system_parameter(parameter, value)
                
            elif action == 'log':
                message = step.get('message', '')
                self.report(f"📢 {message}", logging.INFO)
                
        except Exception as e:
            self.report(f"스텝 실행 오류: {e}", logging.ERROR)

    def _set_device_mode(self, device, mode):
        """장치 모드 설정"""
        device_tag_map = {
            'tank_input_valve': TAG.TAG_TANK_INPUT_VALVE_MODE,
            'tank_output_valve': TAG.TAG_TANK_OUTPUT_VALVE_MODE,
            'conveyor_belt_engine': TAG.TAG_CONVEYOR_BELT_ENGINE_MODE
        }
        
        if device in device_tag_map:
            tag = device_tag_map[device]
            self._send(tag, mode)
            mode_str = self._mode_to_string(mode)
            self.report(f"⚙️  {device} 모드를 {mode_str}로 설정했습니다.", logging.INFO)

    def _set_system_parameter(self, parameter, value):
        """시스템 파라미터 설정"""
        parameter_tag_map = {
            'tank_level_max': TAG.TAG_TANK_LEVEL_MAX,
            'tank_level_min': TAG.TAG_TANK_LEVEL_MIN,
            'bottle_level_max': TAG.TAG_BOTTLE_LEVEL_MAX
        }
        
        if parameter in parameter_tag_map:
            tag = parameter_tag_map[parameter]
            self._send(tag, value)
            self.report(f"📊 {parameter}를 {value}로 설정했습니다.", logging.INFO)

    def _finish_current_scenario(self):
        """현재 시나리오 완료 처리"""
        scenario = self.scenarios[self.current_scenario_index]
        self.report(f"✅ 시나리오 완료: {scenario['name']}", logging.INFO)
        
        # 다음 시나리오가 있는지 확인 (모든 시나리오 실행 모드인 경우)
        if self.current_scenario_index < len(self.scenarios) - 1:
            self.current_scenario_index += 1
            time.sleep(2)  # 2초 대기 후 다음 시나리오 시작
            self._start_scenario(self.current_scenario_index)
        else:
            self.scenario_running = False
            self.report("🎉 모든 시나리오가 완료되었습니다!", logging.INFO)

    def save_custom_scenario(self, scenario):
        """사용자 정의 시나리오 저장"""
        self.scenarios.append(scenario)
        if self.scenario_file:
            try:
                with open(self.scenario_file, 'w', encoding='utf-8') as f:
                    json.dump(self.scenarios, f, ensure_ascii=False, indent=2)
                self.report("사용자 정의 시나리오가 저장되었습니다.", logging.INFO)
            except Exception as e:
                self.report(f"시나리오 저장 실패: {e}", logging.ERROR)


if __name__ == '__main__':
    # 시나리오 파일을 사용하려면 파일 경로를 지정
    # runner = ScenarioRunner('scenarios.json')
    runner = ScenarioRunner()
    runner.start()