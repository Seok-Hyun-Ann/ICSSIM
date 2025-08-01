import logging
from datetime import datetime

from ics_sim.Device import HMI
from Configs import TAG, Controllers
from ConfigLockManager import config_lock_manager


class HMI1(HMI):
    def __init__(self):
        super().__init__('HMI1', TAG.TAG_LIST, Controllers.PLCs, 500)

        self._rows = {}
        self.title_length = 27
        self.msg1_length = 21
        self.msg2_length = 10
        self._border = '-' * (self.title_length + self.msg1_length + self.msg2_length + 4)

        self._border_top = \
            "┌" + "─" * self.title_length + "┬" + "─" * self.msg1_length + "┬" + "─" * self.msg2_length + "┐"
        self._border_mid = \
            "├" + "─" * self.title_length + "┼" + "─" * self.msg1_length + "┼" + "─" * self.msg2_length + "┤"
        self._border_bot = \
            "└" + "─" * self.title_length + "┴" + "─" * self.msg1_length + "┴" + "─" * self.msg2_length + "┘"

        self.cellVerticalLine = "│"

        for tag in self.tags:
            pos = tag.rfind('_')
            tag_name = tag[0:pos]
            if not self._rows.keys().__contains__(tag_name):
                self._rows[tag_name] = {'tag': tag_name.center(self.title_length, ' '), 'msg1': '', 'msg2': ''}

        self._latency = 0
        self.config_mode = False

    def _display(self):
        if self.config_mode:
            self.__show_config_menu()
        else:
            self.__show_table()

    def _operate(self):
        if self.config_mode:
            self.__handle_config_input()
        else:
            self.__update_massages()
            # 설정 모드 진입 확인
            try:
                choice = input("\nPress 'C' for configuration mode or Enter to continue: ").strip().upper()
                if choice == 'C':
                    self.__enter_config_mode()
            except (EOFError, KeyboardInterrupt):
                pass

    def __update_massages(self):
        self._latency = 0

        for row in self._rows:
            self._rows[row]['msg1'] = ''
            self._rows[row]['msg2'] = ''

        for tag in self.tags:
            pos = tag.rfind('_')
            row = tag[0:pos]
            attribute = tag[pos + 1:]

            if attribute == 'value' or attribute == 'status':
                self._rows[row]['msg2'] += self.__get_formatted_value(tag)
            elif attribute == 'max':
                self._rows[row]['msg1'] += self.__get_formatted_value(tag)
                self._rows[row]['msg1'] = self._make_text(self._rows[row]['msg1'].center(self.msg1_length, " "), self.COLOR_GREEN)
            else:
                self._rows[row]['msg1'] += self.__get_formatted_value(tag)

        for row in self._rows:
            if self._rows[row]['msg1'] == '':
                self._rows[row]['msg1'] = ''.center(self.msg1_length, ' ')
            if self._rows[row]['msg2'] == '':
                self._rows[row]['msg2'] = ''.center(self.msg1_length, ' ')

    def __get_formatted_value(self, tag):
        timestamp = datetime.now()
        pos = tag.rfind('_')
        tag_name = tag[0:pos]
        tag_attribute = tag[pos + 1:]

        try:
            value = self._receive(tag)
        except Exception as e:
            self.report(e.__str__(), logging.WARNING)
            value = 'NULL'

        if tag_attribute == 'mode':
            if value == 1:
                value = self._make_text('Off manually'.center(self.msg1_length, " "), self.COLOR_YELLOW)
            elif value == 2:
                value = self._make_text('On manually'.center(self.msg1_length, " "), self.COLOR_YELLOW)
            elif value == 3:
                value = self._make_text('Auto'.center(self.msg1_length, " "), self.COLOR_GREEN)
            else:

                value = self._make_text(str(value).center(self.msg1_length, " "), self.COLOR_RED)

        elif tag_attribute == 'status' or self.tags[tag]['id'] == 7:
            if value == 'NULL':
                value = self._make_text(value.center(self.msg2_length, " "), self.COLOR_RED)
            elif value:
                value = self._make_text('>>>'.center(self.msg2_length, " "), self.COLOR_BLUE)
            else:
                value = self._make_text('X'.center(self.msg2_length, " "), self.COLOR_RED)

        elif tag_attribute == 'min':
            value = 'Min:' + str(value) + ' '

        elif tag_attribute == 'max':
            value = 'Max:' + str(value)

        elif value == 'NULL':
            value = self._make_text(value.center(self.msg2_length, " "), self.COLOR_RED)
        else:
            value = self._make_text(str(value).center(self.msg2_length, " "), self.COLOR_CYAN)

        elapsed = datetime.now() - timestamp

        if elapsed.microseconds > self._latency:
            self._latency = elapsed.microseconds
        return value

    def __show_table(self):
        result = " (Latency {}ms)\n".format(self._latency / 1000)

        first = True
        for row in self._rows:
            if first:
                result += self._border_top + "\n"
                first = False
            else:
                result += self._border_mid + "\n"

            result += '│{}│{}│{}│\n'.format(self._rows[row]['tag'], self._rows[row]['msg1'], self._rows[row]['msg2'])

        result += self._border_bot + "\n"

        self.report(result)

    def __enter_config_mode(self):
        """설정 모드 진입"""
        if config_lock_manager.acquire_lock('HMI1'):
            self.config_mode = True
            self.report(self._make_text("Configuration mode activated!", self.COLOR_GREEN))
        else:
            lock_status = config_lock_manager.get_lock_status()
            if lock_status['locked']:
                self.report(self._make_text(f"Configuration locked by {lock_status['hmi_name']}", self.COLOR_RED))
            else:
                self.report(self._make_text("Failed to acquire configuration lock", self.COLOR_RED))

    def __exit_config_mode(self):
        """설정 모드 종료"""
        if config_lock_manager.release_lock('HMI1'):
            self.config_mode = False
            self.report(self._make_text("Configuration mode deactivated!", self.COLOR_YELLOW))
        else:
            self.report(self._make_text("Failed to release configuration lock", self.COLOR_RED))

    def __show_config_menu(self):
        """설정 메뉴 표시"""
        lock_status = config_lock_manager.get_lock_status()
        
        menu = "\n" + self._make_text("=== CONFIGURATION MODE ===", self.COLOR_GREEN) + "\n\n"
        
        if lock_status['locked'] and lock_status['hmi_name'] == 'HMI1':
            menu += self._make_text("Configuration Lock: ACQUIRED", self.COLOR_GREEN) + "\n"
            menu += f"Lock expires at: {lock_status['expires_at']}\n\n"
            
            menu += self._make_text("Sensor/Actuator Configuration:", self.COLOR_CYAN) + "\n"
            menu += "1) Set Tank Level Min\n"
            menu += "2) Set Tank Level Max\n"
            menu += "3) Set Bottle Level Max\n"
            menu += "4) Set Tank Input Valve Mode\n"
            menu += "5) Set Tank Output Valve Mode\n"
            menu += "6) Set Conveyor Belt Engine Mode\n\n"
            menu += "E) Exit Configuration Mode\n"
            menu += "R) Refresh Lock\n"
        else:
            menu += self._make_text("Configuration Lock: NOT AVAILABLE", self.COLOR_RED) + "\n"
            if lock_status['locked']:
                menu += f"Locked by: {lock_status['hmi_name']}\n"
                menu += f"Lock expires at: {lock_status['expires_at']}\n"
            menu += "\nE) Exit Configuration Mode\n"
            menu += "T) Try to acquire lock\n"
        
        self.report(menu)

    def __handle_config_input(self):
        """설정 입력 처리"""
        try:
            choice = input('Your choice: ').strip().upper()
            
            if choice == 'E':
                self.__exit_config_mode()
            elif choice == 'T':
                self.__enter_config_mode()
            elif choice == 'R':
                if config_lock_manager.acquire_lock('HMI1'):
                    self.report(self._make_text("Lock refreshed!", self.COLOR_GREEN))
                else:
                    self.report(self._make_text("Failed to refresh lock", self.COLOR_RED))
            elif choice in ['1', '2', '3', '4', '5', '6']:
                self.__execute_config_command(int(choice))
            else:
                self.report("Invalid choice!")
                
        except (ValueError, EOFError, KeyboardInterrupt):
            self.report("Invalid input!")
        
        input('Press enter to continue...')

    def __execute_config_command(self, choice):
        """설정 명령 실행"""
        lock_status = config_lock_manager.get_lock_status()
        if not (lock_status['locked'] and lock_status['hmi_name'] == 'HMI1'):
            self.report(self._make_text("Configuration lock not held by HMI1!", self.COLOR_RED))
            return
        
        try:
            if choice <= 3:
                # 수치 설정값
                value = float(input('Enter new value (positive real number): '))
                if value < 0:
                    raise ValueError('Negative numbers are not acceptable.')
                
                if choice == 1:
                    self._send(TAG.TAG_TANK_LEVEL_MIN, value)
                    self.report(self._make_text(f"Tank Level Min set to {value}", self.COLOR_GREEN))
                elif choice == 2:
                    self._send(TAG.TAG_TANK_LEVEL_MAX, value)
                    self.report(self._make_text(f"Tank Level Max set to {value}", self.COLOR_GREEN))
                elif choice == 3:
                    self._send(TAG.TAG_BOTTLE_LEVEL_MAX, value)
                    self.report(self._make_text(f"Bottle Level Max set to {value}", self.COLOR_GREEN))
            else:
                # 모드 설정
                self.report("\n1) Manually Off\n2) Manually On\n3) Auto Operation")
                mode = int(input('Select mode (1-3): '))
                if mode < 1 or mode > 3:
                    raise ValueError('Only 1, 2, and 3 are acceptable')
                
                if choice == 4:
                    self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, mode)
                    self.report(self._make_text(f"Tank Input Valve Mode set to {mode}", self.COLOR_GREEN))
                elif choice == 5:
                    self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, mode)
                    self.report(self._make_text(f"Tank Output Valve Mode set to {mode}", self.COLOR_GREEN))
                elif choice == 6:
                    self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, mode)
                    self.report(self._make_text(f"Conveyor Belt Engine Mode set to {mode}", self.COLOR_GREEN))
                    
        except ValueError as e:
            self.report(self._make_text(f"Invalid input: {e}", self.COLOR_RED))
        except Exception as e:
            self.report(self._make_text(f"Error executing command: {e}", self.COLOR_RED))


if __name__ == '__main__':
    hmi1 = HMI1()
    hmi1.start()
