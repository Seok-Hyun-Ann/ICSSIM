import logging
import os
import sys
import time
import random
import threading
from datetime import datetime, timedelta

from ics_sim.Device import HMI
from Configs import TAG, Controllers
from ConfigLockManager import config_lock_manager
from ics_sim.Attacks import _do_scan_scapy_attack, _do_replay_scapy_attack, _do_mitm_scapy_attack, \
    _do_scan_nmap_attack, _do_command_injection_attack, _do_ddos_attack


class HMI2(HMI):
    def __init__(self):
        super().__init__('HMI2', TAG.TAG_LIST, Controllers.PLCs)
        self.attack_mode = False
        self.attack_thread = None
        self.attack_running = False
        self.random_values = [
            ["TANK LEVEL MIN", 1, 4.5], 
            ["TANK LEVEL MAX", 5.5, 9], 
            ["BOTTLE LEVEL MAX", 1, 1.9]
        ]
        
        # Attack configuration
        self.log_path = os.path.join('.', 'logs', 'attack-logs')
        if not os.path.exists(self.log_path):
            os.makedirs(self.log_path)
            
        # Attack history logger
        self.attack_history = self._setup_attack_logger()
        
        # Available attacks
        self.available_attacks = {
            '1': 'scan-scapy',
            '2': 'scan-nmap', 
            '3': 'ddos',
            '4': 'mitm-scapy',
            '5': 'replay-scapy',
            '6': 'command-injection'
        }

    def _setup_attack_logger(self):
        """Setup attack history logger"""
        attack_history = self.setup_logger(
            f'{self.name()}_attack_history',
            logging.Formatter('%(message)s'),
            file_dir=self.log_path,
            file_ext='.csv'
        )
        
        attack_history.info(
            "{},{},{},{},{},{},{},{}"
            .format("attack", "startStamp", "endStamp", "startTime", "endTime", "attackerName", "target", "description")
        )
        
        return attack_history

    def _before_start(self):
        HMI._before_start(self)
        
        while True:
            response = input("Do you want to enable attack mode? (y/n): ")
            response = response.lower()
            if response == 'y' or response == 'yes':
                self.attack_mode = True
                self._set_clear_scr(False)
                self.report("Attack mode enabled!", logging.INFO)
                break
            elif response == 'n' or response == 'no':
                self.attack_mode = False
                break
            else:
                continue

    def _display(self):
        menu_line = '{}) To change the {} press {} \n'

        menu = '\n'
        
        # 설정 락 상태 표시
        lock_status = config_lock_manager.get_lock_status()
        if lock_status['locked']:
            if lock_status['hmi_name'] == 'HMI2':
                menu += self._make_text("=== CONFIGURATION LOCK: ACQUIRED ===", self.COLOR_GREEN) + '\n'
            else:
                menu += self._make_text(f"=== CONFIGURATION LOCKED BY {lock_status['hmi_name']} ===", self.COLOR_RED) + '\n'
            menu += f"Lock expires at: {lock_status['expires_at']}\n\n"
        else:
            menu += self._make_text("=== CONFIGURATION LOCK: AVAILABLE ===", self.COLOR_CYAN) + '\n\n'
        
        if self.attack_mode:
            menu += self._make_text("=== ATTACK MODE ENABLED ===", self.COLOR_RED) + '\n'
            menu += self.__get_menu_line('A', 'start/stop automatic attacks')
            menu += self.__get_menu_line('R', 'perform random attack now')
            menu += '\n'
            menu += self._make_text("=== AVAILABLE ATTACKS ===", self.COLOR_YELLOW) + '\n'
            menu += self.__get_menu_line('S1', 'Scapy Scan Attack')
            menu += self.__get_menu_line('S2', 'Nmap Scan Attack')  
            menu += self.__get_menu_line('S3', 'DDoS Attack')
            menu += self.__get_menu_line('S4', 'MITM Attack')
            menu += self.__get_menu_line('S5', 'Replay Attack')
            menu += self.__get_menu_line('S6', 'Command Injection Attack')
            menu += '\n'

        # 설정 변경 메뉴 (락 상태에 따라 표시)
        if lock_status['locked'] and lock_status['hmi_name'] == 'HMI2':
            menu += self._make_text("=== CONFIGURATION COMMANDS (UNLOCKED) ===", self.COLOR_GREEN) + '\n'
            menu += self.__get_menu_line(1, 'empty level of tank')
            menu += self.__get_menu_line(2, 'full level of tank')
            menu += self.__get_menu_line(3, 'full level of bottle')
            menu += self.__get_menu_line(4, 'status of tank Input valve')
            menu += self.__get_menu_line(5, 'status of tank output valve')
            menu += self.__get_menu_line(6, 'status of conveyor belt engine')
            menu += self.__get_menu_line('L', 'release configuration lock')
        elif not lock_status['locked']:
            menu += self._make_text("=== CONFIGURATION COMMANDS (LOCKED - ACQUIRE FIRST) ===", self.COLOR_YELLOW) + '\n'
            menu += self.__get_menu_line('L', 'acquire configuration lock')
            menu += "1-6) Configuration commands (requires lock)\n"
        else:
            menu += self._make_text("=== CONFIGURATION COMMANDS (LOCKED BY OTHER HMI) ===", self.COLOR_RED) + '\n'
            menu += "1-6) Configuration commands (unavailable)\n"
        
        if self.attack_mode and self.attack_running:
            menu += '\n' + self._make_text("Automatic attacks are running...", self.COLOR_YELLOW) + '\n'
            
        self.report(menu)

    def __get_menu_line(self, number, text):
        return '{} To change the {} press {} \n'.format(
            self._make_text(str(number)+')', self.COLOR_BLUE),
            self._make_text(text, self.COLOR_GREEN),
            self._make_text(str(number), self.COLOR_BLUE)
        )

    def _operate(self):
        try:
            if self.attack_mode:
                choice = input('your choice (1-6, L for lock, A for auto-attack, R for random attack, S1-S6 for specific attacks): ')
            else:
                choice = input('your choice (1-6, L for lock): ')
                
            if choice.upper() == 'L':
                self._handle_lock_command()
            elif choice.upper() == 'A' and self.attack_mode:
                self._toggle_auto_attack()
            elif choice.upper() == 'R' and self.attack_mode:
                self._perform_random_attack()
            elif choice.upper().startswith('S') and self.attack_mode:
                attack_num = choice.upper()[1:]
                if attack_num in self.available_attacks:
                    self._execute_specific_attack(self.available_attacks[attack_num])
                else:
                    raise ValueError('Invalid attack selection')
            else:
                choice = int(choice)
                input1, input2 = choice, None
                
                if input1 < 1 or input1 > 6:
                    raise ValueError('just integer values between 1 and 6 are acceptable')

                # 설정 변경 권한 확인
                lock_status = config_lock_manager.get_lock_status()
                if not (lock_status['locked'] and lock_status['hmi_name'] == 'HMI2'):
                    if lock_status['locked']:
                        raise ValueError(f'Configuration is locked by {lock_status["hmi_name"]}. Cannot modify settings.')
                    else:
                        raise ValueError('Configuration lock not acquired. Use "L" to acquire lock first.')

                if input1 <= 3:
                    input2 = float(input('Specify set point (positive real value): '))
                    if input2 < 0:
                        raise ValueError('Negative numbers are not acceptable.')
                else:
                    sub_menu = '\n'
                    sub_menu += "1) Send command for manually off\n"
                    sub_menu += "2) Send command for manually on\n"
                    sub_menu += "3) Send command for auto operation\n"
                    self.report(sub_menu)
                    input2 = int(input('Command (1 to 3): '))
                    if input2 < 1 or input2 > 3:
                        raise ValueError('Just 1, 2, and 3 are acceptable for command')

                self._execute_command(input1, input2)

        except ValueError as e:
            self.report(e.__str__())
        except Exception as e:
            self.report('The input is invalid' + e.__str__())

        input('press enter to continue ...')

    def _execute_command(self, input1, input2):
        if input1 == 1:
            self._send(TAG.TAG_TANK_LEVEL_MIN, input2)
        elif input1 == 2:
            self._send(TAG.TAG_TANK_LEVEL_MAX, input2)
        elif input1 == 3:
            self._send(TAG.TAG_BOTTLE_LEVEL_MAX, input2)
        elif input1 == 4:
            self._send(TAG.TAG_TANK_INPUT_VALVE_MODE, input2)
        elif input1 == 5:
            self._send(TAG.TAG_TANK_OUTPUT_VALVE_MODE, input2)
        elif input1 == 6:
            self._send(TAG.TAG_CONVEYOR_BELT_ENGINE_MODE, input2)

    def _execute_specific_attack(self, attack_name):
        """Execute a specific attack type"""
        self.report(f"Executing {attack_name} attack...", logging.WARNING)
        
        if attack_name == 'scan-scapy':
            self._scan_scapy_attack()
        elif attack_name == 'scan-nmap':
            self._scan_nmap_attack()
        elif attack_name == 'ddos':
            self._ddos_attack()
        elif attack_name == 'mitm-scapy':
            self._mitm_scapy_attack()
        elif attack_name == 'replay-scapy':
            self._replay_scapy_attack()
        elif attack_name == 'command-injection':
            self._command_injection_attack()
        else:
            self.report(f"Unknown attack: {attack_name}", logging.ERROR)

    def _scan_scapy_attack(self, target='192.168.0.1/24', timeout=10):
        """Perform Scapy-based network scan attack"""
        attack_name = 'scan-scapy'
        log_file = os.path.join(self.log_path, f'log-{attack_name}.txt')
        
        start = datetime.now()
        self.report(f"Starting {attack_name} attack on {target}...", logging.WARNING)
        
        try:
            _do_scan_scapy_attack(log_dir=self.log_path, log_file=log_file, target=target, timeout=timeout)
            end = datetime.now()
            self._log_attack_history(attack_name, start, end, target)
            self.report(f"{attack_name} attack completed successfully!", logging.INFO)
        except Exception as e:
            self.report(f"{attack_name} attack failed: {e}", logging.ERROR)

    def _scan_nmap_attack(self, target='192.168.0.1-255'):
        """Perform Nmap-based port scan attack"""
        attack_name = 'scan-nmap'
        log_file = os.path.join(self.log_path, f'log-{attack_name}.txt')
        
        start = datetime.now()
        self.report(f"Starting {attack_name} attack on {target}...", logging.WARNING)
        
        try:
            _do_scan_nmap_attack(log_dir=self.log_path, log_file=log_file, target=target)
            end = datetime.now()
            self._log_attack_history(attack_name, start, end, target)
            self.report(f"{attack_name} attack completed successfully!", logging.INFO)
        except Exception as e:
            self.report(f"{attack_name} attack failed: {e}", logging.ERROR)

    def _ddos_attack(self, ddos_agent_path='DDosAgent.py', timeout=30, num_process=5, target='192.168.0.11'):
        """Perform DDoS attack"""
        attack_name = 'ddos'
        log_file = os.path.join(self.log_path, f'log-{attack_name}.txt')
        
        start = datetime.now()
        self.report(f"Starting {attack_name} attack on {target} with {num_process} processes for {timeout}s...", logging.WARNING)
        
        try:
            _do_ddos_attack(log_dir=self.log_path, log_file=log_file, ddos_agent_path=ddos_agent_path, 
                          timeout=timeout, num_process=num_process, target=target)
            end = datetime.now()
            self._log_attack_history(attack_name, start, end, target)
            self.report(f"{attack_name} attack completed successfully!", logging.INFO)
        except Exception as e:
            self.report(f"{attack_name} attack failed: {e}", logging.ERROR)

    def _mitm_scapy_attack(self, timeout=20, noise=0.1, target='192.168.0.1/24'):
        """Perform Man-in-the-Middle attack"""
        attack_name = 'mitm-scapy'
        log_file = os.path.join(self.log_path, f'log-{attack_name}.txt')
        
        start = datetime.now()
        self.report(f"Starting {attack_name} attack on {target} for {timeout}s with noise {noise}...", logging.WARNING)
        
        try:
            _do_mitm_scapy_attack(log_dir=self.log_path, log_file=log_file, timeout=timeout, noise=noise, target=target)
            end = datetime.now()
            self._log_attack_history(attack_name, start, end, target)
            self.report(f"{attack_name} attack completed successfully!", logging.INFO)
        except Exception as e:
            self.report(f"{attack_name} attack failed: {e}", logging.ERROR)

    def _replay_scapy_attack(self, timeout=15, replay_count=3, target='192.168.0.11,192.168.0.22'):
        """Perform Replay attack"""
        attack_name = 'replay-scapy'
        log_file = os.path.join(self.log_path, f'log-{attack_name}.txt')
        
        start = datetime.now()
        self.report(f"Starting {attack_name} attack on {target} for {timeout}s with {replay_count} replays...", logging.WARNING)
        
        try:
            _do_replay_scapy_attack(log_dir=self.log_path, log_file=log_file, timeout=timeout, 
                                  replay_count=replay_count, target=target)
            end = datetime.now()
            self._log_attack_history(attack_name, start, end, target)
            self.report(f"{attack_name} attack completed successfully!", logging.INFO)
        except Exception as e:
            self.report(f"{attack_name} attack failed: {e}", logging.ERROR)

    def _command_injection_attack(self, command_injection_agent='CommandInjectionAgent.py', command_counter=30):
        """Perform Command Injection attack"""
        attack_name = 'command-injection'
        log_file = os.path.join(self.log_path, f'log-{attack_name}.txt')
        
        start = datetime.now()
        self.report(f"Starting {attack_name} attack with {command_counter} commands...", logging.WARNING)
        
        try:
            _do_command_injection_attack(log_dir=self.log_path, log_file=log_file,
                                       command_injection_agent=command_injection_agent, 
                                       command_counter=command_counter)
            end = datetime.now()
            self._log_attack_history(attack_name, start, end, "PLC_VALVES")
            self.report(f"{attack_name} attack completed successfully!", logging.INFO)
        except Exception as e:
            self.report(f"{attack_name} attack failed: {e}", logging.ERROR)

    def _log_attack_history(self, attack_name, start_time, end_time, target):
        """Log attack history to CSV"""
        self.attack_history.info(
            "{},{},{},{},{},{},{},{}".format(
                attack_name,
                start_time.timestamp(), 
                end_time.timestamp(), 
                start_time, 
                end_time, 
                self.name(),
                target,
                f"HMI2_{attack_name}_attack"
            )
        )

    def _toggle_auto_attack(self):
        if self.attack_running:
            self.attack_running = False
            if self.attack_thread:
                self.attack_thread.join()
            self.report("Automatic attacks stopped.", logging.INFO)
        else:
            self.attack_running = True
            self.attack_thread = threading.Thread(target=self._auto_attack_loop)
            self.attack_thread.daemon = True
            self.attack_thread.start()
            self.report("Automatic attacks started.", logging.WARNING)

    def _auto_attack_loop(self):
        while self.attack_running:
            try:
                # Random sleep between 10-30 seconds for attacks
                sleep_time = random.randint(10, 30)
                self.report(f"Next attack in {sleep_time} seconds...", logging.INFO)
                
                for i in range(sleep_time):
                    if not self.attack_running:
                        return
                    time.sleep(1)
                
                if self.attack_running:
                    # Randomly choose between parameter attack and cyber attack
                    attack_type = random.choice(['parameter', 'cyber'])
                    
                    if attack_type == 'parameter':
                        self._perform_random_attack()
                    else:
                        self._perform_random_cyber_attack()
                    
            except Exception as e:
                self.report(f"Auto attack error: {e}", logging.ERROR)

    def _perform_random_attack(self):
        """Perform random parameter manipulation attack"""
        try:
            # Choose random parameter to attack
            choice = random.randint(1, len(self.random_values))
            param_info = self.random_values[choice-1]
            
            # Generate random value within the specified range
            attack_value = random.uniform(param_info[1], param_info[2])
            
            # Execute the attack
            if choice == 1:
                self._send(TAG.TAG_TANK_LEVEL_MIN, attack_value)
            elif choice == 2:
                self._send(TAG.TAG_TANK_LEVEL_MAX, attack_value)
            elif choice == 3:
                self._send(TAG.TAG_BOTTLE_LEVEL_MAX, attack_value)
            
            attack_msg = f"PARAMETER ATTACK: Set {param_info[0]} to {attack_value:.2f}"
            self.report(self._make_text(attack_msg, self.COLOR_RED), logging.WARNING)
            
        except Exception as e:
            self.report(f"Random parameter attack failed: {e}", logging.ERROR)

    def _perform_random_cyber_attack(self):
        """Perform random cyber attack from the 5 available types"""
        try:
            # Choose random attack from available attacks
            attack_choices = list(self.available_attacks.values())
            chosen_attack = random.choice(attack_choices)
            
            attack_msg = f"CYBER ATTACK: Executing {chosen_attack}"
            self.report(self._make_text(attack_msg, self.COLOR_RED), logging.WARNING)
            
            # Execute with reduced parameters for automatic mode
            if chosen_attack == 'scan-scapy':
                self._scan_scapy_attack(timeout=5)
            elif chosen_attack == 'scan-nmap':
                self._scan_nmap_attack()
            elif chosen_attack == 'ddos':
                self._ddos_attack(timeout=10, num_process=3)
            elif chosen_attack == 'mitm-scapy':
                self._mitm_scapy_attack(timeout=10)
            elif chosen_attack == 'replay-scapy':
                self._replay_scapy_attack(timeout=10, replay_count=2)
            elif chosen_attack == 'command-injection':
                self._command_injection_attack(command_counter=10)
                
        except Exception as e:
            self.report(f"Random cyber attack failed: {e}", logging.ERROR)

    def _handle_lock_command(self):
        """설정 락 명령 처리"""
        lock_status = config_lock_manager.get_lock_status()
        
        if lock_status['locked'] and lock_status['hmi_name'] == 'HMI2':
            # 현재 HMI2가 락을 보유한 경우 - 해제
            if config_lock_manager.release_lock('HMI2'):
                self.report(self._make_text("Configuration lock released!", self.COLOR_YELLOW))
            else:
                self.report(self._make_text("Failed to release configuration lock", self.COLOR_RED))
        elif not lock_status['locked']:
            # 락이 없는 경우 - 획득
            if config_lock_manager.acquire_lock('HMI2'):
                self.report(self._make_text("Configuration lock acquired!", self.COLOR_GREEN))
            else:
                self.report(self._make_text("Failed to acquire configuration lock", self.COLOR_RED))
        else:
            # 다른 HMI가 락을 보유한 경우
            self.report(self._make_text(f"Configuration is locked by {lock_status['hmi_name']}", self.COLOR_RED))
            self.report(f"Lock expires at: {lock_status['expires_at']}")


if __name__ == '__main__':
    hmi2 = HMI2()
    hmi2.start()