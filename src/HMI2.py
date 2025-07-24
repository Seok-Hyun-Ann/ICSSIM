import logging
import os
import sys
import time
import random
import threading

from ics_sim.Device import HMI
from Configs import TAG, Controllers


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

    def _before_start(self):
        HMI._before_start(self)
        
        while True:
            response = input("Do you want to enable automatic attack mode? (y/n): ")
            response = response.lower()
            if response == 'y' or response == 'yes':
                self.attack_mode = True
                self._set_clear_scr(False)
                self.report("Automatic attack mode enabled!", logging.INFO)
                break
            elif response == 'n' or response == 'no':
                self.attack_mode = False
                break
            else:
                continue

    def _display(self):
        menu_line = '{}) To change the {} press {} \n'

        menu = '\n'
        
        if self.attack_mode:
            menu += self._make_text("=== ATTACK MODE ENABLED ===", self.COLOR_RED) + '\n'
            menu += self.__get_menu_line('A', 'start/stop automatic attacks')
            menu += self.__get_menu_line('R', 'perform random attack now')
            menu += '\n'

        menu += self.__get_menu_line(1, 'empty level of tank')
        menu += self.__get_menu_line(2, 'full level of tank')
        menu += self.__get_menu_line(3, 'full level of bottle')
        menu += self.__get_menu_line(4, 'status of tank Input valve')
        menu += self.__get_menu_line(5, 'status of tank output valve')
        menu += self.__get_menu_line(6, 'status of conveyor belt engine')
        
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
                choice = input('your choice (1-6, A for auto-attack, R for random attack): ')
            else:
                choice = input('your choice (1 to 6): ')
                
            if choice.upper() == 'A' and self.attack_mode:
                self._toggle_auto_attack()
            elif choice.upper() == 'R' and self.attack_mode:
                self._perform_random_attack()
            else:
                choice = int(choice)
                input1, input2 = choice, None
                
                if input1 < 1 or input1 > 6:
                    raise ValueError('just integer values between 1 and 6 are acceptable')

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
                # Random sleep between 5-20 seconds like HMI3
                sleep_time = random.randint(5, 20)
                self.report(f"Next attack in {sleep_time} seconds...", logging.INFO)
                
                for i in range(sleep_time):
                    if not self.attack_running:
                        return
                    time.sleep(1)
                
                if self.attack_running:
                    self._perform_random_attack()
                    
            except Exception as e:
                self.report(f"Attack error: {e}", logging.ERROR)

    def _perform_random_attack(self):
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
            
            attack_msg = f"ATTACK: Set {param_info[0]} to {attack_value:.2f}"
            self.report(self._make_text(attack_msg, self.COLOR_RED), logging.WARNING)
            
        except Exception as e:
            self.report(f"Random attack failed: {e}", logging.ERROR)


if __name__ == '__main__':
    hmi2 = HMI2()
    hmi2.start()