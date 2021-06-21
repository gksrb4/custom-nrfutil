# modified by dfu_transport_serial.py

# Python imports
import time
from datetime import datetime, timedelta
import binascii
import logging
import struct
import socket

# Python 3rd party imports
from serial import Serial
from serial.serialutil import SerialException

# Nordic Semiconductor imports
from nordicsemi.dfu.dfu_transport   import DfuTransport, DfuEvent, TRANSPORT_LOGGING_LEVEL
from pc_ble_driver_py.exceptions    import NordicSemiException
from nordicsemi.lister.device_lister import DeviceLister
from nordicsemi.dfu.dfu_trigger import DFUTrigger
from nordicsemi.dfu.dfu_transport_serial import DfuTransportSerial

class ValidationException(NordicSemiException):
    """"
    Exception used when validation failed
    """
    pass


logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)

class Slip:
    SLIP_BYTE_END             = 0o300
    SLIP_BYTE_ESC             = 0o333
    SLIP_BYTE_ESC_END         = 0o334
    SLIP_BYTE_ESC_ESC         = 0o335

    SLIP_STATE_DECODING                 = 1
    SLIP_STATE_ESC_RECEIVED             = 2
    SLIP_STATE_CLEARING_INVALID_PACKET  = 3

    @staticmethod
    def encode(data):
        newData = []
        for elem in data:
            if elem == Slip.SLIP_BYTE_END:
                newData.append(Slip.SLIP_BYTE_ESC)
                newData.append(Slip.SLIP_BYTE_ESC_END)
            elif elem == Slip.SLIP_BYTE_ESC:
                newData.append(Slip.SLIP_BYTE_ESC)
                newData.append(Slip.SLIP_BYTE_ESC_ESC)
            else:
                newData.append(elem)
        newData.append(Slip.SLIP_BYTE_END)
        return newData

    @staticmethod
    def decode_add_byte(c, decoded_data, current_state):
        finished = False
        if current_state == Slip.SLIP_STATE_DECODING:
            if c == Slip.SLIP_BYTE_END:
                finished = True
            elif c == Slip.SLIP_BYTE_ESC:
                current_state = Slip.SLIP_STATE_ESC_RECEIVED
            else:
                decoded_data.append(c)
        elif current_state == Slip.SLIP_STATE_ESC_RECEIVED:
            if c == Slip.SLIP_BYTE_ESC_END:
                decoded_data.append(Slip.SLIP_BYTE_END)
                current_state = Slip.SLIP_STATE_DECODING
            elif c == Slip.SLIP_BYTE_ESC_ESC:
                decoded_data.append(Slip.SLIP_BYTE_ESC)
                current_state = Slip.SLIP_STATE_DECODING
            else:
                current_state = Slip.SLIP_STATE_CLEARING_INVALID_PACKET
        elif current_state == Slip.SLIP_STATE_CLEARING_INVALID_PACKET:
            if c == Slip.SLIP_BYTE_END:
                current_state = Slip.SLIP_STATE_DECODING
                decoded_data = []

        return (finished, current_state, decoded_data)

class DFUAdapter:
    def __init__(self, socket):
        self.socket = socket

    def send_message(self, data):
        packet = Slip.encode(data)
        logger.log(TRANSPORT_LOGGING_LEVEL, f'SLIP[{len(data)}]: --> ' + str(data))
        try:
            self.socket.sendall(bytearray(packet))
        except SerialException as e:
            raise NordicSemiException('Sending to tcp/ip failed: ' + str(e) + '. '
                                      'If MSD is enabled on the target device, try to disable it ref. '
                                      'https://wiki.segger.com/index.php?title=J-Link-OB_SAM3U')

    def get_message(self):
        current_state = Slip.SLIP_STATE_DECODING
        finished = False
        decoded_data = []

        while finished == False:
            byte = self.socket.recv(1)
            if byte:
                (byte) = struct.unpack('B', byte)[0]
                (finished, current_state, decoded_data) \
                   = Slip.decode_add_byte(byte, decoded_data, current_state)
            else:
                current_state = Slip.SLIP_STATE_CLEARING_INVALID_PACKET
                return None

        logger.log(TRANSPORT_LOGGING_LEVEL, f'SLIP[{len(decoded_data)}]: <-- ' + str(decoded_data))

        return decoded_data

class DfuTransportTCP(DfuTransport):
    DFU_TCPIP_TRIGGER_REQ_CMD =            0x2323
    DFU_TCPIP_TRIGGER_RESP_CMD =           0x2324
    DFU_TCPIP_TRIGGER_SUB_CMD =            0xDEAD
    DFU_TCPIP_TRIGGER_RET_BOOT =           0x0001
    DFU_TCPIP_DFU_FILE_REQ_CMD =           0x3434
    DFU_TCPIP_DFU_FILE_RESP_CMD =          0x3435
    DFU_TCPIP_DFU_FILE_SUB_CMD_START =     0xDF00
    DFU_TCPIP_DFU_FILE_SUB_CMD_WRITE =     0xDF01
    DFU_TCPIP_DFU_FILE_SUB_CMD_CRC_CHECK = 0xDF02

    DEFAULT_PORT = 5000
    DEFAULT_SOCKET_TIMEOUT = 10.0  # Timeout time for opennig socket
    DEFAULT_TIMEOUT = 10.0  # Timeout time for board response
    DEFAULT_PRN                 = 1
    DEFAULT_DO_PING = True
    DEFAULT_TRANSFER_FILE = False
    
    OP_CODE = {
        'CreateObject'          : 0x01,
        'SetPRN'                : 0x02,
        'CalcChecSum'           : 0x03,
        'Execute'               : 0x04,
        'ReadError'             : 0x05,
        'ReadObject'            : 0x06,
        'GetSerialMTU'          : 0x07,
        'WriteObject'           : 0x08,
        'Ping'                  : 0x09,
        'Response'              : 0x60,
    }

    def __init__(self,
                 host,
                 port=DEFAULT_PORT,
                 socket_timeout=DEFAULT_SOCKET_TIMEOUT,
                 timeout=DEFAULT_TIMEOUT,
                 prn=DEFAULT_PRN,
                 do_ping=DEFAULT_DO_PING,
                 transfer_file=DEFAULT_TRANSFER_FILE):

        super().__init__()
        self.host = host
        self.port = port
        self.socket_timeout = socket_timeout
        self.timeout = timeout
        self.prn         = prn
        self.do_ping     = do_ping

        self.mtu         = 0
        self.ping_id     = 0

        self.dfu_adapter = None
        self.client_socket = None
        self.transfer_file = transfer_file
        # self.socket = None
        """:type: serial.Serial """


    def open(self):
        super().open()
        start = time.time()
        try:
            print('open client socket.')
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(self.socket_timeout)
            if not self.transfer_file:
                self.client_socket.connect((self.host, self.port))
                self.__ensure_bootloader()
            else:
                self.client_socket.connect((self.host, self.port))
                self.__transfer_file()
            self.dfu_adapter = DFUAdapter(self.client_socket)
        except Exception as e:
            end = time.time()
            raise NordicSemiException("TCP/IP socket could not be opened. Reason: {}, waiting secs: {}".format(e, end-start))

        if self.do_ping:
            ping_success = False
            start = datetime.now()
            while (datetime.now() - start < timedelta(seconds=self.timeout)
                    and ping_success == False):
                if self.__ping() == True:
                    ping_success = True

            if ping_success == False:
                raise NordicSemiException("No ping response after opening COM port")

        self.__set_prn()
        self.__get_mtu()

    def close(self):
        super().close()
        print('close client socket.')
        self.client_socket.close()

    def jump_from_buttonless_mode_to_bootloader(self):
        pass

    def send_init_packet(self, init_packet):
        def try_to_recover():
            if response['offset'] == 0 or response['offset'] > len(init_packet):
                # There is no init packet or present init packet is too long.
                return False

            expected_crc = (binascii.crc32(init_packet[:response['offset']]) & 0xFFFFFFFF)

            if expected_crc != response['crc']:
                # Present init packet is invalid.
                return False

            if len(init_packet) > response['offset']:
                # Send missing part.
                try:
                    self.__stream_data(data     = init_packet[response['offset']:],
                                       crc      = expected_crc,
                                       offset   = response['offset'])
                except ValidationException:
                    return False

            self.__execute()
            return True

        response = self.__select_command()
        assert len(init_packet) <= response['max_size'], 'Init command is too long'

        if try_to_recover():
            return

        try:
            self.__create_command(len(init_packet))
            self.__stream_data(data=init_packet)
            self.__execute()
        except ValidationException:
            raise NordicSemiException("Failed to send init packet")

    def send_firmware(self, firmware):
        def try_to_recover():
            if response['offset'] == 0:
                # Nothing to recover
                return
            expected_crc = binascii.crc32(firmware[:response['offset']]) & 0xFFFFFFFF
            remainder    = response['offset'] % response['max_size']

            if expected_crc != response['crc']:
                # Invalid CRC. Remove corrupted data.
                response['offset'] -= remainder if remainder != 0 else response['max_size']
                response['crc']     = \
                        binascii.crc32(firmware[:response['offset']]) & 0xFFFFFFFF
                return

            if (remainder != 0) and (response['offset'] != len(firmware)):
                # Send rest of the page.
                try:
                    to_send             = firmware[response['offset'] : response['offset']
                                                + response['max_size'] - remainder]
                    response['crc']     = self.__stream_data(data   = to_send,
                                                             crc    = response['crc'],
                                                             offset = response['offset'])
                    response['offset'] += len(to_send)
                except ValidationException:
                    # Remove corrupted data.
                    response['offset'] -= remainder
                    response['crc']     = \
                        binascii.crc32(firmware[:response['offset']]) & 0xFFFFFFFF
                    return

            self.__execute()
            self._send_event(event_type=DfuEvent.PROGRESS_EVENT, progress=response['offset'])

        response = self.__select_data()
        try_to_recover()
        for i in range(response['offset'], len(firmware), response['max_size']):
            data = firmware[i:i+response['max_size']]
            try:
                self.__create_data(len(data))
                response['crc'] = self.__stream_data(data=data, crc=response['crc'], offset=i)
                self.__execute()
            except ValidationException:
                raise NordicSemiException("Failed to send firmware")

            self._send_event(event_type=DfuEvent.PROGRESS_EVENT, progress=len(data))
    
    def __print_data(self, data):
        print(self.__get_data_str(data))

    def pop(self, bs:bytearray, sz:int, order='little'):
        if order == 'little':
            fmt = '<'
        else:
            fmt = '>'
        if sz == 1:
            fmt += 'B'
        elif sz == 2:
            fmt += 'H'
        elif sz == 4:
            fmt += 'I'
        elif sz == 8:
            fmt += 'Q'
        else:
            raise Exception('Pop Size Error')
        tup = struct.unpack(fmt, bs[:sz])
        for i in range(sz): _ = bs.pop(0)
        return tup[0]
    
    def __get_data_str(self, data):
        s = ''
        for d in data:
            s += f'{d:02X} '
        return s
    
    def _make_packet_msg(self, cmd:int, body=[], sub_cmd=None, crc_tail=True, debug=False):
        packet = bytearray()
        packet += bytearray(cmd.to_bytes(2, 'big'))
        packet_len = len(body) + (2 if sub_cmd else 0) + (4 if crc_tail else 0)
        packet += bytearray(packet_len.to_bytes(2, 'big'))
        if sub_cmd:
            packet += bytearray(sub_cmd.to_bytes(2, 'little'))
        packet += bytearray(body)
        if crc_tail:
            crc = (binascii.crc32(packet) & 0xFFFFFFFF)
            packet += bytearray(crc.to_bytes(4, 'little'))
        if debug:
            self.__print_data(packet)
        return packet
    
    def __send_dfu_trigger_msg(self):
        packet = self._make_packet_msg(self.DFU_TCPIP_TRIGGER_REQ_CMD, 
                sub_cmd=self.DFU_TCPIP_TRIGGER_SUB_CMD, crc_tail=False, debug=True)
        self.client_socket.sendall(bytes(packet))
    
    def __send_dfu_file_req(self, model_name:str, file_sz:int):
        body = bytearray()
        if len(model_name) > 16:
            raise Exception('Model Name Size Error')
        model_name_buf = bytearray(16)
        model_name_buf[:len(model_name)] = model_name.encode()
        body += model_name_buf
        body += bytearray(file_sz.to_bytes(4, 'little'))
        packet = self._make_packet_msg(self.DFU_TCPIP_DFU_FILE_REQ_CMD, 
                body=body, sub_cmd=self.DFU_TCPIP_DFU_FILE_SUB_CMD_START, debug=True)
        self.client_socket.sendall(bytes(packet))
    
    def __socket_rcv(self):
        try:
            bs = self.client_socket.recv(1024)
            return (True, bs)
        except socket.timeout:
            return (False, None)
    
    def socket_rcv(self, time_out=1):
        start = datetime.now()
        received = False
        packet = None
        while (((datetime.now() - start) < timedelta(seconds=time_out)) and (not received)):
            ret, bs = self.__socket_rcv()
            if not ret:
                continue
            packet = bytearray(bs)
            if len(packet) >= 2:
                received = True
        return received, packet
    
    def __skip_login_msg(self):
        received, packet = self.socket_rcv()
        if (received) and ((packet[0] == 0x10) and (packet[1] == 0x04)):
            logger.info('first packet received')
        else:
            logger.info('empty first packet.')
        print('skip login msg')
    
    def __wait_trigger_msg_resp(self):
        received, packet = self.socket_rcv()
        ret = 0xFFFF
        if not received:
            return (received, ret)
        logger.info('received dfu msg')
        logger.log(TRANSPORT_LOGGING_LEVEL, f'packet: {packet}')
        if len(packet) < 6:
            logger.error(f'failed packet size: {len(packet)}')
            raise Exception(f'Packet Length Error: {len(packet)}')
        cmd = self.pop(packet, 2, 'big')
        if cmd != self.DFU_TCPIP_TRIGGER_RESP_CMD:
            raise Exception(f'Packet CMD Error: {cmd:04X}')
        plen = self.pop(packet, 2, 'big')
        if plen != 2:
            raise Exception(f'Packet Len Error: {plen}')
        ret = self.pop(packet, 2)
        return (received, ret)
    
    def __wait_transfer_file_msg_resp(self):
        received, packet = self.socket_rcv()
        ret = 0xFFFF
        if not received:
            return (received, ret)
        logger.info('received dfu msg')
        logger.log(TRANSPORT_LOGGING_LEVEL, f'packet: {packet}')
        if len(packet) < 6:
            logger.error(f'failed packet size: {len(packet)}')
            raise Exception(f'Packet Length Error: {len(packet)}')
        cmd = self.pop(packet, 2, 'big')
        if cmd != self.DFU_TCPIP_DFU_FILE_RESP_CMD:
            raise Exception(f'Packet CMD Error: {cmd:04X}')
        plen = self.pop(packet, 2, 'big')
        if plen != 2:
            raise Exception(f'Packet Len Error: {plen}')
        ret = self.pop(packet, 2)
        return (received, ret)
    
    def __waiting_dfu_msg(self):
        received, ret = self.__wait_trigger_msg_resp()
        if not received:
            raise NordicSemiException("Tcpip Dfu Trigger Failed.")
        if ret == 0x0000:
            # device goto bootloader mode.
            return False
        elif ret == 0x0001:
            # device in bootloader mode.
            return True
        else:
            raise NordicSemiException("Invalid Result Code.")

    def __waiting_transfer_file_msg(self):
        received, ret = self.__wait_transfer_file_msg_resp()
        if not received:
            raise NordicSemiException("Tcpip Dfu Trigger Failed.")
        if ret == 0x0000:
            return True
        else:
            raise NordicSemiException(f"Invalid Result Code: {ret}")

    def __ensure_bootloader(self):
        # waiting for skip first packet.
        print('waiting for login msg.')
        # self.client_socket.setblocking(False)
        self.__skip_login_msg()
        self.__send_dfu_trigger_msg()
        if not self.__waiting_dfu_msg():
            # device goto bootloader mode.
            # check device is dfu mode.
            print('device goto bootloader mode.')
            self.client_socket.close()
            time.sleep(1)
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10.0)
            self.client_socket.connect((self.host, self.port))
            time.sleep(1)
            self.__send_dfu_trigger_msg()
            if not self.__waiting_dfu_msg():
                print("Failed to goto bootloader mode.")
                raise NordicSemiException('Failed to goto bootloader mode.')
        # device in the bootloader mode.
        print("device in bootloader mode.")

    def __transfer_file(self):
        # waiting for skip first packet.
        print('waiting for login msg.')
        # self.client_socket.setblocking(False)
        self.__skip_login_msg()
        self.__send_dfu_file_req("TEST", 0x40000)
        if not self.__waiting_transfer_file_msg():
            # device goto bootloader mode.
            # check device is dfu mode.
            raise NordicSemiException('Failed to transfer a file.')
        
    def __set_prn(self):
        logger.debug("Serial: Set Packet Receipt Notification {}".format(self.prn))
        self.dfu_adapter.send_message([DfuTransportSerial.OP_CODE['SetPRN']]
            + list(struct.pack('<H', self.prn)))
        self.__get_response(DfuTransportSerial.OP_CODE['SetPRN'])

    def __get_mtu(self):
        self.dfu_adapter.send_message([DfuTransportSerial.OP_CODE['GetSerialMTU']])
        response = self.__get_response(DfuTransportSerial.OP_CODE['GetSerialMTU'])

        self.mtu = struct.unpack('<H', bytearray(response))[0]

    def __ping(self):
        self.ping_id = (self.ping_id + 1) % 256

        self.dfu_adapter.send_message([DfuTransportSerial.OP_CODE['Ping'], self.ping_id])
        resp = self.dfu_adapter.get_message() # Receive raw response to check return code

        if not resp:
            logger.debug('Serial: No ping response')
            return False

        if resp[0] != DfuTransportSerial.OP_CODE['Response']:
            logger.debug('Serial: No Response: 0x{:02X}'.format(resp[0]))
            return False

        if resp[1] != DfuTransportSerial.OP_CODE['Ping']:
            logger.debug('Serial: Unexpected Executed OP_CODE.\n' \
                + 'Expected: 0x{:02X} Received: 0x{:02X}'.format(DfuTransportSerial.OP_CODE['Ping'], resp[1]))
            return False

        if resp[2] != DfuTransport.RES_CODE['Success']:
            # Returning an error code is seen as good enough. The bootloader is up and running
            return True
        else:
            if struct.unpack('B', bytearray(resp[3:]))[0] == self.ping_id:
                return True
            else:
                return False

    def __create_command(self, size):
        self.__create_object(0x01, size)

    def __create_data(self, size):
        self.__create_object(0x02, size)

    def __create_object(self, object_type, size):
        self.dfu_adapter.send_message([DfuTransportSerial.OP_CODE['CreateObject'], object_type]\
                                            + list(struct.pack('<L', size)))
        self.__get_response(DfuTransportSerial.OP_CODE['CreateObject'])

    def __calculate_checksum(self):
        self.dfu_adapter.send_message([DfuTransportSerial.OP_CODE['CalcChecSum']])
        response = self.__get_response(DfuTransportSerial.OP_CODE['CalcChecSum'])

        if response is None:
            raise NordicSemiException('Did not receive checksum response from DFU target. '
                                      'If MSD is enabled on the target device, try to disable it ref. '
                                      'https://wiki.segger.com/index.php?title=J-Link-OB_SAM3U')

        (offset, crc) = struct.unpack('<II', bytearray(response))
        return {'offset': offset, 'crc': crc}

    def __execute(self):
        self.dfu_adapter.send_message([DfuTransportSerial.OP_CODE['Execute']])
        self.__get_response(DfuTransportSerial.OP_CODE['Execute'])

    def __select_command(self):
        return self.__select_object(0x01)

    def __select_data(self):
        return self.__select_object(0x02)

    def __select_object(self, object_type):
        logger.debug("Serial: Selecting Object: type:{}".format(object_type))
        self.dfu_adapter.send_message([DfuTransportSerial.OP_CODE['ReadObject'], object_type])

        response = self.__get_response(DfuTransportSerial.OP_CODE['ReadObject'])
        (max_size, offset, crc)= struct.unpack('<III', bytearray(response))

        logger.debug("Serial: Object selected: " +
            " max_size:{} offset:{} crc:{}".format(max_size, offset, crc))
        return {'max_size': max_size, 'offset': offset, 'crc': crc}

    def __get_checksum_response(self):
        resp = self.__get_response(DfuTransportSerial.OP_CODE['CalcChecSum'])

        (offset, crc) = struct.unpack('<II', bytearray(resp))
        return {'offset': offset, 'crc': crc}

    def __stream_data(self, data, crc=0, offset=0):
        logger.debug("Serial: Streaming Data: " +
            "len:{0} offset:{1} crc:0x{2:08X}".format(len(data), offset, crc))
        def validate_crc():
            if (crc != response['crc']):
                raise ValidationException('Failed CRC validation.\n'\
                                + 'Expected: {} Received: {}.'.format(crc, response['crc']))
            if (offset != response['offset']):
                raise ValidationException('Failed offset validation.\n'\
                                + 'Expected: {} Received: {}.'.format(offset, response['offset']))

        current_pnr     = 0

        for i in range(0, len(data), (self.mtu-1)//2 - 1):
            # append the write data opcode to the front
            # here the maximum data size is self.mtu/2,
            # due to the slip encoding which at maximum doubles the size
            to_transmit = data[i:i + (self.mtu-1)//2 - 1 ]
            to_transmit = struct.pack('B',DfuTransportSerial.OP_CODE['WriteObject']) + to_transmit

            self.dfu_adapter.send_message(list(to_transmit))
            crc     = binascii.crc32(to_transmit[1:], crc) & 0xFFFFFFFF
            offset += len(to_transmit) - 1
            current_pnr    += 1
            if self.prn == current_pnr:
                current_pnr = 0
                response    = self.__get_checksum_response()
                validate_crc()
        response = self.__calculate_checksum()
        validate_crc()
        return crc

    def __get_response(self, operation):
        def get_dict_key(dictionary, value):
            return next((key for key, val in list(dictionary.items()) if val == value), None)

        resp = self.dfu_adapter.get_message()

        if not resp:
            return None

        if resp[0] != DfuTransportSerial.OP_CODE['Response']:
            raise NordicSemiException('No Response: 0x{:02X}'.format(resp[0]))

        if resp[1] != operation:
            raise NordicSemiException('Unexpected Executed OP_CODE.\n' \
                             + 'Expected: 0x{:02X} Received: 0x{:02X}'.format(operation, resp[1]))

        if resp[2] == DfuTransport.RES_CODE['Success']:
            return resp[3:]

        elif resp[2] == DfuTransport.RES_CODE['ExtendedError']:
            try:
                data = DfuTransport.EXT_ERROR_CODE[resp[3]]
            except IndexError:
                data = "Unsupported extended error type {}".format(resp[3])
            raise NordicSemiException('Extended Error 0x{:02X}: {}'.format(resp[3], data))
        else:
            raise NordicSemiException('Response Code {}'.format(
                get_dict_key(DfuTransport.RES_CODE, resp[2])))


if __name__ == "__main__":
    from nordicsemi.dfu.dfu import Dfu
    start = time.time()
    print("DfuTransportTCP")
    try:
        # package = 'pkgs/FULL_NRF52840_V3.3.0_20210610T145523.zip'
        # package = 'pkgs/FULL_NRF52840_AP300_V2.0.2_20210611T173815.zip'
        # package = 'pkgs/APP_NRF52840_AP300_V2.0.2_20210611T175005.zip'
        # package = 'pkgs/APP_NRF52840_V3.3.0_20210607T100806.zip'
        package = 'pkgs/APP_NRF52840_PT200_V3.3.0_20210614T142358.zip'
        tcp_backend = DfuTransportTCP(host="192.168.0.150", transfer_file=True)
        dfu = Dfu(zip_file_path = package, dfu_transport = tcp_backend, connect_delay = 3)
        dfu.dfu_send_images()
        print(f'End time: {time.time()-start} s')
        print("Device programmed.")
    except Exception as e:
        print(f'Exception: {e}')
    print("Module End")
