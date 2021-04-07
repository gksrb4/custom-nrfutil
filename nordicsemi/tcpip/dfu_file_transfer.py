import socket
from datetime import datetime, timedelta
import logging
import binascii
import struct

logger = logging.getLogger(__name__)

class DfuFileTransfer():
    DEFAULT_PORT = 5000
    DEFAULT_SOCKET_TIMEOUT = 5.0  # Timeout time for opennig socket
    DEFAULT_TIMEOUT = 10.0  # Timeout time for board response
    DFU_TCPIP_TRIGGER_REQ_CMD =            0x2323
    DFU_TCPIP_TRIGGER_RESP_CMD =           0x2324
    DFU_TCPIP_TRIGGER_SUB_CMD =            0xDEAD
    DFU_TCPIP_TRIGGER_RET_BOOT =           0x0001
    DFU_TCPIP_DFU_FILE_REQ_CMD =           0x3434
    DFU_TCPIP_DFU_FILE_RESP_CMD =          0x3435
    DFU_TCPIP_DFU_FILE_SUB_CMD_START =     0xDF00
    DFU_TCPIP_DFU_FILE_SUB_CMD_WRITE =     0xDF01
    DFU_TCPIP_DFU_FILE_SUB_CMD_CRC_CHECK = 0xDF02
    
    def __init__(self,
                 host,
                 port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.settimeout(1.0)
        self.client_socket.connect((self.host, self.port))
    
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
    
    def skip_login_msg(self):
        start = datetime.now()
        received, packet = self.socket_rcv()
        if (received) and ((packet[0] == 0x10) and (packet[1] == 0x04)):
            logger.info('first packet received')
        else:
            logger.info('empty first packet.')
        print('skip login msg')
    
    def __get_data_str(self, data):
        s = ''
        for d in data:
            s += f'{d:02X} '
        return s

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
    
    def _send_dfu_trigger_msg(self):
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

    def __recv_response(self, cmd, data):
        recv_cmd = self.pop(data, 2, order='big')
        if cmd != recv_cmd:
            raise Exception(f"Cmd Error: received: {recv_cmd:04X}, expected: {cmd:04X}")
        l = self.pop(data, 2, order='big')
        print(f'cmd: {cmd:04X}, len: {l}')
        self.__print_data(data)
        return data

    def _send_dfu_file(self, model_name, file):
        body = []
        self.__send_dfu_file_req(model_name, len(file))
        received, data = self.socket_rcv()
        if not received:
            raise Exception(f'Error Response: {self.__get_data_str(data)}')
        self.__recv_response(self.DFU_TCPIP_DFU_FILE_RESP_CMD, data)
        

if __name__ == '__main__':
    print("DfuFileTransfer")
    file_path = 'pkgs/nrf52_dfu_default.zip'
    dft = DfuFileTransfer(host="192.168.0.150")
    dft.skip_login_msg();
    with open(file_path, 'rb') as f:
        data = f.read()
        dft._send_dfu_file("PT200TWR", data)
        ret, data = dft.socket_rcv()
        if not ret:
            raise Exception("Fail to receive response")
        print(data)

