


class DfuFileTransfer():

    DEFAULT_PORT = 5000
    DEFAULT_SOCKET_TIMEOUT = 5.0  # Timeout time for opennig socket
    DEFAULT_TIMEOUT = 10.0  # Timeout time for board response
    
    def __init__(self,
                 host,
                 port=DEFAULT_PORT):
        pass

if __name__ == '__main__':
    print("DfuFileTransfer")
    file_path = 'pkgs/nrf52_dfu_default.zip'
    file_path = 'pkgs/nrf52_dfu_default/nrf52840_xxaa.dat'
    with open(file_path, 'rb') as f:
        print(f'opened: {file_path}')
        data = f.read()
        for d in data:
            print(f'{d:02X}')
        print(f'size: {len(data)}')
        print(type(data))
        print(len(data[:100]))
        print(data[:100])

        # print(data[:100])
        # print(data[100:])
