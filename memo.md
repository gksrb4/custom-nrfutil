# env\scripts\activate

# python setup.py build && python setup.py install

# python -m nordicsemi --help

# onefile dist
# pyinstaller --onefile --name nrfutil-cus nordicsemi/__main__.py




# env\scripts\activate && python setup.py build && python setup.py install && pyinstaller --add-binary "libusb/x64/libusb-1.0.dll;." --hidden-import usb1 --onefile --name nrfutil-cus nordicsemi/__main__.py

# usb dfu test
# dist\\nrfutil-cus.exe dfu usb-serial -p COM16 -cd 10 -pkg D:\03.Git\LOCKER_FW\nRF_MAIN\SOURCE\project\1.application\ap\appl\armgcc\_build\release\AP300STD\APP_NRF52840_AP300STD_V2.1.4_20220128T140649.zip