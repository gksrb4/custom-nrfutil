# /******************************************************************************
#  * @Author: HANGYU PARK 
#  * @License: Copyright (c) 2018-2021 by PASSTECH CO., LTD 
#  * @Date: 2020-03-06 13:36:19 
#  * @Last Modified by:   HANGYU PARK 
#  * @Last Modified time: 2020-03-06 13:36:19 
#  ******************************************************************************/
# //-----------------------------------------------------------------------------
import logging
import os
import unittest
import time
import sys
import socket

def setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

class TestClientSocket(unittest.TestCase):
    def setUp(self):
        setup_logging()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = "192.168.0.190"
        self.port = 5000

    def tearDown(self):
        if self.client_socket:
            self.client_socket.close()

    def test_open(self):
        self.client_socket.connect((self.host, self.port))

    def test_close(self):
        self.client_socket.close()

