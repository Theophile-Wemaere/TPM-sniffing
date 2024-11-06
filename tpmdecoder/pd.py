##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2022 Lucas Teske <lucas@teske.com.br>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd
import binascii, re
from enum import Enum

OPERATION_MASK = 0x80
SIZE_MASK = 0x3f
WAIT_MASK = 0x01

# Registers at https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_Platform_TPM_Profile_PTP_2.0_r1.03_v22.pdf
# Page 63 (pdf 71) - Table 17

tpmRegisters = {
    0xD40000: "TPM_ACCESS_0",
    0xD4000C: "TPM_INT_VECTOR_0",
}

for i in range(4):
    tpmRegisters[0xD40008+i] = "TPM_INT_ENABLE_0"

for i in range(4):
    tpmRegisters[0xD40010+i] = "TPM_INT_STATUS_0"

for i in range(4):
    tpmRegisters[0xD40014+i] = "TPM_INTF_CAPABILITY_0"

for i in range(4):
    tpmRegisters[0xD40018+i] = "TPM_STS_0"

for i in range(4):
    tpmRegisters[0xD40024+i] = "TPM_DATA_FIFO_0"

for i in range(4):
    tpmRegisters[0xD40030+i] = "TPM_INTERFACE_ID_0"

for i in range(4):
    tpmRegisters[0xD40080+i] = "TPM_XDATA_FIFO_0"

for i in range(4):
    tpmRegisters[0xD40F00+i] = "TPM_DID_VID_0"

for i in tpmRegisters:
    print("{:08X} = {}".format(i, tpmRegisters[i]))

class State(Enum):
    READING_OP = 1
    READING_ARG = 2
    WAITING = 3
    TRANSFER = 4

class Decoder(srd.Decoder):
    api_version = 3
    id = 'tpm20'
    name = 'TPM2.0'
    longname = 'TPM 2.0'
    desc = 'A TPM 2.0 Protocol Decoder'
    license = 'gplv2+'
    inputs = ['spi']
    outputs = []
    tags = ['SPI', 'TPM']
    options = ()
    annotations = (
        ('text', 'Text'),                   # 0
        ('warning', 'Warning'),             # 1
        ('data-write', 'Data write'),       # 2
        ('data-read', 'Data read'),         # 3
        ('fifo-write', 'FIFO write'),       # 4
        ('fifo-read', 'FIFO read'),         # 5
        ('bitlocker-key', 'Bitlocker Key'), # 6
    )
    annotation_rows = (
         ('row-read', 'Read', (3, )),
         ('row-write', 'Write', (2, )),
         ('row-fifo-read', 'FIFO Read', (5, )),
         ('row-fifo-write', 'FIFO Write', (4, )),
         ('row-bitlocker-key', 'Bitlocker Key', (6, )),
    )
    binary = (
        ('packet-read', 'Packet read'),
        ('packet-write', 'Packet write'),
    )
    options = ()

    def __init__(self):
        self.reset()

    def reset(self):
        self.state = State.READING_OP

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_binary = self.register(srd.OUTPUT_BINARY)

    def decode(self, ss, es, data):
        if len(data) == 3 and data[0] == "DATA":
            _, mosi, miso = data
            self.putdata(ss, es, mosi, miso)

    def report_transaction(self, start, end, ttype, addr, data):
        data = binascii.hexlify(bytearray(data)).decode("ascii")
        if addr in tpmRegisters:
            data = "{}: {}".format(tpmRegisters[addr], data)
        else:
            data = "RESERVED({:06X}): {}".format(addr, data)
        self.put(start, end, self.out_ann, [3 if ttype == 1 else 2, [data] ])

    def report_fifo(self, start, end, ttype, data):
        data = " ".join(["{:02X}".format(x) for x in data])
        self.put(start, end, self.out_ann, [5 if ttype == 1 else 4, [data]] )

    def report_bitlocker_key(self, start, end, key):
        self.put(start, end, self.out_ann, [6, [key] ])

    opIsRead = 0
    addr = 0
    numBytes = 0
    addrIdx = 0
    bytesRead = []
    transactionStart = 0
    transactionEnd = 0

    def putdata(self, ss, es, mosi, miso):
        if self.state == State.READING_OP:
            self.addr = 0
            self.opIsRead = (mosi & OPERATION_MASK) >> 7    # 1 = read, 0 = write
            self.numBytes = (mosi & SIZE_MASK) + 1          # Minimum transfer = 1 byte
            self.addrIdx = 0
            self.bytesRead = []
            self.state = State.READING_ARG
            self.transactionStart = ss
        elif self.state == State.READING_ARG:
            self.addr = (self.addr << 8) | mosi
            self.addrIdx = self.addrIdx + 1
            if self.addrIdx == 3:
                if miso & WAIT_MASK == 0: # Wait state
                    self.state = State.WAITING
                else:
                    self.state = State.TRANSFER
        elif self.state == State.WAITING:
            if miso & WAIT_MASK == 1: # Wait finished
                self.state = State.TRANSFER
        elif self.state == State.TRANSFER:
            if self.opIsRead == 1: # Read from device
                self.bytesRead.append(miso)
            else:   # Read from controller
                self.bytesRead.append(mosi)
            if len(self.bytesRead) == self.numBytes:
                self.transactionEnd = es
                #print("Transaction: ", self.bytesRead)
                self.report_transaction(self.transactionStart, self.transactionEnd, self.opIsRead, self.addr, self.bytesRead)
                if self.addr in tpmRegisters and tpmRegisters[self.addr] == "TPM_DATA_FIFO_0":
                    self.putfifo(self.transactionStart, self.transactionEnd, self.opIsRead, self.bytesRead)
                elif self.opIsRead == 0:
                    self.endfifo()

                self.state = State.READING_OP

    fifoType = -1 # 0 = Write, 1 = Read
    fifoData = []
    fifoStart = 0
    fifoEnd = 0

    def endfifo(self):
        if self.fifoType == -1:
            return # No FIFO
        self.report_fifo(self.fifoStart, self.fifoEnd, self.fifoType, self.fifoData)

        data = "".join(["{:02X}".format(x) for x in self.fifoData])
        key = re.findall(r'2C000[0-6]000[1-9]000[0-1]000[0-5]200000(\w{64})', data)
        if key:
            print("Bitlocker Key: {}".format(key[0]))
            self.report_bitlocker_key(self.fifoStart, self.fifoEnd, key[0])
        self.fifoData = []
        self.fifoType = -1

    def putfifo(self, start, end, ttype, data):
        if self.fifoType != ttype:
            self.endfifo()
            self.fifoType = ttype
            self.fifoStart = start
        self.fifoEnd = end
        for i in data:
            self.fifoData.append(i)
