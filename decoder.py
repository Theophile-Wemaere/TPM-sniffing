#!/bin/python3

# Greatly inspired from https://lucasteske.dev/2024/01/tpm2-bitlocker-keys
import csv
import sys
import binascii
import re
from enum import Enum
from alive_progress import alive_bar

# columns name
MOSI = " MOSI"
MISO = " MISO"
SCK = " CLK"
CS = "CS"
TIME = "Time [s]"
FIFO = ""
to_save = []
bar = None

# TPM Registers
tpmRegisters = {
    0xD40000: "TPM_ACCESS_0",
    0xD4000C: "TPM_INT_VECTOR_0",
}
for i in range(4):
    tpmRegisters[0xD40008 + i] = "TPM_INT_ENABLE_0"
for i in range(4):
    tpmRegisters[0xD40010 + i] = "TPM_INT_STATUS_0"
for i in range(4):
    tpmRegisters[0xD40014 + i] = "TPM_INTF_CAPABILITY_0"
for i in range(4):
    tpmRegisters[0xD40018 + i] = "TPM_STS_0"
for i in range(4):
    tpmRegisters[0xD40024 + i] = "TPM_DATA_FIFO_0"
for i in range(4):
    tpmRegisters[0xD40030 + i] = "TPM_INTERFACE_ID_0"
for i in range(4):
    tpmRegisters[0xD40080 + i] = "TPM_XDATA_FIFO_0"
for i in range(4):
    tpmRegisters[0xD40F00 + i] = "TPM_DID_VID_0"

# Enum for different states in the SPI protocol
class State(Enum):
    READING_OP = 1
    READING_ARG = 2
    WAITING = 3
    TRANSFER = 4

class TPMDecoder:
    def __init__(self):
        self.reset()

    def reset(self):
        self.state = State.READING_OP
        self.addr = 0
        self.opIsRead = 0
        self.numBytes = 0
        self.addrIdx = 0
        self.bytesRead = []
        self.transactionStart = 0
        self.transactionEnd = 0
        # buffer to store temporary data ot search for VMK
        self.vmk_buffer = ""

    def decode(self, ss, es, mosi, miso):
        """ Decode SPI data and report the results. """
        if self.state == State.READING_OP:
            self.addr = 0
            self.opIsRead = (mosi & 0x80) >> 7  # 1 = read, 0 = write
            self.numBytes = (mosi & 0x3f) + 1  # Minimum transfer = 1 byte
            self.addrIdx = 0
            self.bytesRead = []
            self.state = State.READING_ARG
            self.transactionStart = ss
        elif self.state == State.READING_ARG:
            self.addr = (self.addr << 8) | mosi
            self.addrIdx += 1
            if self.addrIdx == 3:
                if miso & 0x01 == 0:  # Wait state
                    self.state = State.WAITING
                else:
                    self.state = State.TRANSFER
        elif self.state == State.WAITING:
            if miso & 0x01 == 1:  # Wait finished
                self.state = State.TRANSFER
        elif self.state == State.TRANSFER:
            if self.opIsRead == 1:  # Read from device
                self.bytesRead.append(miso)
            else:  # Write to device
                self.bytesRead.append(mosi)
            # print(len(self.bytesRead),"->",self.numBytes)
            if len(self.bytesRead) == self.numBytes:
                self.transactionEnd = es
                self.report_transaction(self.transactionStart, self.transactionEnd, self.opIsRead, self.addr, self.bytesRead)
                self.state = State.READING_OP

    def analyse_fifo(self,data):
        """ Search FIFO for VMK header """

        # VMK regex : 2C000[0-6]000[1-9]000[0-1]000[0-5]200000(\w{64})

        if data == "2C":
            self.vmk_buffer = "2C"
        else:
            self.vmk_buffer += data

        key = re.findall(r'2C000[0-6]000[1-9]000[0-1]000[0-5]200000(\w{64})', self.vmk_buffer,re.IGNORECASE)
        if key:
            print("Bitlocker Key: {}".format(key[0]))
            bar.pause()
            # print("Saving file")
            # with open("output.bitlocker","w") as file:
            #     file.write("CS,MOSI,MISO,CLK\n")
            #     for line in to_save:
            #         file.write(line+"\n")
            exit(0)
        

    def report_transaction(self, start, end, ttype, addr, data):
        """ Report decoded transaction. """
        global FIFO
        data_hex = binascii.hexlify(bytearray(data)).decode("ascii")
        if addr in tpmRegisters:
            data_hex = "{}: {}".format(tpmRegisters[addr], data_hex)
            if tpmRegisters[addr] == "TPM_DATA_FIFO_0":
                data = data_hex.split(' ')[1]
                FIFO += data
                self.analyse_fifo(data)
        else:
            data_hex = "RESERVED({:06X}): {}".format(addr, data_hex)
        
        # print(f"Transaction from {start} to {end}: {data_hex}")

def get_line_count(file_path):

    c = 0
    with open(file_path,"r") as file:
        for line in file:
            c += 1
    return c

# Load and decode the SPI data from the CSV
def load_and_decode_csv(file_path):
    tpm_decoder = TPMDecoder()
    
    global to_save, bar

    print(f"Searching CSV file {file_path} for a bitlocker VMK header")
    print("Don't forget to set global var MISO,MOSI,CS and SCK to the corresponding columns name")

    total = get_line_count(file_path)
    
    # Read CSV file
    with open(file_path, mode='r') as file:
        reader = csv.DictReader(file)
        packet = {}
        last_clock = 1
        count = 0
        percent = 0

        mosi_str = ""
        miso_str = ""
        second = False
        with alive_bar(total,enrich_print=False,bar=None,spinner=False) as bar:
            for row in reader:
                to_save.append(f"{row[CS]},{row[MOSI]},{row[MISO]},{row[SCK]}")
                # print(f"{row[CS]},{row[MOSI]},{row[MISO]},{row[SCK]} -> {count+1}")
                percent = (count*100)/total
                # print(f"line {count}/{total} ({percent}%)")
                count += 1
                cs = int(row[CS])
                clock = int(row[SCK])

                if cs == 0:
                    if not packet:
                        packet["time"] = "" # row[TIME].strip()  # Timestamp for the packet
                        packet["MOSI"] = []
                        packet["MISO"] = []
                        packet["bits"] = 0

                    if clock == 1 and last_clock == 0:
                        mosi_bit = int(row[MOSI].strip())
                        miso_bit = int(row[MISO].strip())
                        # print("Input :",mosi_bit,miso_bit)
                        if packet["bits"] % 8 == 0:
                            # print("STR:",mosi_str,miso_str)
                            mosi_str,miso_str = "",""
                            packet["MOSI"].append(mosi_bit)
                            packet["MISO"].append(miso_bit)
                        else:
                            
                            packet["MOSI"][-1] = 2 * packet["MOSI"][-1] + mosi_bit
                            packet["MISO"][-1] = 2 * packet["MISO"][-1] + miso_bit
                        # print("Output :",packet["MOSI"][-1],packet["MISO"][-1])
                        miso_str += str(miso_bit)
                        mosi_str += str(mosi_bit)
                        packet["bits"] += 1
                elif cs == 1:
                    if packet and packet["MOSI"]:
                        # print("*******************")
                        # print(packet["MOSI"],packet["MISO"])
                        for i in range(len(packet["MOSI"])):
                            # Decode the SPI packet using the TPM decoder
                            # print(f"on {count}: On {i} : {i}-{i+1}-{packet['MOSI'][i]}-{packet['MISO'][i]}")
                            tpm_decoder.decode(i, i + 1, packet["MOSI"][i], packet["MISO"][i])
                        # if second:
                        #     with open("smolbitlocker.csv","w") as csvfile:
                        #         csvfile.write("CS,MOSI,MISO,CLK\n")
                        #         for line in to_save:
                        #             csvfile.write(line+'\n')

                        #     exit()
                        # else:
                        #     second = True
                    packet = {}

                last_clock = clock
                bar()

        print("No bitlocker key found :(")

import sys
#csv_file_path = 'bitlocker.csv'
csv_file_path = ''
if len(sys.argv) > 1:
    csv_file_path = sys.argv[1]
else:
    print("Use python3 decoder.py filename.csv")
    exit()
load_and_decode_csv(csv_file_path)