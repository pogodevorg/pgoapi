from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *

from binascii import hexlify, unhexlify

import struct
import ctypes

DEBUG = 0

# WORK IN PROGRESS : Hash Emulation on unicorn engine
class HashEmulator:
    POGO_FILE_NAME = "pokemongo_0_45.payload"

    POGO_BIN_SIZE   = 0x0327F500
    POGO_BIN_OFFSET = 0x00008830
    POGO_BIN_MAX    = POGO_BIN_SIZE
    POGO_FUNC       = 0x1B175C0
    POGO_FUNC_END   = 0x1B17AA4
    NL_SYM_PTR_BASE = 0x2CC8000 
    LA_SYM_PTR_END  = 0x2D09E58
    POGO_EXP_ADDR   = NL_SYM_PTR_BASE
    POGO_EXP_CNT    = ((LA_SYM_PTR_END - NL_SYM_PTR_BASE) / 4)
    POGO_SEG_COMMON = 0x0312C980

    POGO_NOP_FIX1                = 0x01B1769C
    POGO_NOP_FIX2                = 0x01b17cd4
    POGO_HICKUP_ENTRY_BEGIN_STOP = 0x01B175D2
    POGO_HICKUP_ENTRY_2          = 0x01B175DA
    POGO_HICKUP_ENTRY_2_STOP     = 0x01B17CF4
    POGO_HICKUP_ENTRY_3          = 0x01B17CFE

    def __init__(self):
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        self.mu.hook_add(UC_HOOK_CODE, self.POGO_hook)
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.POGO_hook_mem)

        # heap and stack allocation
        self.POGO_createmap(0xE0000000, 0x2000)
        self.POGO_createmap(0xD0000000, 0x2000)
        sp = 0xD0000000 + 0x1000

        # stack
        self.mu.reg_write(UC_ARM_REG_SP, sp)

        # start code calling hash func
        self.POGO_createmap(0x1000, 0x1000)
        self.mu.mem_write(0x1000, "\x90\x47")

        # binary mapping
        f = open(self.POGO_FILE_NAME, "rb")
        code_buffer = f.read(self.POGO_BIN_SIZE)
        f.close()

        # memory prepare
        self.POGO_createmap(self.POGO_BIN_OFFSET, self.POGO_BIN_MAX - self.POGO_BIN_OFFSET)

        code_buffer = code_buffer[:self.POGO_NOP_FIX1] + b'\x00\x00\x00\x00' + code_buffer[self.POGO_NOP_FIX1+4:]
        code_buffer = code_buffer[:self.POGO_NOP_FIX2] + b'\x00\x00\x00\x00' + code_buffer[self.POGO_NOP_FIX2+4:]

        # all segment
        self.mu.mem_write(self.POGO_BIN_OFFSET, code_buffer[self.POGO_BIN_OFFSET:self.POGO_BIN_MAX])

        # export address fill with any valid address
        exportdata = self.POGO_SEG_COMMON
        exportaddr = self.POGO_EXP_ADDR

        for i in range(0, self.POGO_EXP_CNT):
            value1 = code_buffer[exportaddr + (i*4)].encode("hex")
            value2 = code_buffer[exportaddr + (i*4)+1].encode("hex")
            value3 = code_buffer[exportaddr + (i*4)+2].encode("hex")
            value4 = code_buffer[exportaddr + (i*4)+3].encode("hex")
            if value1 == "00" and value2 == "00" and value3 == "00" and value4 == "00":
                self.mu.mem_write(exportaddr + (i * 4), struct.pack("<q", exportdata))

    def POGO_hook(self, uc, address, size, user_data):
        if (DEBUG):
            print(">>> Tracing instruction at 0x%x" %(address), end=' ')
            #for i in range(0, 2):
                #print(code_buffer[address + i].encode("hex"), end=' ')
            print(" ")

    def POGO_hook_mem(self, uc, access, addr, size, value, user_data):
        if DEBUG and addr < 0xD0000000:
            if access == UC_MEM_READ:
                print("r", end=' ')
            elif access == UC_MEM_WRITE:
                print("w", end=' ')
            elif access == UC_MEM_FETCH:
                print("f", end=' ')
            print("len:%d at 0x%lx" % (size, addr))

    def POGO_createmap(self, address, size):
        chunk = address % 0x1000
        taddr = address - chunk
        tsize = ((0xFFF + chunk + size) / 0x1000) * 0x1000

        self.mu.mem_map(taddr, tsize)

    def push(self, reg):
        sp = self.mu.reg_read(UC_ARM_REG_SP)
        regVal = self.mu.reg_read(reg)
        self.mu.mem_write(sp, struct.pack(">i", regVal))
        sp = sp - 4
        self.mu.reg_write(UC_ARM_REG_SP, sp)

    def pop(self, reg):
        sp = self.mu.reg_read(UC_ARM_REG_SP)
        regVal = self.mu.mem_read(sp, 4)
        self.mu.reg_write(reg, struct.unpack("i", regVal)[0])
        sp = sp + 4
        self.mu.reg_write(UC_ARM_REG_SP, sp)

    def hash(self, buffer, size):
        # HASH
        #buffer = "\x46\xe9\x45\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        buffer = "\x46\xe9\x45\xf8" + "\x00" * 24
        print(hexlify(buffer))
        print(size)
        #size = 28

        self.mu.reg_write(UC_ARM_REG_R0, 0xE0001000)
        self.mu.reg_write(UC_ARM_REG_R1, size)
        self.mu.reg_write(UC_ARM_REG_R2, self.POGO_FUNC + 1)

        self.mu.mem_write(0xE0001000, buffer)

        try:
            self.mu.emu_start(0x1000, self.POGO_HICKUP_ENTRY_BEGIN_STOP)
            print("1 done")
            self.push(UC_ARM_REG_D8)
            self.push(UC_ARM_REG_D9)
            self.push(UC_ARM_REG_D10)
            self.push(UC_ARM_REG_D11)
            self.push(UC_ARM_REG_D12)
            self.push(UC_ARM_REG_D13)
            self.push(UC_ARM_REG_D14)
            self.push(UC_ARM_REG_D15)
            self.mu.emu_start(self.POGO_HICKUP_ENTRY_2, self.POGO_HICKUP_ENTRY_2_STOP)
            print("2 done")
            self.pop(UC_ARM_REG_D15)
            self.pop(UC_ARM_REG_D14)
            self.pop(UC_ARM_REG_D13)
            self.pop(UC_ARM_REG_D12)
            self.pop(UC_ARM_REG_D11)
            self.pop(UC_ARM_REG_D10)
            self.pop(UC_ARM_REG_D9)
            self.pop(UC_ARM_REG_D8)
            self.mu.emu_start(self.POGO_HICKUP_ENTRY_3, 0x1002)
            print("3 done")
        except UcError as e:
            print("ERROR: %s" % e)

        r0 = self.mu.reg_read(UC_ARM_REG_R0)
        r1 = self.mu.reg_read(UC_ARM_REG_R1)

        ret = r1
        ret = (ret << 32) | r0
        return ret
