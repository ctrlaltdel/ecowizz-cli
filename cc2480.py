#!/usr/bin/env python

import serial
from binascii import hexlify, unhexlify, a2b_hex
import struct
import sys
import re
import ast
from time import sleep

#
# ANSI colors
#

def color(t, c):
        return chr(0x1b)+"["+str(c)+"m"+t+chr(0x1b)+"[0m"
def black(t):
        return color(t, 30)
def red(t):
        return color(t, 31)
def green(t):
        return color(t, 32)
def yellow(t):
        return color(t, 33)
def blue(t):
        return color(t, 34)
def mangenta(t):
        return color(t, 35)
def cyan(t):
        return color(t, 36)
def white(t):
        return color(t, 37)
def bold(t):
        return color(t, 1)

#
# Library for communication with a TI CC2480 Zigbee chip
# 

SOF = '\xFE'

def _fcs(msg):
  res = 0
  for c in msg:
    res ^= ord(c)
  return res


class Frame:
  def __init__(self, cmd0, cmd1, data):
    self.cmd0 = int(cmd0)
    self.cmd1 = int(cmd1)

    if type(data) == str:
      self.data = data
    elif type(data) == int:
      self.data = chr(data)
    elif type(data) == list or type(data) == tuple:
      self.data = "".join(chr(c) for c in data)
    else:
      raise Exception("Unknown data format: %s" % type(data))

    self.length = len(self.data)

  @classmethod
  def from_wire(cls, data):
    length = ord(data[1])
    fcs = ord(data[-1:])
    cmd0 = ord(data[2])
    cmd1 = ord(data[3])

    if len(data) - 5 != length:
      raise Exception("Invalid frame, size mismatch %i != %i" % (len(data) - 3, length))
      #print "Invalid frame, size mismatch %i != %i" % (len(data) - 3, length)

    # TODO check FCS
    computed_fcs = _fcs(data[1:-1])
    if fcs != computed_fcs:
      raise Exception("FCS doesn't match, corruption? %x != %x" % (fcs, computed_fcs))


    return cls(cmd0 = cmd0, cmd1 = cmd1, data = data[4:-1])

  def serialize(self):
    string = struct.pack("cBBB", SOF, self.length, self.cmd0, self.cmd1)
    string += self.data
    string += struct.pack("B", self.fcs)
    return string

  def _compute_fcs(self):
    return _fcs(chr(self.cmd0) + chr(self.cmd1) + chr(self.length) + self.data)
  fcs = property(_compute_fcs)

  def __repr__(self):
    res = ""

    res += "cmd=%02x:%02x %s\n" % (self.cmd0, self.cmd1, " ".join(["%02x" % ord(c) for c in self.data]))

    frame_type = int(self.cmd0 >> 5)
    subsystem = int(self.cmd0 & 0x1F)
    id = int(self.cmd1)

    TYPES = {
      0: 'POLL',
      1: 'SREQ',
      2: 'AREQ',
      3: 'SRSP'
    }

    SUBSYSTEMS = {
      1: 'SYS',
      4: 'AF',
      5: 'ZDO',
      6: 'sAPI'
    }

    STATUS = {
      0x00: 'ZSuccess',
      0x01: 'ZFailure',
      0x02: 'ZInvalidParameter',
      0x10: 'ZMemError',
      0x11: 'ZBufferFull',
      0x12: 'ZUnsupportedMode',
      0x12: 'ZUnsupportedMode',
      0x13: 'ZMacMemError',
      0xa1: 'ZSecNoKey',
      0xa3: 'ZSecMaxFrmCount',
      0x80: 'zdoInvalidRequestType',
      0x82: 'zdoInvalidEndpoint',
      0x84: 'zdoUnsupported',
      0x85: 'zdoTimeout',
      0x86: 'zdoNoMatch',
      0x87: 'zdoTableFull',
      0x88: 'zdoNoBindEntry',
      0xb1: 'ZApsFail',
      0xb2: 'ZApsTableFull',
      0xb3: 'ZApsIllegalRequest',
      0xb4: 'ZApsInvalidBinding',
      0xb5: 'ZApsUnsupportedAttrib',
      0xb6: 'ZApsNotSupported',
      0xb7: 'ZApsNoAck',
      0xb8: 'ZApsDuplicateEntry',
      0xb9: 'ZApsNoBoundDevice',
      0x82: 'zdoInvalidEndpoint',
      0x84: 'zdoUnsupported',
      0x85: 'zdoTimeout',
      0x86: 'zdoNoMatch',
      0x87: 'zdoTableFull',
      0x88: 'zdoNoBindEntry',
      0xb1: 'ZApsFail',
      0xb2: 'ZApsTableFull',
      0xb3: 'ZApsIllegalRequest',
      0xb4: 'ZApsInvalidBinding',
      0xb5: 'ZApsUnsupportedAttrib',
      0xb6: 'ZApsNotSupported',
      0xb7: 'ZApsNoAck',
      0xb8: 'ZApsDuplicateEntry',
      0xb9: 'ZApsNoBoundDevice',
      0xc1: 'ZNwkInvalidParam',
      0xc2: 'ZNwkInvalidRequest',
      0xc3: 'ZNwkNotPermitted',
      0xc4: 'ZNwkStartupFailure',
      0xc7: 'ZNwkTableFull',
      0xc8: 'ZNwkUnknownDevice',
      0xc9: 'ZNwkUnsupportedAttribute',
      0xca: 'ZNwkNoNetworks',
      0xcb: 'ZNwkLeaveUnconfirmed',
      0xcc: 'ZNwkNoAck',
      0xcd: 'ZNwkNoRoute',
    }

    frame_type = TYPES.get(frame_type)
    subsystem = SUBSYSTEMS.get(subsystem)

    res +=  "%s: %s 0x%02x " % (frame_type, subsystem, id)

    data = tuple([ord(c) for c in self.data])

    if self.cmd1 == 0x81:
      res +=  "ZB_BIND_CONFIRM CommandId=%02x%02x" % (ord(self.data[1]), ord(self.data[0]))
    if self.cmd1 == 0x82:
      res +=  "ZB_ALLOW_BIND_CONFIRM CommandId=%02x%02x" % (ord(self.data[1]), ord(self.data[0]))
    if self.cmd1 == 0x83:
      res +=  "ZB_SEND_DATA_CONFIRM handle=%02x" % ord(self.data[0])
    if self.cmd1 == 0x87:
      length = ord(self.data[4])
      source, command, length, data = struct.unpack("<HHH%ds" % length, self.data)
      res +=  "ZB_RECEIVE_DATA_INDICATION source=%04x command=%04x len=%d" % (source, command, length)
      res +=  " payload=" + hexlify(data).upper()

    if self.cmd0 == 0x26 and self.cmd1 == 0x0A:
      #
      # 26:0a 01 44 04 00 00 01 00 06 81 00 82 00 c1 00 83 00 fb 00 fd 00 08 01 00 41 00 02 00 42 00 03 00 43 00 fa 00 fc 00
      #
      # CMD:               26:0a
      #
      # 0     AppEndPoint:   01
      # 1-2   AppProfileID:  44 04
      # 3-4   DeviceID:      00 00
      # 5     DeviceVersion: 01
      # 6     Unused:        00
      # 7     InputCmdsNum:  06
      # 8-19  InputCmds:     81 00  82 00  c1 00  83 00  fb 00  fd 00
      # 20    OutputCmdsNum: 08
      # 21-36 OutputCmds:    01 00  41 00  02 00  42 00  03 00  43 00  fa 00  fc 00
      #
      res +=  "ZB_APP_REGISTER_REQUEST AppEndPoint=%02x AppProfileID=%02x%02d DeviceID=%02x%02d DeviceVersion=%02d%02d " % (
        data[0],
        data[2], data[1],
        data[4], data[3],
        data[6], data[5] )

      InputCommandsNum = ord(self.data[7])
      p = 8
      res += "\n%d InputCommands:  " % InputCommandsNum
      for i in xrange(InputCommandsNum):
        res += " 0x%02x%02x" % (data[p+2*i+1], data[p+2*i])

      OutputCommandsNum = ord(self.data[8 + 2*InputCommandsNum])
      p = 8 + 2*InputCommandsNum + 1
      res += "\n%d OutputCommands: " % OutputCommandsNum
      for i in xrange(OutputCommandsNum):
        res += " 0x%02x%02x" % (data[p+2*i+1], data[p+2*i])

    if self.cmd0 == 0x26 and self.cmd1 == 0x05:
      configid= ord(self.data[0])
      res +=  "ZB_WRITE_CONFIGURATION ConfigID=%02x Len=%02x" % (ord(self.data[0]), ord(self.data[1]))
      length = ord(self.data[1])
      if length:
        res += " Value=" + hexlify(self.data[2:2+length]).upper() + " "

      if configid == 0x0003:
        res += "ZCD_NV_STARTUP_OPTION"

      if configid == 0x0087:
        res += "ZCE_NV_LOGICAL_TYPE"

    if self.cmd1 == 0x06:
      param = ord(self.data[0])
      res +=  "ZB_GET_DEVICE_INFO param=%d " % param
      if frame_type == 'SRSP':
        if param == 0:
          res +=  "Device state"

        res +=  " payload=" + hexlify(self.data[1:]).upper()

    if self.cmd1 == 0x08:
      res +=  "ZB_PERMIT_JOINING_REQUEST"
    if self.cmd0 == 0x21 and self.cmd1 == 0x02:
      res += "SYS_VERSION"
    if self.cmd0 == 0x26 and self.cmd1 == 0x02:
      res +=  "ZB_ALLOW_BIND timeout=%02x" % ord(self.data[0])
    if self.cmd1 == 0x03:
      if frame_type == 'SREQ':
        res +=  "ZB_SEND_DATA_REQUEST destination=%02x%02x commandID=%02x%02x handle=%02x" % (ord(self.data[1]), ord(self.data[0]), ord(self.data[2+1]), ord(self.data[2+0]), ord(self.data[2+2]))
      elif frame_type == 'SRSP':
        res +=  "ZB_SEND_DATA_REQUEST"
      res +=  " payload=" + hexlify(self.data).upper()
    if self.cmd1 == 0x01:
      res +=  "ZB_BZB_BIND_DEVICE create=%d commandID=%02x%02x" % (ord(self.data[0]), ord(self.data[1+1]), ord(self.data[1+0]))

    if frame_type == 'AREQ':
      if self.cmd1 == 0x00:
        res +=  "SYS_RESET_REQ"
      if self.cmd1 == 0x80:
        res +=  "SYS_RESET_IND reason=%d" % ord(self.data[0])
      if self.cmd1 == 0x02:
        res +=  "SYS_VERSION transportRev=%d Product=%d Rel=%d.%d HwRev=%d" % (ord(self.data[0]), ord(self.data[1]), ord(self.data[2]), ord(self.data[3]), ord(self.data[4]))

    if frame_type == 'ZDO': 
      if self.cmd1 == 0xb6:
        res +=  "ZDO_MGMT_PERMIT_JOIN_RSP"

    if frame_type == 'SREQ': 
      if self.cmd1 == 0x00:
        res +=  "ZB_START_REQUEST"

    if frame_type == 'SRSP': 
      if self.cmd1 == 0x00:
        res +=  "ZB_START_REQUEST"

    if self.cmd0 == 0x46 and self.cmd1 == 0x80:
      res +=  "ZB_START_CONFIRM Status=%s" % STATUS.get(ord(self.data[0]))

    if self.cmd0 == 0x66:
      if self.cmd1 == 0x05:
        res += "ZB_WRITE_CONFIGURATION Status=%s" % STATUS.get(ord(self.data[0]))
    if self.cmd0 == 0x61:
      if self.cmd1 == 0x02:
        res += "SYS_VERSION TransportRev=%02x Product=%02x MajorRel=%02x MinorRel=%02x HwRev=%02x" % tuple([ord(c) for c in self.data])
        #res += "SYS_VERSION TransportRev=%02x Product=%02x MajorRel=%02x MinorRel=%02x HwRev=%02x" % (ord(self.data[0]), ord(self.data[1]), ord(self.data[2]), ord(self.data[3]), ord(self.data[4]))
        #res += "SYS_VERSION %d" % len(self.data)

      if self.cmd1 == 0x08:
        res += "SYS_OSAL_NV_READ"


    return res


class CC2480:
  def __init__(self, device='/dev/ttyUSB0'):
    self.ser = serial.Serial(device, baudrate=115200, timeout=1)

  def write(self, data):
    #print "DEBUG: write %s" % hexlify(data).upper()
    self.ser.write(data)

  def read(self, size=1):
    data = self.ser.read(size)
    #print "DEBUG: read %s" % hexlify(data).upper()
    return data

  def receive(self):
    while True:
      data = self.read()
      if data == SOF:
        frame = data
        break
      
      if data == '':
        return None

    # Length (1 byte)
    data = self.read(1) 
    length = ord(data)
    frame += data

    # Command (2 byte)
    frame += self.read(2) 

    # Data (variable length)
    frame += self.read(length)

    # FCS (1 byte)
    data = self.read(1)
    frame += data
    fcs = ord(data)

    f = Frame.from_wire(frame)

    if f:
      print red(repr(f))
      print
    else:
      print "NO RESPONSE"

    return f

  def send(self, cmd0, cmd1, data=[]):
    frame = Frame(cmd0, cmd1, data)
    print green(repr(frame))
    print
    self.write(frame.serialize())

  def ZB_SEND_DATA_REQUEST(self, destination, commandID, handle=0x00, ack=0x00, radius=0x01, data=""):

    data_length = len(data)
    payload = struct.pack("<HHBBBB", destination, commandID, handle, ack, radius, data_length)
    payload += data
    frame = Frame(0x26, 0x03, payload)
    print frame
    print
    self.write(frame.serialize())

#
# Tests
#

if __name__ == '__main__':

  if sys.argv[1] == "olddump":
    sent = file(sys.argv[2]).read()

    spkts = re.split("<\d{14}\.\d{3}>\x0d", sent)
    spkts = spkts[1:]

    for i in xrange(len(spkts)):
      print Frame.from_wire(spkts[i])

  if sys.argv[1] == "dump":
    strace = open(sys.argv[2])

    prev_syscall = ""
    res = ""


    for line in strace:
      #print line
      syscall, data = re.findall('^(.+)\(\d+, "(.*)"', line)[0]

      data = ast.literal_eval('"' + data + '"')

      if syscall == prev_syscall and line != "":
        res += data
      else:
        prev_syscall = syscall
        if res:

          for frame in re.findall("\xfe[^\xfe]+", res):
            #print hexlify(frame).upper()
            if syscall == 'write':
              print red(repr(Frame.from_wire(frame)))
            elif syscall == 'read':
              print green(repr(Frame.from_wire(frame)))
            print
        res = data


  else:
    z = CC2480(sys.argv[1])
    #z.write(unhexlify("fe00210223"))

    # SYS_VERSION
    z.send(0x21, 0x02)
    z.receive()
    
    # SYS_RESET_REQ
    z.send(0x41, 0x00, 0x1)
    z.receive()

    sleep(1)

    # ZB_START_REQUEST
    z.send(0x26, 0x00, 0x00)
    z.receive()

    # ZB_APP_REGISTER_REQUEST
    z.send(0x26, 0x0a, [0x01, 0x44, 0x04, 0x00, 0x00, 0x01, 0x00, 0x06, 0x81, 0x00, 0x82, 0x00, 0xc1, 0x00, 0x83, 0x00, 0xfb, 0x00, 0xfd, 0x00, 0x08, 0x01, 0x00, 0x41, 0x00, 0x02, 0x00, 0x42, 0x00, 0x03, 0x00, 0x43, 0x00, 0xfa, 0x00, 0xfc, 0x00])

    sleep(2)
    z.receive()
    z.receive()
    z.receive()
    z.receive()
    z.receive()

    # ZB_RECEIVE_DATA_INDICATION
    #z.send(0x46, 0x87, [0x01, 0x00, 0xfb, 0x00, 0x0d, 0x00, 0x00, 0x01, 0x00, 0xb1, 0x01, 0x2d, 0x27, 0x82, 0x00, 0x00, 0x4b, 0x12, 0x00])
    #z.receive()

    #z.write(unhexlify("fe2ab7e8b4ef5997479bb2a613741b55ade07117"))
    #z.receive()
  
    # ZB_GET_DEVICE_INFO
    #for param in xrange(0, 8):
    #  z.send(0x26, 0x06, param)
    #  z.receive()
  
    for i in xrange(2):
      # Prise 1 ON
      z.ZB_SEND_DATA_REQUEST(
        destination=0x0001,
        commandID=0x0002,
        handle=0x01,
        ack=0xff,
        radius=0xff,
        data="\ff")
      z.receive() 
  
      sleep(10)
  
      # Prise 1 OFF
      z.ZB_SEND_DATA_REQUEST(
        destination=0x0001,
        commandID=0x0002,
        handle=0x01,
        ack=0xff,
        radius=0xff,
        data="\00")
      z.receive()

      sleep(10)
