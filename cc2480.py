#!/usr/bin/env python

import serial
from binascii import hexlify, unhexlify, a2b_hex
import struct
import sys
import re
import ast

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
    return "Frame(len=%i, cmd0=%i, cmd1=%i, data=%s)" % (self.length, self.cmd0, self.cmd1, hexlify(self.data).upper())

  def cc2480_dump_frame(self):
    print "cmd=%02x:%02x %s" % (self.cmd0, self.cmd1, " ".join(["%02x" % ord(c) for c in self.data]))

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

    frame_type = TYPES.get(frame_type)
    print frame_type, 

    print ":",
    subsystem = SUBSYSTEMS.get(subsystem)
    print subsystem,

    #print "%s: %s 0x%02x" % (TYPES.get(int(type), 'RESERVED'), SUBSYSTEMS.get(int(subsystem)), id) ,

    if self.cmd1 == 0x80:
      print "ZB_START_CONFIRM",
    if self.cmd1 == 0x81:
      print "ZB_BIND_CONFIRM CommandId=%02x%02x" % (ord(self.data[1]), ord(self.data[0])),
    if self.cmd1 == 0x82:
      print "ZB_ALLOW_BIND_CONFIRM CommandId=%02x%02x" % (ord(self.data[1]), ord(self.data[0])),
    if self.cmd1 == 0x83:
      print "ZB_SEND_DATA_CONFIRM handle=%02x" % ord(self.data[0]),
    if self.cmd1 == 0x87:
      length = ord(self.data[4])
      source, command, length, data = struct.unpack("<HHH%ds" % length, self.data)
      print "ZB_RECEIVE_DATA_INDICATION source=%04x command=%04x len=%d" % (source, command, length)
      print "Payload: " + hexlify(data).upper(),
    if self.cmd1 == 0x0a:
      print "ZB_APP_REGISTER_REQUEST",
    if self.cmd1 == 0x05:
      print "ZB_WRITE_CONFIGURATION",
    if self.cmd1 == 0x06:
      param = ord(self.data[0])
      print "ZB_GET_DEVICE_INFO param=%d" % param,
      if frame_type == 'SRSP':
        if param == 0:
          print "Device state",

        print "Payload: " + hexlify(self.data[1:]).upper(),

    if self.cmd1 == 0x08:
      print "ZB_PERMIT_JOINING_REQUEST",
    if self.cmd1 == 0x02:
      print "ZB_ALLOW_BIND",
    if self.cmd1 == 0x03:
      if frame_type == 'SREQ':
        print "ZB_SEND_DATA_REQUEST destination=%02x%02x commandID=%02x%02x handle=%02x" % (ord(self.data[1]), ord(self.data[0]), ord(self.data[2+1]), ord(self.data[2+0]), ord(self.data[2+2])),
      elif frame_type == 'SRSP':
        print "ZB_SEND_DATA_REQUEST",
      print "Payload: " + hexlify(self.data).upper(),
    if self.cmd1 == 0x01:
      print "ZB_BZB_BIND_DEVICE create=%d commandID=%02x%02x" % (ord(self.data[0]), ord(self.data[1+1]), ord(self.data[1+0])),

    if frame_type == 'AREQ':
      if self.cmd1 == 0x00:
        print "SYS_RESET_REQ",
      if self.cmd1 == 0x80:
        print "SYS_RESET_IND reason=%d" % ord(self.data[0]),
      if self.cmd1 == 0x02:
        print "SYS_VERSION transportRev=%d Product=%d Rel=%d.%d HwRev=%d" % (ord(self.data[0]), ord(self.data[1]), ord(self.data[2]), ord(self.data[3]), ord(self.data[4])),

    if frame_type == 'ZDO': 
      if self.cmd1 == 0xb6:
        print "ZDO_MGMT_PERMIT_JOIN_RSP",

    if frame_type == 'SREQ': 
      if self.cmd1 == 0x00:
        print "ZB_START_REQUEST",

    if frame_type == 'SRSP': 
      if self.cmd1 == 0x00:
        print "ZB_START_REQUEST",
    print


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
      f.cc2480_dump_frame()
    else:
      print "NO RESPONSE"

    return f

  def send(self, cmd0, cmd1, data):
    frame = Frame(cmd0, cmd1, data)
    frame.cc2480_dump_frame()
    self.write(frame.serialize())

  def ZB_SEND_DATA_REQUEST(self, destination, commandID, handle=0x00, ack=0x00, radius=0x01, data=""):

    data_length = len(data)
    payload = struct.pack("<HHBBBB", destination, commandID, handle, ack, radius, data_length)
    payload += data
    frame = Frame(0x26, 0x03, payload)
    frame.cc2480_dump_frame()
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
      Frame.from_wire(spkts[i]).cc2480_dump_frame()

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
            print hexlify(frame).upper()
            Frame.from_wire(frame).cc2480_dump_frame()
            print
        res = data


  else:
    z = CC2480(sys.argv[1])
    #z.write(unhexlify("fe00210223"))
    
    # SYS_RESET_REQ
    #z.send(0x41, 0x00, 0x1)
    #z.receive()

    # ZB_START_REQUEST
    z.send(0x26, 0x00, 0x00)
    z.receive()

    # ZB_APP_REGISTER_REQUEST
    z.send(0x26, 0x0a, [0x01, 0x44, 0x04, 0x00, 0x00, 0x01, 0x00, 0x06, 0x81, 0x00, 0x82, 0x00, 0xc1, 0x00, 0x83, 0x00, 0xfb, 0x00, 0xfd, 0x00, 0x08, 0x01, 0x00, 0x41, 0x00, 0x02, 0x00, 0x42, 0x00, 0x03, 0x00, 0x43, 0x00, 0xfa, 0x00, 0xfc, 0x00])
    z.send(0x26, 0x00, 0x00)

    # ZB_RECEIVE_DATA_INDICATION
    z.send(0x46, 0x87, [0x01, 0x00, 0xfb, 0x00, 0x0d, 0x00, 0x00, 0x01, 0x00, 0xb1, 0x01, 0x2d, 0x27, 0x82, 0x00, 0x00, 0x4b, 0x12, 0x00])
    z.receive()

    z.write(unhexlify("fe2ab7e8b4ef5997479bb2a613741b55ade07117"))
    z.receive()
  
    # ZB_GET_DEVICE_INFO
#    for param in xrange(0, 8):
#      z.send(0x26, 0x06, param)
#      z.receive()
  
    # ZB_APP_REGISTER_REQUEST
  
    # ZB_SEND_DATA_REQUEST
#    z.ZB_SEND_DATA_REQUEST(
#      destination=0x0103,
#      commandID=0x00fa,
#      handle=0x00,
#      ack=0x00,
#      radius=0xff,
#      data="\00\b1\01")
#    z.receive()
  
    while True:
      z.receive()
