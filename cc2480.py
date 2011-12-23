#!/usr/bin/env python

import serial
from binascii import hexlify, unhexlify, a2b_hex
import struct
import sys
import re
import ast
from time import sleep
import multiprocessing as mp
import Queue
import traceback

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
# From http://code.activestate.com/recipes/142812-hex-dumper/
#
def hexdump(src, length=8):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
       text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
       result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return b'\n'.join(result)

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

  def payload_decode(self, command, data):
    res = ""

    if command == 0x00FB:
      print len(data)
      mac = struct.unpack("<6s", data)[0]
      res += "MAC: " + hexlify(mac)
    elif command == 0x00C1:
      # 715BF24EFF7F25578006BB0C460E750691033BD0080000008000
      seq = data[0]
    else:
      res += "Unknown command %04x" % command

    res += "\n" + hexdump(data)
    return res

  def status(self, id):
    return self.STATUS.get(id)

  def _compute_fcs(self):
    return _fcs(chr(self.cmd0) + chr(self.cmd1) + chr(self.length) + self.data)
  fcs = property(_compute_fcs)

  def __repr__(self):
    res = ""

    #res += hexdump(self.frame) + "\n"
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
      #source, command, length, data = struct.unpack("<HHH%ds" % length, self.data)
      source, command, length = struct.unpack("<HHH", self.data[0:6])
      data = self.data[7:length][::-1]
      res +=  "ZB_RECEIVE_DATA_INDICATION source=%04x command=%04x len=%d" % (source, command, length)
      res +=  " payload=" + hexlify(data).upper() + "\n"
      res += self.payload_decode(command, data)

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

    if self.cmd0 == 0x26:
      if self.cmd1 == 0x05:
        configid= ord(self.data[0])
        res +=  "ZB_WRITE_CONFIGURATION ConfigID=%02x Len=%02x" % (ord(self.data[0]), ord(self.data[1]))
        length = ord(self.data[1])
        if length:
          res += " Value=" + hexlify(self.data[2:2+length]).upper() + " "
  
        if configid == 0x0003:
          res += "ZCD_NV_STARTUP_OPTION"
  
        if configid == 0x0087:
          res += "ZCE_NV_LOGICAL_TYPE"
  
      if self.cmd1 == 0x07:
        res += "ZB_FIND_DEVICE_REQUEST SearchKey=%02X%02X%02X%02X%02X%02X%02X%02X" % data

      if self.cmd1 == 0x08:
        res +=  "ZB_PERMIT_JOINING_REQUEST Destination=%02x%02x Timeout=%02x" % (data[1], data[0], data[2])


    if self.cmd1 == 0x06:
      param = ord(self.data[0])
      res +=  "ZB_GET_DEVICE_INFO param=%d " % param
      if frame_type == 'SRSP':
        if param == 0:
          res +=  "Device state"

        res +=  " payload=" + hexlify(self.data[1:]).upper()

    if self.cmd0 == 0x21:
      if self.cmd1 == 0x02:
        res += "SYS_VERSION"
      if self.cmd1 == 0x0D:
        res += "SYS_ADC_READ channel=%02x resolution=%02x" % (data[0], data[1])

    if self.cmd0 == 0x26:
      if self.cmd1 == 0x01:
        res +=  "ZB_BIND_DEVICE create=%d commandID=%02x%02x" % (ord(self.data[0]), ord(self.data[1+1]), ord(self.data[1+0]))

      if self.cmd1 == 0x02:
        res +=  "ZB_ALLOW_BIND timeout=%02x" % ord(self.data[0])

    if self.cmd1 == 0x03:
      if frame_type == 'SREQ':
        res +=  "ZB_SEND_DATA_REQUEST destination=%02x%02x commandID=%02x%02x handle=%02x" % (ord(self.data[1]), ord(self.data[0]), ord(self.data[2+1]), ord(self.data[2+0]), ord(self.data[2+2]))
      elif frame_type == 'SRSP':
        res +=  "ZB_SEND_DATA_REQUEST"
      res +=  " payload=" + hexlify(self.data).upper()
    if frame_type == 'AREQ':
      if self.cmd1 == 0x00:
        res += "SYS_RESET_REQ"
      if self.cmd1 == 0x80:
        res += "SYS_RESET_IND reason=%d" % ord(self.data[0])
      if self.cmd1 == 0x02:
        res += "SYS_VERSION transportRev=%d Product=%d Rel=%d.%d HwRev=%d" % (ord(self.data[0]), ord(self.data[1]), ord(self.data[2]), ord(self.data[3]), ord(self.data[4]))

    if frame_type == 'ZDO': 
      if self.cmd1 == 0xb6:
        res += "ZDO_MGMT_PERMIT_JOIN_RSP"

    if frame_type == 'SREQ': 
      if self.cmd1 == 0x00:
        res += "ZB_START_REQUEST"

    if frame_type == 'SRSP': 
      if self.cmd1 == 0x00:
        res += "ZB_START_REQUEST"

    if self.cmd0 == 0x46:
      if self.cmd1 == 0x80:
        res += "ZB_START_CONFIRM Status=%s" % self.status(data[0])

      if self.cmd1 == 0x85:
        res += "ZB_FIND_DEVICE_CONFIRM SearchType=%02X SearchKey=%02X%02X Result=%02X%02X%02X%02X%02X%02X%02X%02X" % (data[0], data[2], data[1], data[3:]) 

    if self.cmd0 == 0x66:
      if self.cmd1 == 0x02:
        res += "ZB_ALLOW_BIND"
      if self.cmd1 == 0x05:
        res += "ZB_WRITE_CONFIGURATION Status=%s" % self.status(data[0])
      if self.cmd1 == 0x07:
        res += "ZB_FIND_DEVICE_REQUEST"
      if self.cmd1 == 0x08:
        res += "ZB_PERMIT_JOINING_REQUEST Stats=%s" % self.status(data[0])

    if self.cmd0 == 0x61:
      if self.cmd1 == 0x02:
        res += "SYS_VERSION TransportRev=%02x Product=%02x MajorRel=%02x MinorRel=%02x HwRev=%02x" % tuple([ord(c) for c in self.data])
        #res += "SYS_VERSION TransportRev=%02x Product=%02x MajorRel=%02x MinorRel=%02x HwRev=%02x" % (ord(self.data[0]), ord(self.data[1]), ord(self.data[2]), ord(self.data[3]), ord(self.data[4]))
        #res += "SYS_VERSION %d" % len(self.data)

      if self.cmd1 == 0x08:
        res += "SYS_OSAL_NV_READ"

      if self.cmd1 == 0x0D:
        res += "SYS_ADC_READ Value=%02x%02x" % (data[1], data[0])

    #
    # ZDO SREQ
    #

    if self.cmd0 == 0x25:
      if self.cmd1 == 0x00:
        res += "ZDO_NWK_ADDR_REQ"

      if self.cmd1 == 0x01:
        res += "ZDO_IEEE_ADDR_REQ"

      if self.cmd1 == 0x02:
        res += "ZDO_NODE_DESC_REQ"

      if self.cmd1 == 0x03:
        res += "ZDO_POWER_DESC_REQ"

      if self.cmd1 == 0x04:
        res += "ZDO_SIMPLE_DESC_REQ"

      if self.cmd1 == 0x05:
        res += "ZDO_ACTIVE_EP_REQ"

      if self.cmd1 == 0x06:
        res += "ZDO_MATCH_DESC_REQ"

      if self.cmd1 == 0x07:
        res += "ZDO_COMPLEX_DESC_REQ"

      if self.cmd1 == 0x08:
        res += "ZDO_USER_DESC_REQ"

      if self.cmd1 == 0x0A:
        res += "ZDO_DEVICE_ANNCE"

      if self.cmd1 == 0x0B:
        res += "ZDO_USER_DESC_SET"

      if self.cmd1 == 0x0C:
        res += "ZDO_SERVER_DISC_REQ"

      if self.cmd1 == 0x20:
        res += "ZDO_END_DEVICE_BIND_REQ"

      if self.cmd1 == 0x21:
        res += "ZDO_SIMPLE_DESC_RSP"

      if self.cmd1 == 0x22:
        res += "ZDO_UNBIND_REQ"

      if self.cmd1 == 0x30:
        res += "ZDO_MGMT_NWK_DISC_REQ"

      if self.cmd1 == 0x31:
        res += "ZDO_MGMT_LQI_REQ"

      if self.cmd1 == 0x32:
        res += "ZDO_MGMT_RTG_REQ"

      if self.cmd1 == 0x33:
        res += "ZDO_MGMT_BIND_REQ"

      if self.cmd1 == 0x34:
        res += "ZDO_MGMT_LEAVE_REQ"

      if self.cmd1 == 0x35:
        res += "ZDO_MGMT_DIRECT_JOIN_REQ"

      if self.cmd1 == 0x36:
        res += "ZDO_MGMT_PERMIT_JOIN_REQ"

      if self.cmd1 == 0x37:
        res += "ZDO_MGMT_NWK_UPDATE_REQ"

      if self.cmd1 == 0x40:
        res += "ZDO_STARTUP_FROM_APP"

      if self.cmd1 == 0x23:
        res += "ZDO_SET_LINK_KEY"

      if self.cmd1 == 0x24:
        res += "ZDO_REMOVE_LINK_KEY"

      if self.cmd1 == 0x25:
        res += "ZDO_GET_LINK_KEY"

      if self.cmd1 == 0x26:
        res += "ZDO_NWK_DISCOVERY_REQ"

      if self.cmd1 == 0x27:
        res += "ZDO_JOIN_REQ"

      if self.cmd1 == 0x3E:
        res += "MSG_CB_REGISTER"

      if self.cmd1 == 0x3F:
        res += "ZDO_ MSG_CB_REMOVE"

    #
    # ZDO AREQ
    #
    if self.cmd0 == 0x45:
      if self.cmd1 == 0x41:
        res += "ZDO_AUTO_FIND_DESTINATION"

      if self.cmd1 == 0x80:
        res += "ZDO_NWK_ADDR_RSP"

      if self.cmd1 == 0x81:
        res += "ZDO_IEEE_ADDR_RSP"

      if self.cmd1 == 0x82:
        res += "ZDO_NODE_DESC_RSP"

      if self.cmd1 == 0x83:
        res += "ZDO_POWER_DESC_RSP"

      if self.cmd1 == 0x84:
        res += "ZDO_SIMPLE_DESC_RSP"

      if self.cmd1 == 0x85:
        res += "ZDO_ACTIVE_EP_RSP"

      if self.cmd1 == 0x86:
        res += "ZDO_MATCH_DESC_RSP"

      if self.cmd1 == 0x87:
        res += "ZDO_COMPLEX_DESC_RSP"

      if self.cmd1 == 0x88:
        res += "ZDO_USER_DESC_RSP"

      if self.cmd1 == 0x89:
        res += "ZDO_USER_DESC_CONF"

      if self.cmd1 == 0x8A:
        res += "ZDO_SERVER_DISC_RSP"

      if self.cmd1 == 0xA0:
        res += "ZDO_END_DEVICE_BIND_RSP"

      if self.cmd1 == 0xA1:
        res += "ZDO_BIND_RSP"

      if self.cmd1 == 0xA2:
        res += "ZDO_UNBIND_RSP"

      if self.cmd1 == 0xB0:
        res += "ZDO_MGMT_NWK_DISC_RSP"

      if self.cmd1 == 0xB1:
        res += "ZDO_MGMT_LQI_RSP"

      if self.cmd1 == 0xB2:
        res += "ZDO_MGMT_RTG_RSP"

      if self.cmd1 == 0xB3:
        res += "ZDO_MGMT_BIND_RSP"

      if self.cmd1 == 0xB4:
        res += "ZDO_MGMT_LEAVE_RSP"

      if self.cmd1 == 0xB5:
        res += "ZDO_MGMT_DIRECT_JOIN_RSP"

      if self.cmd1 == 0xB6:
        res += "ZDO_MGMT_PERMIT_JOIN_RSP"

      if self.cmd1 == 0xC0:
        res += "ZDO_STATE_CHANGE_IND"

      if self.cmd1 == 0xC1:
        res += "ZDO_END_DEVICE_ANNCE_IND"

      if self.cmd1 == 0xC2:
        res += "ZDO_MATCH_DESC_RSP_SENT"

      if self.cmd1 == 0xC3:
        res += "ZDO_STATUS_ERROR_RSP"

      if self.cmd1 == 0xC4:
        res += "ZDO_SRC_RTG_IND"

      if self.cmd1 == 0xFF:
        res += "ZDO_ MSG_CB_INCOMING"



    #
    # ZDO SRSP
    #
    if self.cmd0 == 0x65:
      if self.cmd1 == 0x00:
        res += "ZDO_NWK_ADDR_REQ"

      if self.cmd1 == 0x01:
        res += "ZDO_IEEE_ADDR_REQ"

      if self.cmd1 == 0x02:
        res += "ZDO_NODE_DESC_REQ"

      if self.cmd1 == 0x03:
        res += "ZDO_POWER_DESC_REQ"

      if self.cmd1 == 0x04:
        res += "ZDO_SIMPLE_DESC_REQ"


      if self.cmd1 == 0x05:
        res += "ZDO_ACTIVE_EP_REQ"

      if self.cmd1 == 0x06:
        res += "ZDO_MATCH_DESC_REQ"

      if self.cmd1 == 0x07:
        res += "ZDO_COMPLEX_DESC_REQ"

      if self.cmd1 == 0x08:
        res += "ZDO_USER_DESC_REQ"

      if self.cmd1 == 0x0A:
        res += "ZDO_DEVICE_ANNCE"

      if self.cmd1 == 0x0B:
        res += "ZDO_USER_DESC_SET"

      if self.cmd1 == 0x0C:
        res += "ZDO_SERVER_DISC_REQ"

      if self.cmd1 == 0x20:
        res += "ZDO_END_DEVICE_BIND_REQ"

      if self.cmd1 == 0x21:
        res += "ZDO_SIMPLE_DESC_RSP"

      if self.cmd1 == 0x22:
        res += "ZDO_UNBIND_REQ"

      if self.cmd1 == 0x30:
        res += "ZDO_MGMT_NWK_DISC_REQ"

      if self.cmd1 == 0x31:
        res += "ZDO_MGMT_LQI_REQ"

      if self.cmd1 == 0x32:
        res += "ZDO_MGMT_RTG_REQ"

      if self.cmd1 == 0x33:
        res += "ZDO_MGMT_BIND_REQ"

      if self.cmd1 == 0x34:
        res += "ZDO_MGMT_LEAVE_REQ"

      if self.cmd1 == 0x35:
        res += "ZDO_MGMT_DIRECT_JOIN_REQ"

      if self.cmd1 == 0x36:
        res += "ZDO_MGMT_PERMIT_JOIN_REQ"

      if self.cmd1 == 0x37:
        res += "ZDO_MGMT_NWK_UPDATE_REQ"

      if self.cmd1 == 0x40:
        res += "ZDO_STARTUP_FROM_APP"

      if self.cmd1 == 0x41:
        res += "ZDO_AUTO_FIND_DESTINATION"

      if self.cmd1 == 0x23:
        res += "ZDO_SET_LINK_KEY"

      if self.cmd1 == 0x24:
        res += "ZDO_REMOVE_LINK_KEY"

      if self.cmd1 == 0x25:
        res += "ZDO_GET_LINK_KEY"

      if self.cmd1 == 0x26:
        res += "ZDO_NWK_DISCOVERY_REQ"

      if self.cmd1 == 0x27:
        res += "ZDO_JOIN_REQ"

      if self.cmd1 == 0x80:
        res += "ZDO_NWK_ADDR_RSP"

      if self.cmd1 == 0x81:
        res += "ZDO_IEEE_ADDR_RSP"

      if self.cmd1 == 0x82:
        res += "ZDO_NODE_DESC_RSP"

      if self.cmd1 == 0x83:
        res += "ZDO_POWER_DESC_RSP"

      if self.cmd1 == 0x84:
        res += "ZDO_SIMPLE_DESC_RSP"


      if self.cmd1 == 0x85:
        res += "ZDO_ACTIVE_EP_RSP"

      if self.cmd1 == 0x86:
        res += "ZDO_MATCH_DESC_RSP"

      if self.cmd1 == 0x87:
        res += "ZDO_COMPLEX_DESC_RSP"

      if self.cmd1 == 0x88:
        res += "ZDO_USER_DESC_RSP"

      if self.cmd1 == 0x89:
        res += "ZDO_USER_DESC_CONF"

      if self.cmd1 == 0x8A:
        res += "ZDO_SERVER_DISC_RSP"

      if self.cmd1 == 0xA0:
        res += "ZDO_END_DEVICE_BIND_RSP"

      if self.cmd1 == 0xA1:
        res += "ZDO_BIND_RSP"

      if self.cmd1 == 0xA2:
        res += "ZDO_UNBIND_RSP"

      if self.cmd1 == 0xB0:
        res += "ZDO_MGMT_NWK_DISC_RSP"

      if self.cmd1 == 0xB1:
        res += "ZDO_MGMT_LQI_RSP"

      if self.cmd1 == 0xB2:
        res += "ZDO_MGMT_RTG_RSP"

      if self.cmd1 == 0xB3:
        res += "ZDO_MGMT_BIND_RSP"

      if self.cmd1 == 0xB4:
        res += "ZDO_MGMT_LEAVE_RSP"

      if self.cmd1 == 0xB5:
        res += "ZDO_MGMT_DIRECT_JOIN_RSP"

      if self.cmd1 == 0xB6:
        res += "ZDO_MGMT_PERMIT_JOIN_RSP"

      if self.cmd1 == 0xC0:
        res += "ZDO_STATE_CHANGE_IND"

      if self.cmd1 == 0xC1:
        res += "ZDO_END_DEVICE_ANNCE_IND"

      if self.cmd1 == 0xC2:
        res += "ZDO_MATCH_DESC_RSP_SENT"

      if self.cmd1 == 0xC3:
        res += "ZDO_STATUS_ERROR_RSP"

      if self.cmd1 == 0xC4:
        res += "ZDO_SRC_RTG_IND"

      if self.cmd1 == 0x3E:
        res += "MSG_CB_REGISTER"

      if self.cmd1 == 0x3F:
        res += "ZDO_ MSG_CB_REMOVE"

      if self.cmd1 == 0xFF:
        res += "ZDO_ MSG_CB_INCOMING"



    if self.cmd0 == 0x45:
      if self.cmd1 == 0x84:
        res += "ZDO_SIMPLE_DESC_RSP" # FIXME

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

      try:
        syscall, data = re.findall('^(.+)\(\d+, "(.*)"', line)[0]
      except IndexError:
        continue

      data = ast.literal_eval('"' + data + '"')

      if syscall == prev_syscall and line != "":
        res += data
      else:
        prev_syscall = syscall
        if res:

          for frame in re.findall("\xfe[^\xfe]+", res):
            print hexlify(frame).upper()

            try:
              if syscall == 'write':
                print red(repr(Frame.from_wire(frame)))
              elif syscall == 'read':
                print green(repr(Frame.from_wire(frame)))
              print
            except Exception, e:
              print e
        res = data


  else:

    def writer(q):
      # SYS_VERSION
      q.put((0x21, 0x02))
      
      # SYS_RESET_REQ
      q.put((0x41, 0x00, 0x1))
  
      # ZB_START_REQUEST
      q.put((0x26, 0x00, 0x00))
  
      # ZB_APP_REGISTER_REQUEST
      q.put((0x26, 0x0a, 0x01, 0x44, 0x04, 0x00, 0x00, 0x01, 0x00, 0x06, 0x81, 0x00, 0x82, 0x00, 0xc1, 0x00, 0x83, 0x00, 0xfb, 0x00, 0xfd, 0x00, 0x08, 0x01, 0x00, 0x41, 0x00, 0x02, 0x00, 0x42, 0x00, 0x03, 0x00, 0x43, 0x00, 0xfa, 0x00, 0xfc, 0x00))
  
      # ZB_RECEIVE_DATA_INDICATION
      #q.put((0x46, 0x87, [0x01, 0x00, 0xfb, 0x00, 0x0d, 0x00, 0x00, 0x01, 0x00, 0xb1, 0x01, 0x2d, 0x27, 0x82, 0x00, 0x00, 0x4b, 0x12, 0x00]))
  
      #z.write(unhexlify("fe2ab7e8b4ef5997479bb2a613741b55ade07117"))))
    
      # ZB_GET_DEVICE_INFO
      #for param in xrange(0, 8):
      #  q.put((0x26, 0x06, param))

      def ZB_SEND_DATA_REQUEST(destination, commandID, handle=0x00, ack=0x00, radius=0x01, data=""):
        data_length = len(data)
        payload = struct.pack("<HHBBBB", destination, commandID, handle, ack, radius, data_length)
        payload += data
        return (0x26, 0x03) + tuple([ord(c) for c in payload])
   
      while False:
        # Prise 1 ON
        q.put(ZB_SEND_DATA_REQUEST(
          destination=0x0001,
          commandID=0x0002,
          handle=0x01,
          ack=0xff,
          radius=0xff,
          data="\ff"))

        sleep(10)
    
        # Prise 1 OFF
        q.put(ZB_SEND_DATA_REQUEST(
          destination=0x0001,
          commandID=0x0002,
          handle=0x01,
          ack=0xff,
          radius=0xff,
          data="\00"))

        sleep(10)

    def reader(q):
      z = CC2480(sys.argv[1])

      while True:
        #print "tick"
        z.receive()
        try:
          data = q.get(False)

          if data:
            z.send(data[0], data[1], data[2:])
        except Queue.Empty:
          pass
        except Exception:
          traceback.print_exc()
        
        sleep(0.1)
 
    # Shared communication queue
    q = mp.Queue()

    r = mp.Process(target=reader, args=(q,))
    r.start()

    w = mp.Process(target=writer, args=(q,))
    w.start()

    # Interactive shell
    while True:
      data = raw_input()
      q.put(tuple([ord(c) for c in unhexlify(data.translate(None, " :."))]))

    r.join()
    w.join()
