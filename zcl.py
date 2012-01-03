
class ZCLFrame:
  def __init__(self, frame):
    self.frame = [ord(c) for c in frame]

  def __repr__(self):
    res = "ZCLFrame: "

    ptr = 0
    control = self.frame[ptr]
    ptr += 1

    ftype = control & 0x03
    res += "type=%X" % ftype

    manuf = control & 0x04
    res += ", manufacturer=%X" % manuf

    direction = control & 0x08
    res += ", direction=%X" % direction

    disdefresp = control & 0x10
    res += ", disdefresp=%X" % disdefresp

    assert control & 0xE0 == 0

    if manuf:
      manuf_code = self.frame[ptr:2]
      ptr += 2

    seq_num = self.frame[ptr]
    ptr += 1

    res += ", seq=%02X" % seq_num

    return res
    

if __name__ == '__main__':
  from binascii import hexlify, unhexlify


  # 0000   FE 13 46 87 3E 14 FB 00    ..F.>...
  # 0008   0D 00 F0 01 00 B1 01 2D    .......-
  # 0010   27 82 00 00 4B 12 00 9E    '...K...
  # cmd=46:87 3e 14 fb 00 0d 00 f0 01 00 b1 01 2d 27 82 00 00 4b 12 00
  # AREQ: sAPI 0x87 ZB_RECEIVE_DATA_INDICATION source=143e command=00fb len=13 payload=F00100B1012D278200004B1200
  # Unknown command 00fb
  print ZCLFrame(unhexlify("F00100B1012D278200004B1200"))

  # 0000   FE 13 46 87 01 00 FB 00    ..F.....
  # 0008   0D 00 F0 01 00 B1 01 23    .......#
  # 0010   12 82 00 00 4B 12 00 8E    ....K...
  # cmd=46:87 01 00 fb 00 0d 00 f0 01 00 b1 01 23 12 82 00 00 4b 12 00
  # AREQ: sAPI 0x87 ZB_RECEIVE_DATA_INDICATION source=0001 command=00fb len=13 payload=F00100B10123128200004B1200
  # Unknown command 00fb

  print ZCLFrame(unhexlify("F00100B10123128200004B1200"))

  # 0000   FE 20 46 87 01 00 C1 00    . F.....
  # 0008   1A 00 FA 0F 00 00 00 82    ........
  # 0010   E4 57 2A 00 00 00 5E 00    .W*...^.
  # 0018   57 00 00 00 00 00 00 00    W.......
  # 0020   00 00 81 00 5D             ....]
  # cmd=46:87 01 00 c1 00 1a 00 fa 0f 00 00 00 82 e4 57 2a 00 00 00 5e 00 57 00 00 00 00 00 00 00 00 00 81 00
  # AREQ: sAPI 0x87 ZB_RECEIVE_DATA_INDICATION source=0001 command=00c1 len=26 payload=FA0F00000082E4572A0000005E00570000000000000000008100
  print ZCLFrame(unhexlify("FA0F00000082E4572A0000005E00570000000000000000008100"))
