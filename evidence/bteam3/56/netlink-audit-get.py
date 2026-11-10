import socket, struct, os
AF_NETLINK=16; NETLINK_AUDIT=9; AUDIT_GET=1000
NLM_F_REQUEST=1; NLM_F_ACK=4
try:
    s=socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
except OSError as e:
    print("socket failed:", e); raise SystemExit
s.bind((0,0))
pid=s.getsockname()[0]
hdr=struct.pack("=IHHII", 16, AUDIT_GET, NLM_F_REQUEST|NLM_F_ACK, 1, 0)
s.send(hdr)
try:
    data=s.recv(4096)
except OSError as e:
    print("recv failed:", e); raise SystemExit
ln, typ, flags, seq, spid = struct.unpack("=IHHII", data[:16])
print("reply len=%d type=%d flags=%d seq=%d pid=%d" % (ln,typ,flags,seq,spid))
if typ == 2:  # NLMSG_ERROR
    err = struct.unpack("=i", data[16:20])[0]
    print("error=%d" % err)
else:
    print("payload type=%d bytes=%s" % (typ, data[16:].hex()))
