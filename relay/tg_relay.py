"""tg_relay.py - the PC side of the Telegram app's byte pipe (src/tg_pipe.h), over the f286dbg USB
agent: it finds the pipe through the crumb D:\\F286_76_<address>.TXT, then loops reading and writing the
phone's memory, moving TCP bytes between the pipe's rings and a real socket to the DC the app asks for.

    python ../f286dbg/tools/f286.py run out/tg.bin    # start the app (or open it from the launcher)
    python relay/tg_relay.py [--tools DIR]            # DIR holds f286.py (default: ../f286dbg/tools)

The relay sees only MTProto ciphertext. It also gives the app the time, 32 bytes of entropy
(os.urandom) and the api_id/api_hash, which stay off the phone's storage. These come from
$TG_API_ID / $TG_API_HASH or the OS keyring (service "telegram-api", users "api_id" and "api_hash";
$TG_KEYRING_SERVICE overrides the name). This is a stand-in until the phone's own sockets (sci_sock_*,
PDP) are reverse-engineered: the app's client code does not change when the pipe is replaced. The
Relay class only needs mem_read/mem_write, so anything with access to the app's memory can drive it.
"""
import argparse
import os
import socket
import struct
import sys
import time

MAGIC = 0x31504754
HDR = 0x90                                   # header bytes up to the rings (tg_pipe.h)
O_UP_RD, O_DN_WR, O_ACK = 0x14, 0x18, 0x30
O_TIME, O_ENT_SEQ, O_ENT, O_API_ID, O_API_HASH = 0x38, 0x40, 0x48, 0x68, 0x6c


def credentials(log=print):
    """-> (api_id, api_hash) from the environment or the keyring, (None, None) if missing.
    The values are never logged."""
    api_id, api_hash = os.environ.get("TG_API_ID"), os.environ.get("TG_API_HASH")
    if api_id and api_hash:
        return api_id, api_hash
    service = os.environ.get("TG_KEYRING_SERVICE", "telegram-api")
    try:
        import keyring
        return keyring.get_password(service, "api_id"), keyring.get_password(service, "api_hash")
    except Exception as e:                              # noqa: BLE001  (no keyring module or backend)
        log(f"no credentials: set TG_API_ID/TG_API_HASH or install keyring ({e})")
        return None, None


def find_tools(arg):
    """the directory holding f286.py: --tools, $F286_TOOLS, or ../f286dbg/tools"""
    for d in (arg, os.environ.get("F286_TOOLS")):
        if d:
            if not os.path.exists(os.path.join(d, "f286.py")):
                sys.exit(f"no f286.py in {d}")
            return d
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "f286dbg", "tools")
    if os.path.exists(os.path.join(d, "f286.py")):
        return d
    sys.exit("f286.py not found: pass --tools DIR or set F286_TOOLS (it is in the f286dbg repository)")


class Relay:
    """mem_read(addr, n) -> bytes, mem_write(addr, data); one poll() per tick"""

    def __init__(self, base, mem_read, mem_write, log=print, credentials=True):
        self.base, self.rd, self.wr, self.log = base, mem_read, mem_write, log
        self.sock, self.primed, self.polls, self.up, self.down = None, False, 0, 0, 0
        self.credentials = credentials

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def poll(self):
        """-> False once the app has gone (magic cleared)"""
        h = self.rd(self.base, HDR)
        magic, size, up_cap, dn_cap, up_wr, up_rd, dn_wr, dn_rd, req, req_seq, ip, port, ack, conn, \
            _t, polls = struct.unpack_from("<16I", h)
        if magic != MAGIC:
            self.close()
            return False
        self.polls = polls + 1
        self.wr(self.base + O_TIME, struct.pack("<II", int(time.time()), self.polls))
        if not self.primed:
            self.primed = True
            if conn and req_seq == ack:                 # an earlier relay's socket: tell the app it is gone
                self.wr(self.base + 0x34, struct.pack("<I", 0))
                self.log("stale connection reset")
            ent_seq = struct.unpack_from("<I", h, O_ENT_SEQ)[0]
            self.wr(self.base + O_ENT, os.urandom(32))
            self.wr(self.base + O_ENT_SEQ, struct.pack("<I", ent_seq + 1))
            if self.credentials:
                api_id, api_hash = credentials(self.log)
                if api_id and api_hash:
                    self.wr(self.base + O_API_HASH, api_hash.encode() + b"\0")
                    self.wr(self.base + O_API_ID, struct.pack("<I", int(api_id)))
                    self.log("api_id/api_hash given")
        if req_seq != ack:
            self.close()
            conn = 0
            if req == 1:
                addr = socket.inet_ntoa(struct.pack(">I", ip))
                try:
                    self.sock = socket.create_connection((addr, port), timeout=10)
                    self.sock.setblocking(False)
                    conn = 1
                    self.log(f"connected {addr}:{port}")
                    # bytes queued for an earlier socket must not reach this one; the app writes
                    # the new stream only after it sees the ack below
                    if up_wr != up_rd:
                        self.log(f"dropped {(up_wr - up_rd) & 0xffffffff} stale bytes")
                    up_rd = up_wr
                    self.wr(self.base + O_UP_RD, struct.pack("<I", up_rd))
                except OSError as e:
                    self.log(f"connect {addr}:{port} failed: {e}")
            else:
                self.log("close")
            self.wr(self.base + O_ACK, struct.pack("<II", req_seq, conn))
        if not self.sock:
            return True
        up_base, dn_base = self.base + HDR, self.base + HDR + up_cap
        while up_wr != up_rd:                           # phone -> server
            idx = up_rd & (up_cap - 1)
            n = min((up_wr - up_rd) & 0xffffffff, up_cap - idx)
            try:
                self.sock.sendall(self.rd(up_base + idx, n))
            except OSError as e:
                self.log(f"send failed: {e}")
                break
            up_rd = (up_rd + n) & 0xffffffff
            self.up += n
        self.wr(self.base + O_UP_RD, struct.pack("<I", up_rd))
        free = dn_cap - ((dn_wr - dn_rd) & 0xffffffff)  # server -> phone
        if free:
            try:
                data = self.sock.recv(free)
                if not data:
                    self.log("server closed")
                    self.close()
                    self.wr(self.base + 0x34, struct.pack("<I", 0))
                    return True
            except BlockingIOError:
                data = b""
            except OSError as e:
                self.log(f"recv failed: {e}")
                data = b""
            off = 0
            while off < len(data):
                idx = dn_wr & (dn_cap - 1)
                n = min(len(data) - off, dn_cap - idx)
                self.wr(dn_base + idx, data[off:off + n])
                dn_wr = (dn_wr + n) & 0xffffffff
                off += n
            if data:
                self.down += len(data)
                self.wr(self.base + O_DN_WR, struct.pack("<I", dn_wr))
        if (self.up, self.down) != getattr(self, "_shown", None):
            self._shown = (self.up, self.down)
            self.log(f"{time.strftime('%H:%M:%S')} up {self.up} B, down {self.down} B")
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", help="directory with f286.py, the f286dbg agent's PC client")
    ap.add_argument("--emu", metavar="HOST:PORT", help="talk to the agent over TCP instead of USB")
    ap.add_argument("--every", type=float, default=0.03, help="seconds between polls")
    a = ap.parse_args()
    sys.path.insert(0, find_tools(a.tools))
    import f286                                         # noqa: E402
    ph = f286.Phone("tcp" if a.emu else "usb", a.emu)
    base = None
    for name, _, _ in ph.fs_ls("D:\\F286_76_*"):       # crumbs of earlier runs stay: take the live one
        addr = int(name[8:16], 16)
        # only probe inside the app heap window (always mapped): a read elsewhere can fault the phone
        if 0x82000000 <= addr < 0x83000000 and struct.unpack("<I", ph.read(addr, 4))[0] == MAGIC:
            base = addr
        else:
            ph.fs_rm("D:\\" + name)
    if base is None:
        sys.exit("no D:\\F286_76_*.TXT: is the Telegram app open?")
    print(f"pipe at {base:#x}")
    r = Relay(base, ph.read, ph.write)
    try:
        while r.poll():
            time.sleep(a.every)
    except KeyboardInterrupt:
        pass
    r.close()
    print(f"app closed; up {r.up} B, down {r.down} B")


if __name__ == "__main__":
    main()
