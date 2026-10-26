@load base/frameworks/notice
@load base/protocols/conn

module UDPLab;

export {
    redef enum Notice::Type += {
        UDP_Like_Scan
    };

    const threshold: count = 10 &redef;
}

global scan_count: table[addr, addr] of count &default=0;
global notice_count: table[addr, addr] of count &default=0;
global batch: table[addr, addr] of count &default=1;
global seen_port: table[addr, addr, port] of count &default=0;

event Conn::log_conn(rec: Conn::Info)
    {
    if (rec$proto != udp || ! rec?$history ||
        ! rec?$conn_state)
        return;

    if (rec$history != "D" || rec$conn_state != "S0")
        return;

    local src = rec$id$orig_h;
    local dst = rec$id$resp_h;
    local p = rec$id$resp_p;

    if (seen_port[src, dst, p] == batch[src, dst])
        return;

    seen_port[src, dst, p] = batch[src, dst];
    scan_count[src, dst] += 1;

    if (scan_count[src, dst] >= threshold)
        {
        NOTICE([
            $note=UDPLab::UDP_Like_Scan,
            $msg=fmt("UDP-like scan: %d distinct ports from %s to %s; previous notices=%d",
                     scan_count[src, dst], src, dst,
                     notice_count[src, dst]),
            $src=src,
            $dst=dst,
            $n=scan_count[src, dst],
            $identifier=fmt("udp-%s-%s-%d",
                            src, dst, notice_count[src, dst])
        ]);

        notice_count[src, dst] += 1;
        scan_count[src, dst] = 0;
        batch[src, dst] += 1;
        }
    }
