from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, icmp, udp, tcp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {
            '10.0.0.1': '10:00:00:00:00:01',
            '10.0.0.2': '10:00:00:00:00:02',
            '10.0.0.3': '10:00:00:00:00:03',
            '10.0.0.4': '10:00:00:00:00:04'
        }
        self.links = {
            # links[src][dst] -> port
            '10:00:00:00:00:01' : { '10:00:00:00:00:02' : 2, '10:00:00:00:00:04' : 3 },
            '10:00:00:00:00:02' : { '10:00:00:00:00:03' : 2, '10:00:00:00:00:01' : 3 },
            '10:00:00:00:00:03' : { '10:00:00:00:00:04' : 2, '10:00:00:00:00:02' : 3 },
            '10:00:00:00:00:04' : { '10:00:00:00:00:01' : 2, '10:00:00:00:00:03' : 3 }
        }
        self.to_host = {
            '10:00:00:00:00:01' : 1,
            '10:00:00:00:00:02' : 2,
            '10:00:00:00:00:03' : 3,
            '10:00:00:00:00:04' : 4
        }
        self.tcp_blacklist = { '10:00:00:00:00:02', '10:00:00:00:00:04' }
        self.udp_blacklist = [ '10:00:00:00:00:01', '10:00:00:00:00:04' ]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        # Drop all IPv6 traffic
        match = parser.OFPMatch(eth_type=0x86DD)
        actions = []
        self.add_flow(datapath, 1, match, actions)

        # regular traffic
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        self.logger.info("packet-in %s" % (pkt,))
        pkt_ethernet = pkt.get_protocols(ethernet.ethernet)[0]
        if not pkt_ethernet:
            return

        dst = pkt_ethernet.dst
        src = pkt_ethernet.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(datapath, in_port, pkt_ethernet, pkt_arp)
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            pkt_icmp = pkt.get_protocol(icmp.icmp)
            pkt_udp = pkt.get_protocol(udp.udp)
            pkt_tcp = pkt.get_protocol(tcp.tcp)

            if pkt_icmp:
                # handle icmp
                self._handle_icmp(dpid, datapath, pkt_ethernet, pkt_icmp, pkt)
                return
            elif pkt_udp:
                # handle udp
                self._handle_udp(dpid, datapath, pkt_ethernet, pkt_udp, pkt)
                return
            elif pkt_tcp:
                # handle tcp
                self._handle_tcp(dpid, datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_tcp, pkt)
                return
    
    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.ip_to_mac[pkt_arp.dst_ip]))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=self.ip_to_mac[pkt_arp.dst_ip],
                                 src_ip=pkt_arp.dst_ip,
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))
        self._send_packet(datapath, port, pkt)

    def _get_out_port(self, dpid, src, dst, clockwise):
        if self.to_host[dst] == dpid:
            return 1
        port = 2 if clockwise else 3
        return self.links[src].get(dst, port)

    def _handle_icmp(self, dpid, datapath, pkt_ethernet, pkt_icmp, pkt):
        # clockwise if two shortest path
        # port 2 is clockwise, port 3 is counter-clockwise
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        src = pkt_ethernet.src
        dst = pkt_ethernet.dst
        out_port = self._get_out_port(dpid, src, dst, True)
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800,
                                ip_proto=1,
                                eth_dst=dst)
        actions = [parser.OFPActionOutput(port=out_port)]
        self.add_flow(datapath, 1, match, actions)
        self._send_packet(datapath, out_port, pkt)

    def _handle_tcp(self, dpid, datapath, port, pkt_ethernet, pkt_ipv4, pkt_tcp, pkt):
        # clockwise if two shortest path
        # port 2 is clockwise, port 3 is counter-clockwise
        src = pkt_ethernet.src
        dst = pkt_ethernet.dst
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # blocking rule - HTTP from H2 or H4
        if src in self.tcp_blacklist and pkt_tcp.dst_port == 80:
            pkt_rst = packet.Packet()
            pkt_rst.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                               src=dst, 
                                               dst=src))
            pkt_rst.add_protocol(ipv4.ipv4(src=pkt_ipv4.dst,
                                       dst=pkt_ipv4.src,
                                       proto=6))
            pkt_rst.add_protocol(tcp.tcp(src_port = pkt_tcp.dst_port, 
                                     dst_port = pkt_tcp.src_port, 
                                     ack=pkt_tcp.seq+1, 
                                     bits=0b010100))
            self._send_packet(datapath, port, pkt_rst)
            self.logger.info("TCP RST sent")
            # blocking rule should have higher priority
            match = parser.OFPMatch(eth_type=0x0800,
                                    ip_proto=6,
                                    eth_src=src,
                                    tcp_dst=pkt_tcp.dst_port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 100, match, actions)
            return
        # normal case
        out_port = self._get_out_port(dpid, src, dst, True)
        match = parser.OFPMatch(eth_type=0x0800,
                                ip_proto=6,
                                eth_src=src,
                                eth_dst=dst,
                                tcp_dst=pkt_tcp.dst_port)
        actions = [parser.OFPActionOutput(port=out_port)]
        self.add_flow(datapath, 1, match, actions)
        self._send_packet(datapath, out_port, pkt)

    def _handle_udp(self, dpid, datapath, pkt_ethernet, pkt_udp, pkt):
        # counter-clockwise
        # port 2 is clockwise, port 3 is counter-clockwise
        src = pkt_ethernet.src
        dst = pkt_ethernet.dst
        parser = datapath.ofproto_parser
        # blocking rule - UDP from H1 or H4
        if src in self.udp_blacklist:
            # blocking rule should have higher priority
            match = parser.OFPMatch(eth_type=0x0800,
                                    ip_proto=17,
                                    eth_src=src)
            actions = []
            self.add_flow(datapath, 100, match, actions)
            return
        # normal case
        out_port = self._get_out_port(dpid, src, dst, False)
        match = parser.OFPMatch(eth_type=0x0800,
                                ip_proto=17,
                                eth_src=src,
                                eth_dst=dst,
                                tcp_dst=pkt_udp.dst_port)
        actions = [parser.OFPActionOutput(port=out_port)]
        self.add_flow(datapath, 1, match, actions)
        self._send_packet(datapath, out_port, pkt)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
