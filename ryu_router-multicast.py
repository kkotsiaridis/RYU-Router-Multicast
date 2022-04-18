#Kotsiaridis Konstantinos 2547
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import igmp
from ryu.lib.packet import ether_types



class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.multicast_table2_g1 = {}
        self.multicast_table2_g2 = {}
        self.multicast_table3_g1 = {}
        self.multicast_table3_g2 = {}
        self.multicast_mac_to_ip = {}
        

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.logger.info("Datapath ID is %s", hex(dpid))

        if dpid == 0x1A:
            actions1 = []
            actions1.append(parser.OFPActionSetDlSrc("00:00:00:00:04:01"))
            actions1.append(parser.OFPActionSetDlDst("00:00:00:00:04:02"))
            match1 = parser.OFPMatch(dl_type = 0x0800,nw_tos = 8, nw_dst = "192.168.2.0",nw_dst_mask = 24)
            actions1.append(parser.OFPActionOutput(4))
            self.add_flow(datapath, match1, actions1)

            actions2 = []
            actions2.append(parser.OFPActionSetDlSrc("00:00:00:00:03:01"))
            actions2.append(parser.OFPActionSetDlDst("00:00:00:00:03:02"))
            match2 = parser.OFPMatch(in_port = 2, dl_type = 0x0800,nw_dst = "239.0.0.1")
            actions2.append(parser.OFPActionOutput(1))
            self.add_flow(datapath, match2, actions2)

            actions3 = []
            actions3.append(parser.OFPActionSetDlSrc("00:00:00:00:03:01"))
            actions3.append(parser.OFPActionSetDlDst("00:00:00:00:03:02"))
            match3 = parser.OFPMatch(in_port = 2, dl_type = 0x0800,nw_dst = "239.0.0.2")
            actions3.append(parser.OFPActionOutput(1))
            self.add_flow(datapath, match3, actions3)

            actions4 = []
            actions4.append(parser.OFPActionSetDlSrc("00:00:00:00:01:01"))
            actions4.append(parser.OFPActionSetDlDst("01:00:5e:00:00:01"))
            match4 = parser.OFPMatch(in_port = 1, dl_type = 0x0800,nw_dst = "239.0.0.1")
            actions4.append(parser.OFPActionOutput(2))
            self.add_flow(datapath, match4, actions4)

            actions5 = []
            actions5.append(parser.OFPActionSetDlSrc("00:00:00:00:01:01"))
            actions5.append(parser.OFPActionSetDlDst("01:00:5e:00:00:02"))
            match5 = parser.OFPMatch(in_port = 1, dl_type = 0x0800,nw_dst = "239.0.0.2")
            actions5.append(parser.OFPActionOutput(2))
            self.add_flow(datapath, match5, actions5)



        elif dpid == 0x1B:
            actions1 = []
            actions1.append(parser.OFPActionSetDlSrc("00:00:00:00:04:02"))
            actions1.append(parser.OFPActionSetDlDst("00:00:00:00:04:01"))
            match1 = parser.OFPMatch(dl_type = 0x0800,nw_tos = 8, nw_dst = "192.168.1.0",nw_dst_mask = 24)
            actions1.append(parser.OFPActionOutput(4))
            self.add_flow(datapath, match1, actions1)

            actions2 = []
            actions2.append(parser.OFPActionSetDlSrc("00:00:00:00:03:02"))
            actions2.append(parser.OFPActionSetDlDst("00:00:00:00:03:01"))
            match2 = parser.OFPMatch(in_port = 2, dl_type = 0x0800,nw_dst = "239.0.0.1")
            actions2.append(parser.OFPActionOutput(1))
            self.add_flow(datapath, match2, actions2)

            actions3 = []
            actions3.append(parser.OFPActionSetDlSrc("00:00:00:00:03:02"))
            actions3.append(parser.OFPActionSetDlDst("00:00:00:00:03:01"))
            match3 = parser.OFPMatch(in_port = 2, dl_type = 0x0800,nw_dst = "239.0.0.2")
            actions3.append(parser.OFPActionOutput(1))
            self.add_flow(datapath, match3, actions3)

            actions4 = []
            actions4.append(parser.OFPActionSetDlSrc("00:00:00:00:02:01"))
            actions4.append(parser.OFPActionSetDlDst("01:00:5e:00:00:01"))
            match4 = parser.OFPMatch(in_port = 1, dl_type = 0x0800,nw_dst = "239.0.0.1")
            actions4.append(parser.OFPActionOutput(2))
            self.add_flow(datapath, match4, actions4)

            actions5 = []
            actions5.append(parser.OFPActionSetDlSrc("00:00:00:00:02:01"))
            actions5.append(parser.OFPActionSetDlDst("01:00:5e:00:00:02"))
            match5 = parser.OFPMatch(in_port = 1, dl_type = 0x0800,nw_dst = "239.0.0.2")
            actions5.append(parser.OFPActionOutput(2))
            self.add_flow(datapath, match5, actions5)

        elif dpid == 0x2:
            self.multicast_table2_g1.setdefault(1, True)
            self.multicast_table2_g2.setdefault(1, True)

        elif dpid == 0x3:
            self.multicast_table3_g1.setdefault(1, True)
            self.multicast_table3_g2.setdefault(1, True)
            



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        if dpid == 0x2 or dpid == 0x3:
            self.mac_to_port.setdefault(dpid, {})

            if ethertype ==ether_types.ETH_TYPE_IP:
                pkt_ip = pkt.get_protocol(ipv4.ipv4)
                if pkt_ip.proto == 2:
                    pkt_igmp = pkt.get_protocol(igmp.igmp)
                    self._handle_igmp(pkt_igmp, msg, dpid)
                    return
                elif "01:00:5e:" in eth.dst:
                    self._handle_multicast(datapath,eth,msg,dpid)
                    return

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = msg.in_port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            match = datapath.ofproto_parser.OFPMatch(
                in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
             #install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
            return

        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt.opcode == arp.ARP_REQUEST:
                    #self.logger.info("packet-in: %s" % (pkt,))
                    self._handle_arp(datapath, msg.in_port , eth, arp_pkt)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                pkt_ip = pkt.get_protocol(ipv4.ipv4)
                #self.logger.info("packet-in-ip: %s" % (pkt_ip,))
                self._handle_ip(datapath,eth,pkt_ip,msg,dpid)
                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt.opcode == arp.ARP_REQUEST:
                    #self.logger.info("packet-in: %s" % (pkt,))
                    self._handle_arp(datapath, msg.in_port , eth, arp_pkt)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                pkt_ip = pkt.get_protocol(ipv4.ipv4)
                #self.logger.info("packet-in-ip: %s" % (pkt_ip,))
                self._handle_ip(datapath,eth,pkt_ip,msg,dpid)
                return
            return

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        pkt = packet.Packet()

        if pkt_arp.dst_ip == "192.168.1.1":
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                               dst=pkt_ethernet.src,
                                               src="00:00:00:00:01:01"))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                               src_mac="00:00:00:00:01:01",
                                               src_ip="192.168.1.1",
                                               dst_mac=pkt_arp.src_mac,
                                               dst_ip=pkt_arp.src_ip))                                 
        else:
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                               dst=pkt_ethernet.src,
                                               src="00:00:00:00:02:01"))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                               src_mac="00:00:00:00:02:01",
                                               src_ip="192.168.2.1",
                                               dst_mac=pkt_arp.src_mac,
                                               dst_ip=pkt_arp.src_ip))
        self._send_packet(datapath, port, pkt)

    def icmp_reply(self, datapath, port, pkt_ethernet, pkt_ip,msg):
        pkt = packet.Packet()
        if("192.168.1" in pkt_ip.src):
            pkt.add_protocol(ethernet.ethernet(ethertype= pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src="00:00:00:00:01:01"))
            pkt.add_protocol(ipv4.ipv4(dst=pkt_ip.src,
                                   src="192.168.1.1",
                                   proto=pkt_ip.proto))

        else:
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src="00:00:00:00:02:01"))
            pkt.add_protocol(ipv4.ipv4(dst=pkt_ip.src,
                                   src="192.168.2.1",
                                   proto=pkt_ip.proto))

        pkt.add_protocol(icmp.icmp(type_= 3,
                                   code= 1,
                                   csum=0,
                                   data= icmp.dest_unreach(data = msg.data[ethernet.ethernet._MIN_LEN:])))
        #self.logger.info("packet-out %s" % (pkt,))
        self._send_packet(datapath, port, pkt)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        
    def _handle_ip(self, datapath, pkt_eth, pkt_ip, msg,dpid):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []
        
        if ("192.168.2." in pkt_ip.dst) and (dpid == 0x1A):
            actions.append(parser.OFPActionSetDlSrc("00:00:00:00:03:01"))
            actions.append(parser.OFPActionSetDlDst("00:00:00:00:03:02"))
            match = parser.OFPMatch(dl_type = 0x0800, nw_tos = 0, nw_dst = "192.168.2.0", nw_dst_mask = 24)
            out_port = 1
            
        elif("192.168.2." in pkt_ip.dst) and (dpid == 0x1B):
            actions.append(parser.OFPActionSetDlSrc("00:00:00:00:02:01"))
            out_port = 2
            if pkt_ip.dst =="192.168.2.2":
                actions.append(parser.OFPActionSetDlDst("00:00:00:00:02:02"))
                match = parser.OFPMatch(dl_type = 0x0800, nw_dst = "192.168.2.2")
            else:
                actions.append(parser.OFPActionSetDlDst("00:00:00:00:02:03"))
                match = parser.OFPMatch( dl_type = 0x0800, nw_dst ="192.168.2.3")
                
        elif("192.168.1." in pkt_ip.dst) and (dpid == 0x1A):
           actions.append(parser.OFPActionSetDlSrc("00:00:00:00:01:01"))
           out_port = 2
           if pkt_ip.dst =="192.168.1.2":
               actions.append(parser.OFPActionSetDlDst("00:00:00:00:01:02"))
               match = parser.OFPMatch(dl_type = 0x0800, nw_dst ="192.168.1.2")  
           else:
               actions.append(parser.OFPActionSetDlDst("00:00:00:00:01:03"))
               match = parser.OFPMatch(dl_type = 0x0800, nw_dst ="192.168.1.3")
               
        elif("192.168.1." in pkt_ip.dst) and (dpid == 0x1B):
           actions.append(parser.OFPActionSetDlSrc("00:00:00:00:03:02"))
           actions.append(parser.OFPActionSetDlDst("00:00:00:00:03:01"))
           match = parser.OFPMatch(dl_type = 0x0800, nw_tos = 0, nw_dst = "192.168.1.0", nw_dst_mask = 24)
           out_port = 1

        else:
            self.icmp_reply(datapath, msg.in_port, pkt_eth, pkt_ip,msg)
            return

        actions.append(parser.OFPActionOutput(out_port))
            
        out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, 
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, data=msg.data)
        datapath.send_msg(out)
        self.add_flow(datapath, match, actions)

    def _handle_igmp(self,pkt_igmp, msg, dpid):

        multicast_mac = "01:00:5e:00:00:"
        last_point = pkt_igmp.records[0].address.rfind('.') + 1
        last_byte= int(pkt_igmp.records[0].address[last_point:])
        last_byte_hex = hex(last_byte)
        if(len(last_byte_hex)==3):
            add = "0"+last_byte_hex[2:]
        else:
            add = last_byte_hex[2:]
        multicast_mac = multicast_mac + add

        self.multicast_mac_to_ip.setdefault(multicast_mac,pkt_igmp.records[0].address)
    
        if pkt_igmp.msgtype == 34:
            if dpid == 0x2:
                if pkt_igmp.records[0].address == "239.0.0.1":
                    self.multicast_table2_g1.setdefault(msg.in_port,True)
                else:
                    self.multicast_table2_g2.setdefault(msg.in_port,True)

            elif dpid ==0x3:
                if pkt_igmp.records[0].address == "239.0.0.1":
                    self.multicast_table3_g1.setdefault(msg.in_port,True)
                else:
                    self.multicast_table3_g2.setdefault(msg.in_port,True)
               
    def _handle_multicast(self,datapath, pkt_eth, msg,dpid):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []

        multicast_ip = self.multicast_mac_to_ip.setdefault(pkt_eth.dst,{})
        if dpid == 0x2:
            if multicast_ip == "239.0.0.1":
                mtable = self.multicast_table2_g1
            else:
                mtable = self.multicast_table2_g2

        elif dpid == 0x3:
            if multicast_ip == "239.0.0.1":
                mtable = self.multicast_table3_g1
            else:
                mtable = self.multicast_table3_g2

        for port in mtable:
            if ((port != msg.in_port) and (mtable[port] == True)):
                actions.append(parser.OFPActionOutput(port))
            
        match = parser.OFPMatch(in_port = msg.in_port, dl_dst = pkt_eth.dst)

        out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, 
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, data=msg.data)
        datapath.send_msg(out)
        self.add_flow(datapath, match, actions)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
