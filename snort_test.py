# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

from __future__ import print_function

import array
import requests 

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import *
from ryu.lib import snortlib

from ryu.topology import api
from ryu.topology import event
import requests

import os
import random
import time


Switch_dict = {} 


class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 3
        self.mac_to_port = {}

        socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

        # for p in pkt.protocols:
        #     if hasattr(p, 'protocol_name') is False:
        #         break
        #     print('p: %s' % p.protocol_name)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        print("Alert received from container:" + str(ev.addr))
        msg = ev.msg
        #print(ev)
        #print(ev.addr)
        for sw in api.get_all_switch(self):
            switch_name = sw.dp.socket.getpeername()
            if switch_name[0] == ev.addr:
                switch_dpid = str(sw.dp.id)
            break
        switch_datapath = Switch_dict[switch_dpid]['object']
        pkt = msg.pkt
        pkt = packet.Packet(array.array('B', pkt))
        ip = pkt.get_protocol(ipv4.ipv4)
        srcip = ip.src
        dstip = ip.dst
        print(srcip, dstip)
        match3 = parser.OFPMatch(ipv4_src=srcip, ipv4_dst=dstip)
        match4 = parser.OFPMatch(ipv4_src=dstip, ipv4_dst=srcip)
        actions3 = []
        self.add_flow(switch_datapath, 1, match3, actions3)
        self.add_flow(switch_datapath, 1, match4, actions3)
        print("Rules added for container alert" + str(ev.addr))

        #print('alertmsg: %s' % ''.join(msg.alertmsg))

        #self.packet_print(msg.pkt)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        address = ev.msg.datapath.address
        dpid = str(ev.msg.datapath.id)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        Switch_dict[dpid] = {}
        Switch_dict[dpid]['addr'] = address[0]
        Switch_dict[dpid]['object'] = datapath

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        print("Flow rules added in datapath"+ str(datapath))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        if (src != 'ff:ff:ff:ff:ff:ff'):
            if src not in self.mac_to_port[dpid]:
                self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            out_port1 = self.snort_port
        else:
            out_port = ofproto.OFPP_FLOOD
            out_port1 = self.snort_port

        actions = [parser.OFPActionOutput(out_port)]
        actions1 = [parser.OFPActionOutput(out_port1)]

        # install a flow to avoid packet_in next time
        if (out_port != ofproto.OFPP_FLOOD) and (str(dst)[:5] != '33:33') :
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                
                
                
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port = in_port,  ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port = self.snort_port,  ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                
                    print("ICMP")
            
                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    src_port = t.src_port
                    dst_port = t.dst_port
                    match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port = in_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port)
                    match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port = self.snort_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port)
                    print("TCP")
            
                #  If UDP Protocol 
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    src_port = u.src_port
                    dst_port = u.dst_port
                    match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port = in_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port)           
                    match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port = self.snort_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port)
                    print("UDP")

            	# verify if we have a valid buffer_id, if yes avoid to send both
            	# flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER :
                    print("Adding flows with Buffer ID")
                    self.add_flow(datapath, 1, match1, actions1, msg.buffer_id)
                    self.add_flow(datapath, 1, match2, actions, msg.buffer_id)
                    return
                else :
                    print("Adding flows without buffer ID")
                    self.add_flow(datapath, 1, match1, actions1)
                    self.add_flow(datapath, 1, match2, actions)
        
                    switch_addr = datapath.address
                    print("calling container switch" + str(switch_addr[0]))
                    url = "http://127.0.0.1:5000/api/create"
                    params = {'host_ip':switch_addr[0], 'switch_id':"1234", 'protocol':"ICMP"}
                    r = requests.get(url=url,params=params)
                    print(r)
            else:
                if eth.ethertype == ether_types.ETH_TYPE_ARP :
                    print("ARP Packet")
                    arp_pkt = pkt.get_protocol(arp.arp)
                    if arp_pkt.opcode == arp.ARP_REQUEST :
                        print("ARP request")
                    else : 
                        print("ARP Reply")

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        print("Exiting packet in handler for datapath"+ str(datapath))
