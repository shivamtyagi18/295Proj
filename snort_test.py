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

#dictionary used to deploy OpenFlow rules for alerts
Switch_dict = {} 

#List to check if container deployed for the same traffic. 
deployed_list = []

class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.mac_to_port = {}

        socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()            #server to receive alerts from any container pigrelay


    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):                      #code to deploy Openflow rules based on Snort alerts

        print("Alert received from container:" + str(ev.addr))
        msg = ev.msg
        switch_datapath = Switch_dict.get(ev.addr)
        parser = switch_datapath.ofproto_parser
        ofproto = switch_datapath.ofproto
        
        #fetch packet details for match params to add OpenFlow rules
        
        pkt = msg.pkt
        pkt = packet.Packet(array.array('B', pkt))
        ip = pkt.get_protocol(ipv4.ipv4)
        srcip = ip.src
        dstip = ip.dst
        protocol = ip.proto
        print(srcip, dstip)
        
        #if different rules for different protocols. Allows traffic on specific port to be dropped based on protocol.  
        
        
        if protocol == in_proto.IPPROTO_ICMP:
            match3 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, ipv4_src=srcip, ipv4_dst=dstip)
            match4 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, ipv4_src=dstip, ipv4_dst=srcip)
            actions3 = []
            self.add_flow(switch_datapath, 1, match3, actions3)
            self.add_flow(switch_datapath, 1, match4, actions3)
            print("Rules deleted for container alert" + str(ev.addr))




    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        address = ev.msg.datapath.address
        dpid = str(ev.msg.datapath.id)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #append the switch address to Switch_dict
        Switch_dict[address[0]] = {}
        Switch_dict[address[0]] = datapath

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
        
        
        # call to deploy a container when a switch connects to the controller
        url = "http://127.0.0.1:5000/api/create"
        params = {'host_ip': address[0]}
        r = requests.get(url=url, params=params)


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        print("Flow rules added in "+ str(datapath.address[0]) + "  match:   " + str(match))
    
    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)
        print("Flow rules deleted for modification in " + str(datapath.address[0]) + "  match:  "+ str(match) )



    #Function to check if there's any container deployed for same kind of flow in a switch

    def checkDeployment(self, switch_addr, src_ip,dst_ip,src_port,dst_port,protocol):
        test1 = {"switch_addr": switch_addr, "src_ip": src_ip, "dst_ip":dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": protocol}
        for i in range(len(deployed_list)):
            if test1==deployed_list[i] :
                print("Rule addition in progress" + str(switch_addr))
                return True
        return False


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


        # learn a mac address to avoid FLOOD next time.
        if (src != 'ff:ff:ff:ff:ff:ff'):
            if src not in self.mac_to_port[dpid]:
                self.mac_to_port[dpid][src] = in_port


        #Generic flow rule addition if there's no container running in the switch for any protocol 
        
        if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
        else:
                out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        actions_return = [parser.OFPActionOutput(in_port)]

        switch_addr = datapath.address
        
        # install a flow to avoid packet_in next time
        # adding both to and fo rules at once to avoid repeat snort calls 
        if (out_port != ofproto.OFPP_FLOOD) and (str(dst)[:5] != '33:33'):

            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                print("Packet inside: " + str(srcip) +" "+ str(dstip) +" "+ str(protocol))
              
              
              # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    match_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=out_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    deployment = {"switch_addr": datapath.address[0], "src_ip": srcip, "dst_ip":dstip, "src_port": "0", "dst_port": "0", "protocol": protocol}
                    if self.checkDeployment(datapath.address[0],srcip,dstip,"0","0",protocol):
                        return 
                    params = {'host_ip': switch_addr[0], 'src_ip': srcip, 'dst_ip': dstip, 'protocol' : protocol, 'src_port' : "0", 'dst_port' : "0"}
             
             
             #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port, )
                    match_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=out_port, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, tcp_src=t.dst_port, tcp_dst=t.src_port, )
                    params = {'host_ip': switch_addr[0], 'src_ip': srcip, 'dst_ip': dstip, 'protocol': protocol, 'src_port': tcp_src, 'dst_port': tcp_dst}
                    deployment = {"switch_addr": datapath.address[0], "src_ip": srcip, "dst_ip":dstip, "src_port": tcp_src, "dst_port": tcp_dst, "protocol": protocol}
                    if self.checkDeployment(datapath.address[0], srcip,dstip,tcp_src,tcp_dst,protocol):
                        return 
            
            
            #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port, )
                    match_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=out_port, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, udp_src=u.dst_port, udp_dst=u.src_port, )
                    params = {'host_ip': switch_addr[0], 'src_ip': srcip, 'dst_ip': dstip, 'protocol': protocol, 'src_port': udp_src, 'dst_port': udp_dst}
                    deployment = {"switch_addr": datapath.address[0], "src_ip": srcip, "dst_ip":dstip, "src_port": udp_src, "dst_port": udp_dst, "protocol": protocol}
                    if self.checkDeployment(datapath.address[0], srcip,dstip,udp_src,udp_dst,protocol):
                        return


            #Call to orchestrator to start snort
                deployed_list.append(deployment)
                print("calling container switch" + str(switch_addr[0]))
                url = "http://127.0.0.1:5000/api/start"
                r = requests.get(url=url, params=params)
                print(r)

            
            #adding flow rule for arp packets
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=in_port, eth_dst=dst, eth_src=src)
                match_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=out_port, eth_dst=src, eth_src=dst)
                r = requests.Response()


            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, 1, match, actions)
                self.add_flow(datapath, 1, match_return, actions_return)

            #calculate the number of ports and create a snort_port
            ports = len(datapath.ports) - 1
            self.snort_port = ports

            #Check if Snort started by orchestrator and change flow rules accordingly
            #adding both to and fro flow rules from source to destination


            if ( (r.status_code is not None) and (r.status_code == 201) ) :
                # check IP Protocol and create a match for IP
                if eth.ethertype == ether_types.ETH_TYPE_IP:
                    ip = pkt.get_protocol(ipv4.ipv4)
                    srcip = ip.src
                    dstip = ip.dst
                    protocol = ip.proto

                    # if ICMP Protocol
                    if protocol == in_proto.IPPROTO_ICMP:
                        self.del_flow(datapath,match)
                        self.del_flow(datapath,match_return)
                        match0 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                        match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=self.snort_port, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                        match0_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=out_port, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol)
                        match1_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=self.snort_port, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol)

                    #  if TCP Protocol
                    elif protocol == in_proto.IPPROTO_TCP:
                        self.del_flow(datapath,match)
                        t = pkt.get_protocol(tcp.tcp)
                        src_port = t.src_port
                        dst_port = t.dst_port
                        match0 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=srcip,
                                                 ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port,
                                                 tcp_dst=t.dst_port)
                        match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=self.snort_port,
                                                 ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port,
                                                 tcp_dst=t.dst_port)
                        match0_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=out_port, ipv4_src=dstip,
                                                 ipv4_dst=srcip, ip_proto=protocol, tcp_src=t.dst_port,
                                                 tcp_dst=t.src_port)
                        match1_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=self.snort_port,
                                                 ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, tcp_src=t.dst_port,
                                                 tcp_dst=t.src_port)

                    #  If UDP Protocol
                    elif protocol == in_proto.IPPROTO_UDP:
                        self.del_flow(datapath,match)
                        u = pkt.get_protocol(udp.udp)
                        src_port = u.src_port
                        dst_port = u.dst_port
                        match0 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=srcip,
                                                 ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port,
                                                 udp_dst=u.dst_port)
                        match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=self.snort_port,
                                                 ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port,
                                                 udp_dst=u.dst_port)
                        match0_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=out_port, ipv4_src=dstip,
                                                 ipv4_dst=srcip, ip_proto=protocol, udp_src=u.dst_port,
                                                 udp_dst=u.src_port)
                        match1_return = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=self.snort_port,
                                                 ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, udp_src=u.dst_port,
                                                 udp_dst=u.src_port)

                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                        out_port1 = self.snort_port


                    actions = [parser.OFPActionOutput(out_port)]
                    actions1 = [parser.OFPActionOutput(out_port1)]

                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    self.add_flow(datapath, 0, match0, actions1)
                    self.add_flow(datapath, 0, match1, actions)
                    self.add_flow(datapath, 0, match0_return, actions1)
                    self.add_flow(datapath, 0, match1_return, actions_return)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

