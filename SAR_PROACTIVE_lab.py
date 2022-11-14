# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches
import copy
import networkx as nx
import time
import json
import logging
import struct
import threading
from threading import Thread
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath
import ryu.app.ofctl.api as api

# number of ports for each switch, 2 for neighboring switches and 1 for the host
NUMBER_OF_SWITCH_PORTS = 3


class ZodiacSwitch(app_manager.RyuApp):
    # defines the version of the openflow protocol
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    # switch and link status monitoring function every time interval t
    def check_status(self):

        try:
            # switches_new_obj = get_switch(self.topology_api_app, None)
            links_new_obj = get_link(self.topology_api_app, None)
            s2 = []
            # switches_new = [switch.dp.id for switch in switches_new_obj]
            links_new = [(link.src.dpid, link.dst.dpid, {'from_port': link.src.port_no}, {'to_port': link.dst.port_no})
                         for
                         link in links_new_obj]
            self.logger.error("\n\n\nNr of links ryu / our -- number of switches: %d %d %d", len(links_new), len(self.links), len(self.switches))
            for l in links_new:
                # if l[0] not in s2:
                #   s2.append(l[0])
                if l[1] not in s2:
                    s2.append(l[1])
            # self.logger.error("switches: %s", s2)
            for x in self.switches:
                y = x.id
                # self.logger.info("y: %d",y)
                if y not in s2:
                    self.logger.info("switch %d morto", y)
                    #self.switches.remove(x)

            # self.logger.error("switches: %s", self.switches)
            for link_o in self.links_old:
                if link_o not in links_new:
                    self.logger.error("A link is broken!: %s", link_o)
                    try:
                        if link_o[0] in s2 and link_o[1] in s2:
                            # self.link_del_handler(link_o)
                            process = Thread(target=self.link_del_handler, args=[link_o])
                            process.start()
                        elif link_o[0] in s2:
                            # self.link_del_handler(link_o)
                            process = Thread(target=self.link_del_handler, args=[link_o])
                            process.start()
                        #else:
                         #   self.switches.remove(link_o[1])
                        # elif link_o[1] in s2:
                        #   pass
                        elif link_o[0] not in s2 and link_o[1] not in s2:
                            links2 = [(link_o[0], link_o[1], {'port': link_o[2]['from_port']})]
                            links3 = [(link_o[1], link_o[0], {'port': link_o[3]['to_port']})]
                            if links2[0] in self.links:
                                self.links.remove(links2[0])
                            if links3[0] in self.links:
                                self.links.remove(links3[0])
                            for s in self.switches:
                                if s.id is link_o[0]:
                                    self.switches.remove(s)
                                if s.id is link_o[1]:
                                    self.switches.remove(s)

                    except:
                        self.logger.error("exception: link was already removed")
            for link_o in links_new:
		#self.logger.error(link_o)
		try:
			if link_o not in self.links_old:
			    #self.logger.error(link_o)
			    self.logger.error("Trying to restore shortest path")
			    dpid_src = link.src.dpid
			    dpid_dst = link.dst.dpid
			    if dpid_src is not None and dpid_dst is not None:
				try:
					reply = self.get_flows(get_datapath(self, dpid_src), -1)[0]
				except:
					return
			    #else:
			     #   if dpid_src is None:
			      #      reply = self.get_flows(get_datapath(self, dpid_dst), -1)[0]
			       # if dpid_dst is None:
				#    reply = self.get_flows(get_datapath(self, dpid_src), -1)[0]
			    # self.logger.error(reply.body)
			    for flow in reply.body:
				try:
				    ipv4_src = (flow.match.get('ipv4_src'))
				    ipv4_dst = (flow.match.get('ipv4_dst'))
				    mac_ipv4_src = self.ip_to_mac[ipv4_src]
				    mac_ipv4_dst = self.ip_to_mac[ipv4_dst]
				    dpid_ipv4_src = self.mac_to_dpid[mac_ipv4_src]
				    dpid_ipv4_dst = self.mac_to_dpid[mac_ipv4_dst]
				    dp = get_datapath(self, dpid=dpid_ipv4_src)
				    #for s in self.switches:
					#if s.id is dpid_ipv4_src:
					#	dp = s
				    path = nx.shortest_path(self.net, dpid_ipv4_src, dpid_ipv4_dst)
				    path_all = nx.all_simple_paths(self.net, dpid_ipv4_src, dpid_ipv4_dst)
				    #self.logger.error("w path %s %d", path, dp.id)
				    #process = Thread(target=self.path_installr, args=[path, dp,
				      #                   dp.ofproto_parser,
				      #                  ipv4_dst, ipv4_src, None, dpid_ipv4_src, mac_ipv4_src,
				      #                  dpid_ipv4_dst, mac_ipv4_dst, 2, 2])
				    #process.start()
				    self.path_installer(path, dp,
				                        dp.ofproto_parser,
				                        ipv4_dst, ipv4_src, None, dpid_ipv4_src, mac_ipv4_src,
				                        dpid_ipv4_dst, mac_ipv4_dst, 2, 2)
				    path_all = nx.all_simple_paths(self.net, dpid_src, dpid_dst)
				    #self.logger.error(" --- Shortest path: %s", path)
				    path_backup = list(path_all)
				    if path in path_backup:
				        path_backup.remove(list(path))
				    if len(path_backup) is not 0:
				        #self.logger.error(" --- Alternative path: %s", path_backup)
					self.path_installer(path_backup[0], dp,
				                        dp.ofproto_parser,
				                        ipv4_dst, ipv4_src, None, dpid_ipv4_src, mac_ipv4_src,
				                        dpid_ipv4_dst, mac_ipv4_dst, 1, 1)	
				except Exception as b:
					pass	
		except Exception as e:
			pass
            self.links_old = copy.deepcopy(links_new)
            #self.switches_old = copy.deepcopy(self.switches)
        # Simple timer that uses callback methods and is served by thread pool threads.
        # It invokes the function itself every second.
        except:
            pass
            #self.logger.error("check_status crashed")
        timer = threading.Timer(self.time_interval, self.check_status)
        # start timer for monitoring links and switches status
        timer.start()

    # variable initialization function and monitoring start
    def __init__(self, *args, **kwargs):
        super(ZodiacSwitch, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.mac_to_port = {}
        self.mac_to_dpid = {}
        self.port_to_mac = {}
        self.ip_to_mac = {}
        self.port_occupied = {}
        self.GLOBAL_VARIABLE = 0
        self.stop = 0
        self.links_old = []
        self.switches_old = {}
        self.switches = []
        self.time_interval = 1
        self.RESTORING_SHORTEST_PATH = 1
        self.BUFFER_ID_ = 0
        self.MOBILITY = 1
        # initializing the status variable with the thread timer
        status = threading.Timer(5.0, self.check_status)
        # start timer for monitoring links and switches status
        status.start()

    # Individual flow request message with datapath value and output port number
    def ofdpa_table_stats_request(self, datapath, port_no):
        # variable initialization for datapath
        parser = datapath.ofproto_parser
        # The controller returns, via an openflow status request, the datapath
        # and the corresponding output port number
        if port_no is not -1:
            return parser.OFPFlowStatsRequest(datapath, out_port=port_no)
        else:
            return parser.OFPFlowStatsRequest(datapath)

    # Flow table request with datapath value and output port number
    def get_flows(self, datapath, port_no):
        # The controller uses this message to query flow table.
        if port_no is -1:
            msg = (self.ofdpa_table_stats_request(datapath, -1))
        else:
            msg = (self.ofdpa_table_stats_request(datapath, port_no))
        return api.send_msg(self, msg, reply_cls=datapath.ofproto_parser.OFPFlowStatsReply, reply_multi=True)

    # Features reply message. The parameter CONFIG_DISPATCHER negotiates version
    # and sents features-request message.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # The switch responds with a features reply message to a features request.
    def switch_features_handler(self, ev):
        # This message is handled by the Ryu framework, so the Ryu application do not need to process this typically.
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
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions, buffer_id=None)

    # The controller sends the message, contained in the mod variable, to
    # add a new row in the flow table.
    def add_flow(self, datapath, cookie, priority, match, actions, buffer_id):
        idle_timeout = 300
        hard_timeout = 600
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # This instruction writes/applies/clears the actions. We use it for applying an action.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        # The controller sends this message to modify the flow table. Buffered packet to apply to,
        # it is possible have the option without buffer_id.
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, buffer_id=buffer_id,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        msg = parser.OFPBarrierRequest(datapath)
        api.send_msg(self, msg, reply_cls=datapath.ofproto_parser.OFPBarrierReply, reply_multi=True)

    # The controller notifies to the switches, with the message contained in flow_mod,
    # the deletion of a row in the flow table
    def del_flow(self, datapath, ipv4_dst, ipv4_src, cookie):
        table_id = 0
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        cookie = cookie
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
        instructions = []
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, cookie, 0xFFFFFFFFFFFFFFFF, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      match, instructions)
        datapath.send_msg(flow_mod)

    # Send_arp sends all messages to the controller, in fact we never have a direct message exchange
    # between switches. This type of exchange is used as we are working with a centralized network.
    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        # If it is an ARP request
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        # If it is an ARP reply
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    # The switch reacts to the arrival of the packet and sends the packet that received to the
    # controller by this message.
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
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        # if self.simulation_flag == 1 and (dst == "255.255.255.255" or dst == "0.0.0.0" or src == "0.0.0.0"):
        #   return
        dpid_src = datapath.id
        #		self.logger.error(ev.msg)
        # TOPOLOGY DISCOVERY------------------------------------------

        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]

        # MAC LEARNING-------------------------------------------------

        self.mac_to_port.setdefault(dpid_src, {})
        self.port_to_mac.setdefault(dpid_src, {})
        self.mac_to_port[dpid_src][src] = in_port
        #if src not in self.mac_to_dpid:
        self.mac_to_dpid[src] = dpid_src
        self.port_to_mac[dpid_src][in_port] = src

        # HANDLE ARP PACKETS--------------------------------------------

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_packet = pkt.get_protocol(arp.arp)
            arp_dst_ip = arp_packet.dst_ip
            arp_src_ip = arp_packet.src_ip
            # self.logger.info("It is an ARP packet")
            # If it is an ARP request
            if arp_packet.opcode == 1:
                # self.logger.info("It is an ARP request")
                if arp_dst_ip in self.ip_to_mac:
                    # self.logger.info("The address is inside the IP TO MAC table")
                    srcIp = arp_dst_ip
                    dstIp = arp_src_ip
                    srcMac = self.ip_to_mac[arp_dst_ip]
                    dstMac = src
                    outPort = in_port
                    opcode = 2
                    self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
                # self.logger.info("packet in %s %s %s %s", srcMac, srcIp, dstMac, dstIp)
                else:
                    # self.logger.info("The address is NOT inside the IP TO MAC table")
                    srcIp = arp_src_ip
                    dstIp = arp_dst_ip
                    srcMac = src
                    dstMac = dst
                    # learn the new IP address
                    self.ip_to_mac.setdefault(srcIp, {})
                    self.ip_to_mac[srcIp] = srcMac
                    # Send and ARP request to all the switches
                    opcode = 1
                    for id_switch in switches:
                        # if id_switch != dpid_src:
                        datapath_dst = get_datapath(self, id_switch)
                        for po in range(1, len(self.port_occupied[id_switch]) + 1):
                            if self.port_occupied[id_switch][po] == 0:
                                outPort = po
                                if id_switch == dpid_src:
                                    if outPort != in_port:
                                        self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
                                else:
                                    self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)

            else:
                srcIp = arp_src_ip
                dstIp = arp_dst_ip
                srcMac = src
                dstMac = dst
                if arp_dst_ip in self.ip_to_mac:
                    # learn the new IP address
                    self.ip_to_mac.setdefault(srcIp, {})
                    self.ip_to_mac[srcIp] = srcMac
                # Send and ARP reply to the switch
                opcode = 2
                outPort = self.mac_to_port[self.mac_to_dpid[dstMac]][dstMac]
                datapath_dst = get_datapath(self, self.mac_to_dpid[dstMac])
                self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)

        # HANDLE IP PACKETS-----------------------------------------------

        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip4_pkt:
            src_ip = ip4_pkt.src
            dst_ip = ip4_pkt.dst
            src_MAC = src
            dst_MAC = dst
            proto = str(ip4_pkt.proto)
            sport = "0"
            dport = "0"
            if proto == "6":
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                sport = str(tcp_pkt.src_port)
                dport = str(tcp_pkt.dst_port)

            if proto == "17":
                udp_pkt = pkt.get_protocol(udp.udp)
                sport = str(udp_pkt.src_port)
                dport = str(udp_pkt.dst_port)

            self.logger.info("Packet in switch: %s, source IP: %s, destination IP: %s, From the port: %s", dpid_src,
                             src_ip, dst_ip, in_port)
            # self.logger.info("Packet in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src, dst, in_port)

            try:
                datapath_dst = get_datapath(self, self.mac_to_dpid[dst_MAC])
                dpid_dst = datapath_dst.id
                self.logger.info(" --- Destination present on switch: %s", dpid_dst)
                self.stop = 0
            except:
                if not self.MOBILITY:
                    print(dst_MAC, ":Destination MAC not present.")
                    self.stop = 1
                ########mobility
                if self.MOBILITY:
                    print(dst_MAC,
                          ":Destination MAC not present. Let's send an ARP request fo find it (it has probably moved")
                    self.ip_to_mac.setdefault(src_ip, {})
                    self.ip_to_mac[src_ip] = src
                    # Send and ARP request to all the switches
                    opcode = 1
                    for id_switch in switches:
                        # if id_switch != dpid_src:
                        datapath_dst = get_datapath(self, id_switch)
                        for po in range(1, len(self.port_occupied[id_switch]) + 1):
                            if self.port_occupied[id_switch][po] == 0:
                                outPort = po
                                if id_switch == dpid_src:
                                    if outPort != in_port:
                                        self.send_arp(datapath_dst, opcode, src, src_ip, dst, dst_ip, outPort)
                                else:
                                    self.send_arp(datapath_dst, opcode, src, src_ip, dst, dst_ip, outPort)
                    if self.mac_to_dpid.has_key(dst):
                        dpid_dst = get_datapath(self, self.mac_to_dpid[dst]).id
                        self.stop = 0
                    else:
                        self.stop = 1
            ########mobility

            if self.stop == 0:
                # Shortest path computation
                try:
                    path = nx.shortest_path(self.net, dpid_src, dpid_dst)
		    self.path_installer(path, datapath, parser, dst_ip, src_ip, msg,
                                        dpid_src, src, dpid_dst, dst, 2, 2)
                    #path_all = nx.all_simple_paths(self.net, dpid_src, dpid_dst)
                    #self.logger.error(" --- Shortest path: %s", path)
                    #path_backup = list(path_all)
                    #if path in path_backup:
                     #   path_backup.remove(list(path))
                    #if len(path_backup) is not 0:
                     #   self.logger.error(" --- Alternative path: %s", path_backup)
                        
                except:
                    self.logger.info("Error in calculating path")
		try:
                    path = nx.shortest_path(self.net, dpid_src, dpid_dst)
                    path_all = nx.all_simple_paths(self.net, dpid_src, dpid_dst)
                    #self.logger.error(" --- Shortest path: %s", path)
                    path_backup = list(path_all)
                    if path in path_backup:
                        path_backup.remove(list(path))
                    if len(path_backup) is not 0:
                        self.logger.error(" --- Alternative path: %s", path_backup)
			self.path_installer(path_backup[0], datapath, parser, dst_ip, src_ip, None,
                                        dpid_src, src, dpid_dst, dst, 1, 1)		
		except:
		    pass

    def path_installer(self, path, datapath, parser, dst_ip, src_ip, msg, dpid_src, src, dpid_dst, dst, priority,
                       cookie):

        # Set the flows for different cases
        # If the path length is equal to 1, we  only install forwarding on
        # neighboring switches
        if msg is not None:
            buffer_id = msg.buffer_id
        else:
            buffer_id = None
        if len(path) == 1:
            In_Port = self.mac_to_port[dpid_src][src]
            Out_Port = self.mac_to_port[dpid_dst][dst]
            actions_1 = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
            actions_2 = [datapath.ofproto_parser.OFPActionOutput(In_Port)]
            match_1 = parser.OFPMatch(in_port=In_Port, eth_type=0x0800, ipv4_dst=dst_ip, ipv4_src=src_ip)
            match_2 = parser.OFPMatch(in_port=Out_Port, eth_type=0x0800, ipv4_dst=src_ip, ipv4_src=dst_ip)
            try:
                self.add_flow(datapath, priority, cookie, match_2, actions_2, buffer_id=None)
                self.add_flow(datapath, priority, cookie, match_1, actions_1, buffer_id=buffer_id)
            except:
                self.logger.error("impossible to install the rule")
        # If the path length is greater than 1, we instal different forwarding rules on switches
        elif len(path) >= 2:
            datapath_src = get_datapath(self, path[0])
            datapath_dst = get_datapath(self, path[len(path) - 1])
            dpid_src = datapath_src.id
            dpid_dst = datapath_dst.id
            In_Port_src = self.mac_to_port[dpid_src][src]
            In_Port_dst = self.mac_to_port[dpid_dst][dst]
            Out_Port_src = self.net[path[0]][path[1]]['port']
            Out_Port_dst = self.net[path[len(path) - 1]][path[len(path) - 2]]['port']

            if len(path) > 2:
                for i in range(1, len(path) - 1):
                    #self.logger.info("Install the flow on switch %s", path[i])
                    In_Port_temp = self.net[path[i]][path[i - 1]]['port']
                    Out_Port_temp = self.net[path[i]][path[i + 1]]['port']
                    dp = get_datapath(self, path[i])
                    actions_1 = [dp.ofproto_parser.OFPActionOutput(Out_Port_temp)]
                    actions_2 = [dp.ofproto_parser.OFPActionOutput(In_Port_temp)]
                    match_1 = parser.OFPMatch(in_port=In_Port_temp, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
                    match_2 = parser.OFPMatch(in_port=Out_Port_temp, eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
                    try:
                        self.add_flow(dp, priority, cookie, match_1, actions_1, buffer_id=None)
                        self.add_flow(dp, priority, cookie, match_2, actions_2, buffer_id=None)
                    except:
                        self.logger.error("impossible to install the rule")
            try:
                actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(Out_Port_dst)]
                match_1_dst = parser.OFPMatch(in_port=In_Port_dst, eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
                self.add_flow(datapath_dst, priority, cookie, match_1_dst, actions_1_dst, buffer_id=None)

                actions_2_dst = [datapath.ofproto_parser.OFPActionOutput(In_Port_dst)]
                match_2_dst = parser.OFPMatch(in_port=Out_Port_dst, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
                self.add_flow(datapath_dst, priority, cookie, match_2_dst, actions_2_dst, buffer_id=None)
                #self.logger.info("Install the flow on switch %s", path[len(path) - 1])
            except:
                self.logger.error("impossible to install the rule")

            try:
                actions_2_src = [datapath.ofproto_parser.OFPActionOutput(In_Port_src)]
                match_2_src = parser.OFPMatch(in_port=Out_Port_src, eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
                self.add_flow(datapath_src, priority, cookie, match_2_src, actions_2_src, buffer_id=None)
                actions_1_src = [datapath.ofproto_parser.OFPActionOutput(Out_Port_src)]
                match_1_src = parser.OFPMatch(in_port=In_Port_src, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
                self.add_flow(datapath_src, priority, cookie, match_1_src, actions_1_src, buffer_id=buffer_id)
                #self.logger.info("Install the flow on switch %s", path[0])
            except:
                self.logger.error("impossible to install the rule")

    # The event EventSwitchEnter will trigger the activation of get_topology_data.
    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    # @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    # Function returns the network topology each time a packet arrives at the switch
    def get_topology_data(self, ev):
        self.logger.error("get_topology_data inizio")
        self.switches.append(ev.switch.dp)
        self.net.add_nodes_from(self.switches)
        # To get the list of objects Link, we also get the port from the source node that arrives at the
        # destination node, as that information will be necessary later during the forwarding step.
        links_list = get_link(self.topology_api_app, None)
        self.links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(self.links)
        # links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        # riga sopra inutile
        # self.logger.error("get_topology_data fine")
        for switch_port in range(1, NUMBER_OF_SWITCH_PORTS + 1):
            self.port_occupied.setdefault(ev.switch.dp.id, {})
            self.port_occupied[ev.switch.dp.id][switch_port] = 0

    # Function reacts and allows the deletion of a link
    # The parameter MAIN DISPATCHER permits to understand that the switch-features message is received
    # and sents the set-config message
    def link_del_handler(self, link):
        #self.logger.info("link : %s", link)
        dpid_src = get_datapath(self, dpid=link[0])
        dpid_dst = get_datapath(self, dpid=link[1])
        links2 = [(link[0], link[1], {'port': link[2]['from_port']})]
        links3 = [(link[1], link[0], {'port': link[3]['to_port']})]
        #self.logger.error(links2)
        #self.logger.error(links3)
        if links2[0] not in self.links and links3[0] not in self.links:
            self.logger.error("Link was already removed")
            if self.net.has_edge(link[0], link[1]): ###
                self.net.remove_edge(link[0], link[1]) ###
            return

        if dpid_src is not None and dpid_dst is not None:
            reply = self.get_flows(dpid_src, link[2]['from_port'])[0]
        else:
            if dpid_src is None:
                reply = self.get_flows(dpid_dst, link[3]['to_port'])[0]
                if link[0] in self.net.node:
                    #try:
                    self.net.remove_node(link[0])
                    #except:
                    #self.logger.error("error")
            if dpid_dst is None:
                reply = self.get_flows(dpid_src, link[2]['from_port'])[0]
                if link[1] in self.net.node:
                    #try:
                    self.net.remove_node(link[1])
                    #except:
                    #    self.logger.error("error")

        #self.logger.error(self.net.node)
        #switch_list = get_switch(self.topology_api_app, None)
        switches = [switch for switch in self.switches]
        if self.net.has_edge(link[0], link[1]):
            try:
                self.net.remove_edge(link[0], link[1])
            except:
                self.logger.error("error")
        if links2[0] in self.links:
            self.links.remove(links2[0])
        #if links3[0] in self.links:
         #   self.links.remove(links3[0])
        links_ = [(link[0], link[1], link[2]['from_port'])]
        self.logger.error(links_)
        for l in links_:
            if l[0] in self.port_occupied:
                self.port_occupied[l[0]][l[2]] = 0
        # if dpid_src is None and link[0] in self.port_occupied:
        #   self.port_occupied.pop(link[0])
        # threads = []
        for flow in reply.body:
            ipv4_src = (flow.match.get('ipv4_src'))
            ipv4_dst = (flow.match.get('ipv4_dst'))
	    out_port = flow.instructions[0].actions[0].port
            cookie = flow.cookie
            if ipv4_src is not None and ipv4_dst is not None and out_port is link[2]['from_port']:

                self.logger.error("Deleting flows with src %s - dst %s and cookie %d", ipv4_src, ipv4_dst, cookie)
                for datapath in switches:
                    if datapath.id == dpid_dst:
                        #self.logger.error("dpid uguale: %d", datapath.id)
                        # This is the destination datapath to which we don't send the commans since it may be dead
                        continue
                    try:
                        self.del_flow(datapath, ipv4_dst, ipv4_src, cookie)
                    except:
                        self.logger.error("Impossibile to delete the rule")
                # 	process.start()
                # 	threads.append(process)
                # for process in threads:
                # 	process.join()

        s2 = []
        links_new_obj = get_link(self.topology_api_app, None)

        links_new = [(link.src.dpid, link.dst.dpid, {'from_port': link.src.port_no}, {'to_port': link.dst.port_no})
                     for link in links_new_obj]
        # self.logger.error(links_new)
        for l in links_new:
            # if l[0] not in s2:
            #  s2.append(l[0])
            if l[1] not in s2:
                s2.append(l[1])
        for x in self.switches:
            y = x.id
            # self.logger.info("y: %d",y)
            if y not in s2:
                self.logger.info("switch %d morto", y)
                self.switches.remove(x)

    # Function reacts and allows to add a link

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        link = ev.link
        self.logger.error("Link added %s", link)
        #self.net.add_edge(get_datapath(self, dpid=link.src.dpid).id, get_datapath(self, dpid=link.dst.dpid).id)
	#self.net.add_edge(get_datapath(self, dpid=link.dst.dpid).id, get_datapath(self, dpid=link.src.dpid).id)
        links = [(get_datapath(self, dpid=link.src.dpid).id, get_datapath(self, dpid=link.dst.dpid).id,
                  {'port': link.src.port_no})]
        self.net.add_edges_from(links)
        links_ = [(link.src.dpid, link.dst.dpid, link.src.port_no)]
        # self.logger.error(links_)
        for l in links_:
            #        if l[0] in self.port_occupied:
            self.port_occupied[l[0]][l[2]] = 1
        # adds the link to the link status list
        links2 = [(ev.link.src.dpid, ev.link.dst.dpid, {'port': ev.link.src.port_no})]
        links3 = [(ev.link.dst.dpid, ev.link.src.dpid, {'port': ev.link.dst.port_no})]
        if (links2[0] not in self.links):
            self.links.append(links2[0])
        #if (links3[0] not in self.links):
         #   self.links.append(links3[0])



app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')
