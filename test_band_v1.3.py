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

from ryu import utils
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
import struct
import socket
import datetime 
import time


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.start_time = [0,0,0]
        self.end_time  = [0,0,0]
        self.re_time = [0,0]
        self.re_time_u = [0,0]
        self.count = 0
        self.dp_add = 0
        self.data = []
        self.cc = 0

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
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        if int(datapath.id) == 2:
            match = parser.OFPMatch(eth_type=0x0800,ipv4_src='0.0.0.1', ipv4_dst='0.0.0.2')
            actions = [parser.OFPActionSetField(ipv4_src='0.0.0.0'),
                       parser.OFPActionSetField(ipv4_dst='0.0.0.0'),
                       parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 1, match, actions)
		
        if int(datapath.id) == 1 :
            self.dp_add = datapath
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=0x0800,
                                       dst='75:43:21:13:15:17',
                                       src='75:43:12:31:51:71'))
    
            pkt.add_protocol(ipv4.ipv4(dst='0.0.0.2',
                               src='0.0.0.1',
              	               ttl=254,proto=6))
     
            pkt.add_protocol(tcp.tcp(src_port=1234,
                             dst_port=5001,
                             seq=1234566))
            pkt.add_protocol('j'*1380)
            pkt.serialize()
            actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
            match = parser.OFPMatch(eth_type=0x0800,ipv4_src='0.0.0.1', ipv4_dst='0.0.0.2')
            actions = [parser.OFPActionOutput(2),
                       parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match, actions)
            #self.start_time[int(datapath.id)-1] = datetime.datetime.now().microsecond

            datapath.send_packet_out(buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                     actions=actions, data=pkt.data)

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
        #if ev.msg.msg_len < ev.msg.total_len:
        #    self.logger.debug("packet truncated: only %s of %s bytes",
        #                      ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        nw = pkt.get_protocol(ipv4.ipv4)
        tp = pkt.get_protocol(tcp.tcp)
        if nw is not None and dst == '75:43:21:13:15:17':
            print nw.src
            print nw.dst
            self.re_time[self.count] = struct.unpack("I",socket.inet_aton(str(nw.src)))[0]
            self.re_time_u[self.count] = struct.unpack("I",socket.inet_aton(str(nw.dst)))[0]
            
            self.count = self.count + 1
            if self.count == 2 :
                self.count = 0
                
                result = self.re_time[1] - self.re_time[0]
                result = result * 1000000 + self.re_time_u[1] - self.re_time_u[0]
                print 11472.0/result
                #file_object = open('file.txt', 'a')
                #file_object.write(str(11472.0/result))
                #file_object.write("\n")
                if result :
                    self.data.append(11472.0/result)
                    self.cc =self.cc + 1
                    if self.cc == 100:
                        for i in range(20):
                            x = max(self.data)
                            y = min(self.data)
                            self.data.remove(x)
                            self.data.remove(y)
                        print sum(self.data)/60
                        print sum(self.data)
                        file_object = open('file.txt', 'a')
                        file_object.write(str(sum(self.data)/60))
                        file_object.write("\n")
                    else:
                        pkt = packet.Packet()
                        pkt.add_protocol(ethernet.ethernet(ethertype=0x0800,
                                                  dst='75:43:21:13:15:17',
                                                  src='75:43:12:31:51:71'))
            
                        pkt.add_protocol(ipv4.ipv4(dst='0.0.0.2',
                                              src='0.0.0.1',
                      	                      ttl=254,proto=6))
             
                        pkt.add_protocol(tcp.tcp(src_port=1234,
                                         dst_port=5001,
                                         seq=1234566))
                        pkt.add_protocol('j'*1380)
                        pkt.serialize()
                        actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
                        match = parser.OFPMatch(eth_type=0x0800,ipv4_src='0.0.0.1', ipv4_dst='0.0.0.2')
                        actions = [parser.OFPActionOutput(2),
                                   parser.OFPActionOutput(2)]
                        self.dp_add.send_packet_out(buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                                    actions=actions, data=pkt.data)

        else:

            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
        

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
