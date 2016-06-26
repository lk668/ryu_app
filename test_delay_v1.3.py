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
import datetime 


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.start_time = [0,0,0]
        self.end_time  = [0,0,0]

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
        pkt = packet.Packet()
    
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0800,
                                       dst='70:56:81:12:34:56',
                                       src='70:56:81:65:43:21'))
    
        pkt.add_protocol(ipv4.ipv4(dst='192.168.8.70',
                               src='192.168.8.50',
              	               proto=6))
     
        pkt.add_protocol(tcp.tcp(src_port=5566,
                             dst_port=8080,
                             seq=1234566))
        pkt.serialize()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        #out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
        #                          in_port=1, actions=actions, data=data) 
        # ??? pkt.data has 
        self.start_time[int(datapath.id)-1] = datetime.datetime.now().microsecond
        #print self.start_time[int(datapath.id)-1] 
        #datapath.send_msg(out)

        datapath.send_packet_out(buffer_id=ofproto.OFP_NO_BUFFER, in_port=1,
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
        dst = eth.dst
        src = eth.src
        nw = pkt.get_protocol(ipv4.ipv4)
        tp = pkt.get_protocol(tcp.tcp)
        if nw is not None and nw.src == '192.168.8.50':
            print ("####")
            self.end_time[int(datapath.id)-1] = datetime.datetime.now().microsecond
            #print int(datapath.id)
            #print self.start_time[int(datapath.id)-1]
            #print self.end_time[int(datapath.id)-1]
            #print datetime.datetime.now().microsecond
            if int(datapath.id) == 1:
                pkt = packet.Packet()
    
                pkt.add_protocol(ethernet.ethernet(ethertype=0x0800,
                                           dst='70:56:81:12:34:56',
                                           src='70:56:81:65:43:21'))
    
                pkt.add_protocol(ipv4.ipv4(dst='192.168.8.70',
                                           src='192.168.8.51',
              	                           proto=6))
     
                pkt.add_protocol(tcp.tcp(src_port=5566,
                                         dst_port=8080,
                                         seq=1234566))
                pkt.serialize()
                actions = [parser.OFPActionOutput(2)]
        
                self.start_time[2] = datetime.datetime.now().microsecond

                datapath.send_packet_out(buffer_id=ofproto.OFP_NO_BUFFER, in_port=1,
                                         actions=actions, data=pkt.data)
        elif nw is not None and nw.src == '192.168.8.51':
            print ("####")
            self.end_time[2] = datetime.datetime.now().microsecond
            print ("switch1---->switch2")
            #print self.end_time[2]-self.start_time[2]
            print self.start_time[0]
            print self.end_time[0]
            print self.start_time[1]
            print self.end_time[1]
            print self.start_time[2]
            print self.end_time[2]
            print self.end_time[2]-self.start_time[2]-(self.end_time[0]-self.start_time[0]+self.end_time[1]-self.start_time[1])/2
                
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
