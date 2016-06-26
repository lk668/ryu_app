#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct
import pika 
import json
import sys
import eventlet
import socket
import datetime 
import time
import threading
from multiprocessing import Process  

from ryu.ofproto import ofproto_common
from ryu.controller import controller

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib import hub


dp ={}                                            #存储datapath，添加流表时调用

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.data = []
        self.mark = True
        self.start_time = 0
        self.end_time = 0
        self.links = []
        self.num = 0
        self.end_test = False
        self.selectLink_thread = hub.spawn(self.run) 
        #self.child_proc = Process(target=self.run, args=())
        #self.child_proc.start()
    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def add_flow_test_delay(self, datapath, match, actions, priority=0x8000, buffer_id=None):#priority=ofproto.OFP_DEFAULT_PRIORITY
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     priority=priority, match=match, cookie=0,
                                    command=ofproto.OFPFC_ADD,idle_timeout=0, hard_timeout=0,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority = priority,
                                    match=match, cookie=0,command=ofproto.OFPFC_ADD,
                                    idle_timeout=0, hard_timeout=0,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def remove_table_flows(self, datapath, match, actions,priority = 0x7000):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority = priority,
                                    match=match, cookie=0,command=ofproto.OFPFC_DELETE_STRICT,
                                    idle_timeout=0, hard_timeout=0,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        return flow_mod

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        nw = pkt.get_protocol(ipv4.ipv4)
        tp = pkt.get_protocol(tcp.tcp)
        if nw is not None and dst == '75:43:21:13:15:17':
            self.end_time = time.time()
            #self.end_time = datetime.datetime.now().microsecond
            print self.end_time-self.start_time
            #self.links[self.num]['delay'] = str(round((self.end_time - self.start_time)*0.9*1000,3))+'ms'
            self.links[self.num]['delay'] = str(round((self.end_time - self.start_time)*0.9*1000,3))+'ms'
            print nw.src
            print nw.dst
            print datapath.id
            self.mark = True
            if(self.num == len(self.links) - 1):
                self.end_test = True
        else:
            dpid = datapath.id
            dp[dpid] = datapath                      #将datapath存储到dp中，key值为datapath.id
            self.mac_to_port.setdefault(dpid, {})
            #self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
            #print ', '.join(['%s:%s' % item for item in datapath.__dict__.items()])

            self.mac_to_port[dpid][src] = msg.in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, msg.in_port,out_port)
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, msg.in_port, dst, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)

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

    def callback(self, ch, method, properties, body):
        data = json.loads(body)           #将数据加载成字典
        #ofp_tcp_listen_port = int(data.get("id"))+6633  #虚拟租户网络的ID是否一致
        #if ofp_tcp_listen_port == controller.CONF.ofp_tcp_listen_port: #controller.CONF.ofp_tcp_listen_port为controller.py下加载的启动端的监听port
        pro = data.get('pro')
        if pro=="link":
            link_result = "Success: link_selection_status: "+"successful"
            try:
                change_flow(data)
            except:
                link_result = "Error: link_selection_status: "+"failed"
            ch.basic_publish(exchange='',
                            routing_key=properties.reply_to,
                            body= link_result)
            ch.basic_ack(delivery_tag = method.delivery_tag) 
        else :
            self.testing_delay(data)
            while(not self.end_test):
                time.sleep(0.1)
            self.end_test = False
            ch.basic_publish(exchange='',
                            routing_key=properties.reply_to,
                            body=json.dumps(self.links))
            ch.basic_ack(delivery_tag = method.delivery_tag)
        # print body
        # ch.basic_publish(exchange='',
        #                 routing_key=properties.reply_to,
        #                 body="sb")
        # ch.basic_ack(delivery_tag = method.delivery_tag)
            # conn.send(json.dumps(self.links))

    def run(self):                          #用于接收前端的发送数据
        time.sleep(10)
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='127.0.0.1'))
        channel = connection.channel()
        #channel.exchange_declare(exchange='ryu',type='fanout')
        channel.queue_declare(queue='ryu_')
        #channel.queue_bind(exchange='ryu',queue='ryu_change_flow')
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(self.callback,queue='ryu_')
        channel.start_consuming()  

    def testing_delay(self,data):
        print(data)
        self.links = data.get("links")
        for i in range(0,len(self.links)):
            self.num = i
            src = self.links[i].get("src")
            dst = self.links[i].get("dst")
            dp_src = int(src.get("dpid").replace(':',''),16)
            dp_dst = int(dst.get("dpid").replace(':',''),16)
            port_1 = int(src.get("port"))
            port_2 = int(dst.get("port"))
            self.adding_flow(dp_dst,port_2,"dst")
            self.adding_flow(dp_src,port_1,"src")
            tmp = 0;
            while(self.mark):
                time.sleep(0.1)
                tmp+=1
                if(tmp>10):
                    break;  
            self.mark = True
            self.deleting_flow(dp_dst,port_2,"dst")
            self.deleting_flow(dp_src,port_1,"src")

    def adding_flow(self,dpid,port,typ):
        datapath = dp[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if typ=="dst":
            actions = []
            #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            #match = parser.OFPMatch(in_port =port,nw_src=struct.unpack("!I", socket.inet_aton('10.0.0.1'))[0], nw_dst=struct.unpack("!I", socket.inet_aton('10.0.0.2'))[0])
            #match = parser.OFPMatch(in_port =2,nw_src=1,nw_dst=2)
            match = parser.OFPMatch(in_port =2,nw_src=1,nw_dst=2)
            self.add_flow_test_delay(datapath, match, actions, 0x7000)

        if typ=="src":
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
            match = parser.OFPMatch(in_port=port,nw_src=1, nw_dst=2)
            #match = parser.OFPMatch(in_port=ofproto.OFPP_CONTROLLER,nw_src=1, nw_dst=2)
            actions = [parser.OFPActionOutput(port)]
            self.add_flow_test_delay(datapath, match, actions,0x7000)
            self.start_time = time.time()
            #self.start_time = datetime.datetime.now().microsecond
            datapath.send_packet_out(in_port=port,buffer_id=ofproto.OFP_NO_BUFFER,
                                       actions=actions, data=pkt.data)

    def deleting_flow(self,dpid,port,typ):
        datapath = dp[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if typ=="dst":
            actions = []
            #match = parser.OFPMatch(in_port =port,nw_src=struct.unpack("!I", socket.inet_aton('10.0.0.1'))[0], nw_dst=struct.unpack("!I", socket.inet_aton('10.0.0.2'))[0])
            match = parser.OFPMatch(in_port =2,nw_src=1,nw_dst=2)
            flow_mod = self.remove_table_flows(datapath,match, actions)
            datapath.send_msg(flow_mod)

        if typ=="src":
            match = parser.OFPMatch(in_port=port,nw_src=1, nw_dst=2)
            actions = [parser.OFPActionOutput(port)]
            flow_mod = self.remove_table_flows(datapath, match, actions)
            datapath.send_msg(flow_mod)

def change_flow(data):                     #修改流表的处理函数
    print(data)
    params =data.get("params")
    network = params.get("network")
    hosts = network.get("hosts")
    switches = network.get("switches")
    src_MAC = hosts[0].get("mac")
    dst_MAC = hosts[1].get("mac")
    for switch in switches:
        dpid_str = switch.get("dpid")
        dp_str=dpid_str.replace(':','')
        dpid=int(dp_str,16)
        in_port = switch.get("in_port")
        out_port = switch.get("out_port")
        datapath = dp[dpid] 
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        SimpleSwitch().add_flow(datapath, in_port, dst_MAC, actions)
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        SimpleSwitch().add_flow(datapath, out_port, src_MAC, actions)

           

