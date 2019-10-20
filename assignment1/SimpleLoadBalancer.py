from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import json # addition to read configuration from file


class SimpleLoadBalancer(object):

    
    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None, 
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):
        
        # add the necessary openflow listeners
        core.openflow.addListeners(self) 

        # set class parameters
        # write your code here!!!
        self.lb_mac=lb_mac
        self.service_ip=service_ip
        self.server_ips=server_ips
        self.user_ip_to_group=user_ip_to_group
        self.server_ip_to_group=server_ip_to_group
        self.client_ip_to_mac_port={}
        self.server_ip_to_mac_port={}
        self.group_to_server_ip={}
        self.lb_mapping={}
        for x,y in self.server_ip_to_group.items():
            if y in self.group_to_server_ip:
                self.group_to_server_ip[y].append(x)
            else:
                #EDW PREPEI NA VALW ELIF AMA UPARXEI STOUS HOST H IP KAI NA VALW TO ELSE STO AMA DEN UPARXEI :P
                self.group_to_server_ip[y]=[x]
        pass


    # respond to switch connection up event
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        # write your code here!!!
        for server_ip in self.server_ips:
            self.send_proxied_arp_request(event.connection, server_ip)
        pass


    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip):
        # write your code here!!!
        self.lb_mapping[client_ip]=random.choice(self.group_to_server_ip[self.user_ip_to_group[client_ip]])
        self.lb_mapping[self.lb_mapping[client_ip]]=client_ip
        log.info("Update load balancer mapping, selected server %s for client %s and created flow rule" % (self.lb_mapping[client_ip], client_ip))
        pass
    

    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        # write your code here!!!
        if packet.next.protodst==IPAddr(self.service_ip):
            log.info("Received ARP request from client %s" % packet.src)
            self.client_ip_to_mac_port[packet.next.protosrc]={'mac':packet.src, 'port':outport}
            r=arp(opcode=2,hwsrc=EthAddr(self.lb_mac),hwdst=EthAddr(requested_mac),protosrc=IPAddr(self.service_ip),protodst=IPAddr(packet.next.protosrc))  
        else:
            log.info("Received ARP request from server %s" % packet.src)
            r=arp(opcode=2,hwsrc=EthAddr(self.lb_mac),hwdst=EthAddr(requested_mac),protosrc=packet.next.protodst,protodst=IPAddr(packet.next.protosrc))
        e=ethernet(type=ethernet.ARP_TYPE, src=EthAddr(self.lb_mac),dst=EthAddr(requested_mac))
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        connection.send(msg)
        pass


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
        # write your code here!!!
        r=arp(opcode=1, hwsrc=EthAddr(self.lb_mac),hwdst=EthAddr("FF:FF:FF:FF:FF:FF"),protosrc=IPAddr(self.service_ip),protodst=IPAddr(ip))   
        e=ethernet(type=ethernet.ARP_TYPE, src=EthAddr(self.lb_mac),dst=EthAddr("FF:FF:FF:FF:FF:FF"))
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        connection.send(msg)
        pass

    
    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        # write your code here!!!
        actions=[]
        actions.append(of.ofp_action_dl_addr.set_dst(str(self.server_ip_to_mac_port[server_ip]['mac'])))
        actions.append(of.ofp_action_dl_addr.set_src(str(self.lb_mac)))
        actions.append(of.ofp_action_nw_addr.set_dst(str(server_ip)))
        actions.append(of.ofp_action_output(port = outport))
        msg=of.ofp_flow_mod()
        msg.idle_timeout=10
        msg.buffer_id=buffer_id
        msg.actions=actions
        msg.match=of.ofp_match(in_port=self.client_ip_to_mac_port[client_ip]['port'] ,nw_dst=self.service_ip, nw_src=client_ip, dl_src=self.client_ip_to_mac_port[client_ip]['mac'], dl_dst=self.lb_mac,dl_type=0x800)
        connection.send(msg)
        pass


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        # write your code here!!!
        actions=[]
        actions.append(of.ofp_action_dl_addr.set_dst(str(self.client_ip_to_mac_port[client_ip]['mac'])))
        actions.append(of.ofp_action_dl_addr.set_src(str(self.lb_mac)))
        actions.append(of.ofp_action_nw_addr.set_src(str(self.service_ip)))
        actions.append(of.ofp_action_output(port = outport))
        msg=of.ofp_flow_mod()
        msg.idle_timeout=10
        msg.actions=actions
        msg.match=of.ofp_match(in_port=self.server_ip_to_mac_port[server_ip]['port'], nw_dst=client_ip, nw_src=server_ip, dl_src=self.server_ip_to_mac_port[server_ip]['mac'],dl_dst=self.lb_mac, dl_type=0x800)
        connection.send(msg)
        pass

    def install_flow_for_dropping(self, connection, outport, srcip, dstip, buffer_id):
        log.info("Dropping and creating rule for packet of IP which is not included in configuration file or packet that does not follow the client-> server rule")
        actions=[]
        actions.append(of.ofp_action_output(port = outport))
        msg=of.ofp_flow_mod()
        msg.idle_timeout=10
        msg.actions=actions
        msg.match=of.ofp_match(nw_src=srcip, nw_dst=dstip, in_port=outport, dl_type=0x800)
        connection.send(msg)


    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        
        if packet.type == packet.ARP_TYPE:
            # write your code here!!!
            if packet.next.opcode==1: #if arp request
                if packet.next.protodst==IPAddr(self.service_ip) or (IPAddr(packet.next.protosrc) in self.server_ip_to_group and IPAddr(packet.next.protodst) in self.client_ip_to_mac_port):
                    self.send_proxied_arp_reply(packet, connection, inport, packet.next.hwsrc)
            elif packet.next.opcode==2: #if arp reply
                self.server_ip_to_mac_port[packet.next.protosrc]={'mac':packet.src, 'port':inport}
                log.info("Received ARP reply from server %s" % packet.next.protosrc)
            else:
                log.info("Unknown ARP opcode: %s" % packet.next.opcode)
                return
            pass
        elif packet.type == packet.IP_TYPE:
            dstIP=packet.next.dstip
            srcIP=packet.next.srcip
            # write your code here!!!
            if dstIP==self.service_ip and srcIP in self.user_ip_to_group: #if traffic starting from user(json file) and traffic is intended for service ip
                while packet.next.srcip not in self.client_ip_to_mac_port: #python is slow(?), sometimes the traffic comes before saving to dictionary
                    time.sleep(0.001)
                self.update_lb_mapping(packet.next.srcip)
                self.install_flow_rule_server_to_client(connection, self.client_ip_to_mac_port[srcIP]['port'], self.lb_mapping[srcIP], srcIP, event.ofp.buffer_id)
                self.install_flow_rule_client_to_server(connection, self.server_ip_to_mac_port[self.lb_mapping[srcIP]]['port'], srcIP, self.lb_mapping[srcIP], event.ofp.buffer_id)               
            else: #drop packet in case it is not starting from client, or not intended for service ip
                self.install_flow_for_dropping(connection, inport, srcIP, dstIP, event.ofp.buffer_id)
            pass
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return


# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}    
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict


# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")
    
    # load the configuration from file    
    configuration_dict = load_json_dict(configuration_json_file)   

    # the service IP that is publicly visible from the users' side   
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])

    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]    

    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')    
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")
