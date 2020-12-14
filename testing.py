#!/usr/bin/env python3.8

import pyshark, multiprocessing, sys, os, json, random
from time import time, sleep
import database

#number of seconds to retain packets
cache_size = 10
#number of seconds for host status to expire
host_expire_time = 60
host_pair_expire_time = 30
netflow_expire_time = 10

'''
TODO
	remove packet timestamps from host_pairs and port flows after X seconds
	reevaluate as active or dead

Research TTL and passive traceroute techniques




What is a flow?
• Source IP address
• Destination IP address
• Source port
• Destination port
• Layer 3 protocol type
• TOS byte (DSCP)
• Input logical interface (ifIndex)

Flow Record Contents
• Source and Destination, IP address and port
• Packet and byte counts
• Start and end times
• ToS, TCP flags
Basic information about the flow…
…plus, information related to routing
• Next-hop IP address
• Source and destination AS
• Source and destination prefix
'''
rand_ids = ['']


def id_generate():
	new = ''
	while new in rand_ids:
		new = str(random.randint(100000, 999999)) 
	rand_ids.append(new)
	return new

def find_interfaces():
	#return a list of all interfaces on the device
	lines = []
	global interfaces
	interfaces = []
	with open('/proc/net/dev') as f:
		for line in f:
			lines.append(line.strip())
	for line in lines[2:]:
		if 'lo' not in line.split(":")[0]:
			interfaces.append(line.split(":")[0])
	return

def enable_promisc(interface):
	#enable promiscuous listening mode on every interface:
	os.system(f'ifconfig {interface} promisc')

def disable_promisc(interface):
	#disable promiscuous listening mode on every interface:
	os.system(f'ifconfig {interface} -promisc')

def format_packet_data(packet):
	packet_data = {'timestamp' : packet.sniff_timestamp,}
	if 'ETH' in str(packet.layers):
		packet_data['eth'] = {	'src' : packet.eth.src,
								'dst' : packet.eth.dst,}
	if 'TCP' in str(packet.layers) or 'UDP' in str(packet.layers):
		packet_data['ip']  = {	'src' : packet.ip.src,
								'dst' : packet.ip.dst,}
	if 'TCP' in str(packet.layers):
		packet_data['tcp'] = {	'src' : packet.tcp.srcport,
								'dst' : packet.tcp.dstport,}
	if 'UDP' in str(packet.layers):
		packet_data['udp'] = {	'src' : packet.udp.srcport,
								'dst' : packet.udp.dstport,}
	if 'ARP' in str(packet.layers):
		packet_data['arp'] = {	'mac' : {	'src' : packet.arp.src_hw_mac,
											'dst' : packet.arp.dst_hw_mac,
										},
								'ip'  : {	'src' : packet.arp.src_proto_ipv4,
											'dst' : packet.arp.dst_proto_ipv4,
										},
								'code': packet.arp.opcode,}
	# packet.pretty_print()
	return json.dumps(packet_data)

def live_capture(interface=None):
	#start a live packet capture on the specified interface
	print(f'waiting for packets on {interface}')
	enable_promisc(interface)
	capture = pyshark.LiveCapture(interface=interface, only_summaries=False)
	for packet in capture.sniff_continuously():
		with open(f'./pcap_{interface}.log', 'a') as log:
			log.write(format_packet_data(packet) + '\n') 
	disable_promisc(interface)
	return

def create_captures():
	#create a seperate capture for each interface
	captures =[]
	find_interfaces()
	for interface in interfaces:
		p = multiprocessing.Process(target=live_capture, args=(interface,))
		captures.append(p)
		p.start()
	return captures

def add_new_data_from(logfile):
	new_packets = []
	with open(logfile, 'r') as log:
		for packet in log:
			packet = eval(packet.strip())
			packet['timestamp'] = float(packet['timestamp'])
			if (float(packet['timestamp']) + 10) > float(time()):
				if packet not in database.packet_cache:
					new_packets.append(packet)
	database.packet_cache.extend(new_packets)
	clean_logs(logfile)

def clean_logs(logfile):
	with open(logfile, 'w') as f:
		f.write('')

def discard_old_packets():
	current_data = []
	for packet in database.packet_cache:
		timestamp = float(packet['timestamp'])
		# print(f'{round(float(time() - timestamp), 2)} seconds ago packet from {packet.strip().split(";")[3]} going to {packet.strip().split(";")[4]} arrived')
		if timestamp + cache_size >= float(time()):
			current_data.append(packet)
	database.packet_cache = current_data

def discard_old_netflow_transmissions():
	def remove_old_flows(flow_type, host_pair_id):
		for netflow in database.netflows[host_pair_id][flow_type]:
			recent_transmissions = []
			for timestamp in database.netflows[host_pair_id][flow_type][netflow]['recent_transmissions']:
				if timestamp + netflow_expire_time > time():
					recent_transmissions.append(timestamp)
			database.netflows[host_pair_id][flow_type][netflow]['recent_transmissions'] = recent_transmissions
	for host_pair in database.netflows:
		recent_transmissions = []
		for timestamp in database.netflows[host_pair]['recent_transmissions']:
			if timestamp + host_pair_expire_time > time():
				recent_transmissions.append(timestamp)
		database.netflows[host_pair]['recent_transmissions'] = recent_transmissions
		remove_old_flows('tcp_flows', database.netflows[host_pair]['host_pair_ID'])
		remove_old_flows('udp_flows', database.netflows[host_pair]['host_pair_ID'])

def discard_old_data():
	discard_old_packets()
	discard_old_netflow_transmissions()

def discover_hosts():
	for packet in database.packet_cache:
		if 'ip' in packet:
			database.hosts[packet['ip']['src']] = database.hosts.get(packet['ip']['src'], {})
			database.hosts[packet['ip']['src']]['recently_active'] = True
			database.hosts[packet['ip']['src']]['last_transmission'] = float(packet['timestamp'])
		elif 'arp' in packet:
			database.hosts[packet['arp']['ip']['src']] = database.hosts.get(packet['arp']['ip']['src'], {})
			database.hosts[packet['arp']['ip']['src']]['recently_active'] = True
			database.hosts[packet['arp']['ip']['src']]['last_transmission'] = float(packet['timestamp'])


		# if packet['ip']['src'] not in database.hosts:
		# 	database[packet['ip']['src']] = {'recently_active' : True}
		# if packet['arp']['ip']['src'] not in database.hosts:
		# 	database[packet['arp']['ip']['src']] = {'recently_active' : True}

def host_pair_new(ip1, ip2):
	new_ID = id_generate()
	database.netflows[new_ID] = { 	'host_pair_ID'				: new_ID,
									'addresses' 				: [ip1, ip2],
									'recently_active' 			: True,
									'recent_transmissions' 		: [],
									'tcp_flows'					: {},
									'udp_flows'					: {},
								}
	return new_ID

def host_pair_update(host_pair_id, timestamp):
	database.netflows[host_pair_id]['recent_transmissions'].insert(0, timestamp)
	return

def tcp_flow_new(packet, host_pair_id, timestamp):
	new_ID = id_generate()
	database.netflows[host_pair_id]['tcp_flows'][new_ID] = 	{	'flowID'					: new_ID,
																'ports' 					: [packet['tcp']['src'], packet['tcp']['dst']],
																'recently_active' 			: True,
																'recent_transmissions' 		: [float(timestamp)],
															}

def tcp_flow_update(packet, host_pair_id):
	for port_flow in database.netflows[host_pair_id]['tcp_flows']:
		if packet['tcp']['src'] in database.netflows[host_pair_id]['tcp_flows'][port_flow]['ports'] and packet['tcp']['dst'] in database.netflows[host_pair_id]['tcp_flows'][port_flow]['ports']:
			port_flow_ID = database.netflows[host_pair_id]['tcp_flows'][port_flow]['flowID']
			database.netflows[host_pair_id]['tcp_flows'][port_flow_ID]['recent_transmissions'].insert(0, float(packet['timestamp']))
			return
	tcp_flow_new(packet, host_pair_id, packet['timestamp'])
	return

def udp_flow_new(packet, host_pair_id, timestamp):
	new_ID = id_generate()
	database.netflows[host_pair_id]['udp_flows'][new_ID] = 	{	'flowID'					: new_ID,
																'ports' 					: [packet['udp']['src'], packet['udp']['dst']],
																'recently_active' 			: True,
																'recent_transmissions' 		: [float(timestamp)],
															}

def udp_flow_update(packet, host_pair_id):
	for port_flow in database.netflows[host_pair_id]['udp_flows']:
		if packet['udp']['src'] in database.netflows[host_pair_id]['udp_flows'][port_flow]['ports'] and packet['udp']['dst'] in database.netflows[host_pair_id]['udp_flows'][port_flow]['ports']:
			port_flow_ID = database.netflows[host_pair_id]['udp_flows'][port_flow]['flowID']
			database.netflows[host_pair_id]['udp_flows'][port_flow_ID]['recent_transmissions'].insert(0, float(packet['timestamp']))
			return
	udp_flow_new(packet, host_pair_id, packet['timestamp'])
	return

def arp_check(packet):
	for flow in database.netflows:
		if packet['arp']['ip']['src'] in database.netflows[flow]['addresses'] and packet['arp']['ip']['dst'] in database.netflows[flow]['addresses'] and int(packet['arp']['code']) == 2:
			host_pair_ID = database.netflows[flow]['host_pair_ID']
			host_pair_update(host_pair_ID, packet['timestamp'])
			return
	if int(packet['arp']['code']) == 2:
		host_pair_ID = host_pair_new(packet['arp']['ip']['src'], packet['arp']['ip']['dst'])
		host_pair_update(host_pair_ID, packet['timestamp'])
		return

def tcp_check(packet):
	for flow in database.netflows:
		if packet['ip']['src'] in database.netflows[flow]['addresses'] and packet['ip']['dst'] in database.netflows[flow]['addresses']:
			host_pair_ID = database.netflows[flow]['host_pair_ID']
			host_pair_update(host_pair_ID, packet['timestamp'])
			tcp_flow_update(packet, host_pair_ID)
			return
	host_pair_ID = host_pair_new(packet['ip']['src'], packet['ip']['dst'])
	host_pair_update(host_pair_ID, packet['timestamp'])
	tcp_flow_update(packet, host_pair_ID)
	return

def udp_check(packet):
	for flow in database.netflows:
		if packet['ip']['src'] in database.netflows[flow]['addresses'] and packet['ip']['dst'] in database.netflows[flow]['addresses']:
			host_pair_ID = database.netflows[flow]['host_pair_ID']
			host_pair_update(host_pair_ID, packet['timestamp'])
			udp_flow_update(packet, host_pair_ID)
			return
	host_pair_ID = host_pair_new(packet['ip']['src'], packet['ip']['dst'])
	host_pair_update(host_pair_ID, packet['timestamp'])
	udp_flow_update(packet, host_pair_ID)
	return

def update_data():
	discard_old_data()
	for log in interface_logs:
		add_new_data_from(log)
	discover_hosts()

def update_hosts():
	for host in database.hosts:
		if database.hosts[host]['last_transmission'] < time() - host_expire_time:
			database.hosts[host]['recently_active'] = False

def update_host_pair_status():
	def update_netflow_status(flow_type, host_pair_id):
		for netflow in database.netflows[host_pair_id][flow_type]:
			if database.netflows[host_pair][flow_type][netflow]['recent_transmissions']:
				database.netflows[host_pair][flow_type][netflow]['recently_active'] = True
			else:
				database.netflows[host_pair][flow_type][netflow]['recently_active'] = False
	for host_pair in database.netflows:
		if database.netflows[host_pair]['recent_transmissions']:
			database.netflows[host_pair]['recently_active'] = True
			update_netflow_status('tcp_flows', database.netflows[host_pair]['host_pair_ID'])
			update_netflow_status('udp_flows', database.netflows[host_pair]['host_pair_ID'])
		else:
			database.netflows[host_pair]['recently_active'] = False
			update_netflow_status('tcp_flows', database.netflows[host_pair]['host_pair_ID'])
			update_netflow_status('udp_flows', database.netflows[host_pair]['host_pair_ID'])

def update_netflows():
	for packet in database.packet_cache:
		if 'arp' in packet.keys():
			arp_check(packet)
		if 'tcp' in packet.keys():
			tcp_check(packet)
		if 'udp' in packet.keys():
			udp_check(packet)
	update_host_pair_status()

def get_flow_count(host_pair_id, flow_type):
	count = 0
	for netflow in database.netflows[host_pair_id][flow_type]:
		if database.netflows[host_pair_id][flow_type][netflow]['recently_active']:
			count += 1
	return count

def display_update():
	sys.stdout.flush()
	print('-'*80)
	print('-'*80)
	print('\n')
	print(f'packets in cache: {len(database.packet_cache)}')
	print(f'hosts in log: {len(database.hosts)}')
	print('-'*80)
	print('Recently active hosts:')
	for host in database.hosts:
		if database.hosts[host]['recently_active']:
			print(f"{host} last seen {round(time() - database.hosts[host]['last_transmission'])} seconds ago")
	print('-'*80)		
	print(f'Active connections between hosts:')
	for flow in database.netflows:
		if database.netflows[flow]['recently_active']:
			tcp_count = get_flow_count(database.netflows[flow]['host_pair_ID'], 'tcp_flows')
			udp_count = get_flow_count(database.netflows[flow]['host_pair_ID'], 'udp_flows')
			print(f"Connection active between {database.netflows[flow]['addresses'][0]} and {database.netflows[flow]['addresses'][1]} with {tcp_count} TCP and {udp_count} UDP streams")
	print('\n')

def main():
	running = True
	captures = create_captures()
	
	global interface_logs
	interface_logs = []
	
	for interface in interfaces:
		interface_logs.append(f'./pcap_{interface}.log')
	

	while running:
		sleep(5)
		update_data()
		update_hosts()
		update_netflows()
		display_update()
		# print(json.dumps(database.netflows))

		




if __name__ == '__main__':
	main()
	




	'''

useful pyshark methods:
Capture class:
	next()
	clear()
	load()






	'''