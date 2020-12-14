#!/usr/bin/env python 3.8

packet_cache = []
hosts = {}
netflows = {}



'''
Packet Structure

packet = {	'timestamp'	:	packet.sniff_timestamp,
			'eth' 		: 	{	'src' : packet.eth.src,
								'dst' : packet.eth.dst,
							},
		
			'ip'  		: 	{	'src' : packet.ip.src,
								'dst' : packet.ip.dst,
							},
			'tcp' 		: 	{	'src' : packet.tcp.srcport,
								'dst' : packet.tcp.dstport,
							},
			'udp'		:	{	'src' : packet.udp.srcport,
								'dst' : packet.udp.dstport,
							},
			'arp'		:	{	'mac' : {	'src' : packet.arp.src_hw_mac,
											'dst' : packet.arp.dst_hw_mac,
										},
								'ip'  : {	'src' : packet.arp.src_proto_ipv4,
											'dst' : packet.arp.dst_proto_ipv4,
										},
								'code': packet.arp.opcode,
						}


'''

'''	
	netflow structure:
	host_pair_ID: { 'host_pair_ID'				: host_pair_ID,
					'addresses' 				: [ip1, ip2],
					'recently_active' 			: True,
					'recent_transmissions' 		: [list of timestamps],
				  	'tcp_flows'					: 	{		flowID(random value) : 	{ 	'flowID'					: flowID,
				  															`			'ports' 					: [port1, port2],
									  								   					'recently_active' 			: True,
									  								   					'last_transmission_time' 	: float(timestamp),
									  								  				},
									  						flowID(random value) : 	{ 	'flowID'					: flowID,
									  													'ports' 					: [port1, port2],
									  								   					'recently_active' 			: True,
									  								   					'last_transmission_time' 	: float(timestamp),
									  								  				},
									  						flowID(random value) : 	{ 	'flowID'					: flowID,
									  													'ports' 					: [port1, port2],
									  								   					'recently_active' 			: True,
									  								   					'last_transmission_time' 	: float(timestamp),
									  								  				},
							
													} 
	
				}

	'''