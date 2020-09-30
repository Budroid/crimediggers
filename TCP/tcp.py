#!/usr/bin/env python3.7
# Author: RJA Buddenbohmer
from scapy.all import *
from scapy.packet import *
from scapy.layers.inet import TCP
import json, re

email_ports = [25, 110]          # SMTP and POP, as we saw in the Wireshark statistics
packets = rdpcap('./jim.pcapng') # The capture
mail_list = []                   # List of mails, constructed during analysis

def is_email_packet(packet):
    # All TCP packets with the correct port numbers and an actual payload
    return packet.haslayer(TCP) and (packet.dport in email_ports or packet.sport in email_ports) and packet[TCP].payload

def contains_message(packet):
    # We are only interested in packets with From and To fields in the payload
    content = bytes(packet[TCP].payload).decode("utf-8")
    return any(fieldname in content for fieldname in ["To: ", "From: "])

def is_message(packet):
    return is_email_packet(packet) and contains_message(packet)

def parse_payload(payload):
    # Extract the header bytes
    end_of_header = payload.find(b'\r\n\r\n')
    header_bytes = payload[:end_of_header]
    result = parse_header(header_bytes)
    # Extract and parse the data bytes
    data_bytes = payload[end_of_header:]
    data = parse_data(data_bytes, result)
    # Merge header and data
    result.update(data)
    return result

def parse_header(header):
    # Create a dictionary from all header fields
    header_dict = {}
    for line in header.split(b'\r\n'):
        # The +OK octets' line is not a header field
        if line and not line.startswith(b'+OK '):
           # Convert all multilines to singlelines 
           if not line.startswith(b' '):
              k, v = line.split(b":", 1) 
              header_dict[k.decode('utf-8')] = v.decode('utf-8').strip()
           else:
              last_key = list(header_dict.keys())[-1] 
              header_dict[last_key] += ' ' + line.strip().decode('utf')
    return header_dict

def parse_data(data, header):
    data_dict = {}
    # Do we have an attachment?
    if "multipart" in header['Content-Type']:
       boundary = get_boundary(header['Content-Type'])
       parts = [] 
       for section in data.split(boundary.encode()):
           if b'Content-Type' in section:
               parts.append(parse_payload(section))
       data_dict["parts"] = parts
    else:
       message_text = []
       for line in data.replace(b"\r\n.\r\n", b"").split(b'\r\n'):
           if line:
              message_text.append(line.decode('utf-8'))
       data_dict["message_lines"] = message_text
    return data_dict

def get_boundary(content_type):
    boundary = re.search(r'(?<=boundary=\")(.*)(?=\")', content_type).group(1)
    return "--" + boundary    
    
print("CRIMEDIGGERS  -  TCP/IP\n")
# First we need to collect all the required data
for pkt in packets:
    if is_message(pkt):
       mail = parse_payload(bytes(pkt[TCP].payload))
       mail_list.append(mail)
 # Now we have all information structured, lets print a nice timeline
for mail in mail_list:
    print("{:<10} {}".format("Date:", mail["Date"]))
    print("{:<10} {}".format("Sender:", mail["From"]))
    print("{:<10} {}".format("Receiver:", mail["To"]))
    print("{:<10} {}".format("Subject:", mail["Subject"]))
    if "message_lines" in mail:
       message_lines = mail["message_lines"] 
       print("\n{:<10} {}".format("Message:", message_lines[0]))
       for line in message_lines[1:]:
           print("{:<10} {}".format("", line))
    print("----------------------------------------\n")



