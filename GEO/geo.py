#!/usr/bin/env python3.7
# Author: RJA Buddenbohmer
import xml.etree.ElementTree as ET
import json, webbrowser

print("CRIMEDIGGERS  -  GEO")
trees = [ET.parse('GPS 1.gpx'), ET.parse('GPS 2.gpx')]
event_list = []
suspicious_area_list = []

def get_small_coords(location):
    lat = float(location.get('lat'))
    lon = float(location.get('lon'))
    return f'{lat:.4f};{lon:.4f}'

def add_to_events(time, location, action, device):
    event_list.append({"time": time, 
                       "location": location, 
                       "action": action, 
                       "device": device})

# First check whenever they where close to eachother
for location_1 in trees[0].getroot().iter('wpt'):
    for location_2 in trees[1].getroot().iter('wpt'):
        if get_small_coords(location_1) == get_small_coords(location_2):
            suspicious_area_list.append(get_small_coords(location_1))

# Construct an eventlist with suspicious events
index = 1
for tree in trees:
    last_seen = None
    root = tree.getroot()
    for location in root.iter('wpt'):
        coords = get_small_coords(location)
        suspicious_area = coords in suspicious_area_list
        if suspicious_area:
            if last_seen != coords and last_seen in suspicious_area_list:
                add_to_events(location.find('time').text, last_seen, "leaving ", index)
            add_to_events(location.find('time').text, coords, "entering", index)    
        else:
            if last_seen in suspicious_area_list:
                add_to_events(location.find('time').text, last_seen, "leaving ", index)   
        last_seen = coords
    index = index+1
    
# Create a timeline from the eventlist
event_list.sort(key=lambda e: e['time'])
previous = {"time": "0", "location": "0", "action": "0", "device": 0}
for event in event_list:
    match = ""
    if event['device'] != previous['device'] and event['location'] == previous['location']:    
       match = " < --- MATCH!"
       result = event['location']  
    print(event['time'].replace("T", " ").replace("Z", "") + 
          ": Device " + str(event['device']) + 
          " " + str(event['action']) + 
          " suspicious area " + event['location'] + 
          match)
    previous = event

# Show result in on google maps
url = "https://www.google.nl/maps/place/52%C2%B021'37.8%22N+4%C2%B052'28.2%22E/@" + result.replace(";", ",") + ",19z/data=!4m5!3m4!1s0x0:0x0!8m2!3d52.3605!4d4.8745"
# Linux only. For Windows fill in the location of your chrome installation
chrome_path = '/usr/bin/google-chrome %s'
webbrowser.get(chrome_path).open(url)
    