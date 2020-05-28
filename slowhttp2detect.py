import sys
import logging
import textwrap
import argparse

import netifaces as ni
import ipaddress
import pyshark as ps

import plotly.graph_objects as go

# Parse input args
PARSER = argparse.ArgumentParser(description=textwrap.dedent('''\
                                SlowHTTP/2 Attack Detector
                                 
                                author: Michael Jurek
                                        xjurek03@stud.feec.vutbr.cz'''),
                                formatter_class=argparse.RawTextHelpFormatter)

PARSER.add_argument("-l","--live",action="store_true",required='-i' in sys.argv,help="live Slow DoS Attack detection")
PARSER.add_argument("-i","--interface",default="ens33",required='-l' in sys.argv,type=str,help="name of interface for Slow DoS Attack live capture")
PARSER.add_argument("-d","--duration",default=60, type=int,help="duration of detection in seconds")
PARSER.add_argument("-f","--file",metavar="FILE",required='-a' in sys.argv,type=str,help=".pcap file for Slow DoS Attack detection")
PARSER.add_argument("-a","--address",required='-f' in sys.argv, help="ip address of server for Slow DoS Attack detection")
args = PARSER.parse_args()

# Logger setup
LOGGER = logging.Logger(name="slowhttp2detect")
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
LOGGER.addHandler(handler)

mode = "offline"

if(args.live) and (args.file):
    LOGGER.info("Error: -l and -i must be supplied or -f and -a must be supplied")
    sys.exit(1)
elif(not args.live) and (args.file is None):
    LOGGER.info("Error: -l and -i must be supplied or -f and -a must be supplied")
    sys.exit(1)
elif(args.live):
    mode = "online"

captured_attacks = {"SLOW_READ": 0,
                    "SLOW_POST": 0,
                    "SLOW_PREFACE": 0,
                    "SLOW_HEADERS": 0,
                    "SLOW_SETTINGS": 0,
                    "NONE_ATTACK": 0}

possible_settings_attack = []

def check_possible_settings_attack(packet):
    for p in possible_settings_attack:
        if(p["IP_ADDRESS"] == packet['ip'].src and
        p["PORT"] == packet['tcp'].port and
        p["STREAM_ID"] == packet['http2'].streamid):
            return True
    return False

def analyze_packet(packet):
    try:
        if('Stream: Magic' in packet['http2'].stream):
            try:
                if(packet['http2'].settings_initial_window_size == '0'):
                    captured_attacks["SLOW_READ"] += 1
                    captured_attacks["NONE_ATTACK"] -= 1
                else:
                    if(check_possible_settings_attack(packet)):
                        try:
                            if(packet['http2'].settings):
                                captured_attacks["NONE_ATTACK"] += 1
                                captured_attacks["SLOW_SETTINGS"] -= 1
                        except AttributeError:
                            pass
                    else:
                        possible_settings_attack.append({
                            "IP_ADDRESS": packet['ip'].src,
                            "PORT": packet['tcp'].port,
                            "STREAM_ID": packet['http2'].streamid
                        })
                        captured_attacks["SLOW_SETTINGS"] += 1
                        captured_attacks["NONE_ATTACK"] += 1
            except AttributeError:
                captured_attacks["SLOW_PREFACE"] += 1
        
        elif('Stream: HEADERS' in packet['http2'].stream):
            if(packet['http2'].flags_end_stream == '0' and packet['http2'].flags_eh == '1'):
                captured_attacks["SLOW_POST"] += 1
                captured_attacks["NONE_ATTACK"] -= 1
                captured_attacks["SLOW_SETTINGS"] -= 1
            elif(packet['http2'].flags_end_stream == '1' and packet['http2'].flags_eh == '0'):
                captured_attacks["SLOW_HEADERS"] += 1
                captured_attacks["NONE_ATTACK"] -= 1
                captured_attacks["SLOW_SETTINGS"] -= 1
            else:
                captured_attacks["NONE_ATTACK"] += 1
        
        else:
            captured_attacks["NONE_ATTACK"] += 1

    except AttributeError:
        captured_attacks["NONE_ATTACK"] += 1
    


def detect_online(interface, duration):
    """Online detection for Slow DoS Attacks on HTTP/2 protocol"""
    try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    except ValueError:
        LOGGER.error("Invalid interface inserted.")
        sys.exit(1)
    
    live_capture = ps.LiveCapture(interface, display_filter="ip.dst == "+str(ip)+" && http2")
    live_capture.sniff(timeout=duration)

    for packet in live_capture._packets:
        analyze_packet(packet)


def detect_offline(file, ip):
    """Offline detection for Slow DoS Attacks on HTTP/2 protocol"""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        LOGGER.error("Inavlid IP address inserted.")
        sys.exit(1)
    try:
        file_capture = ps.FileCapture(file+'.pcap', display_filter="ip.dst == "+str(ip)+" && http2")
    except FileNotFoundError:
        LOGGER.error("Inserted file does not exist.")
        sys.exit(1)

    for packet in file_capture:
        analyze_packet(packet)
    
    

if __name__ == '__main__':
    try:
        if mode=="online":
            detect_online(args.interface, args.duration)
        else:
            detect_offline(args.file, args.address)
    except KeyboardInterrupt:
        LOGGER.error("\nENDING ...")
    if(captured_attacks["SLOW_SETTINGS"]>0):
        captured_attacks["NONE_ATTACK"] -= captured_attacks["SLOW_SETTINGS"]*2
    LOGGER.info(captured_attacks)

    x_features = ["Slow READ", "Slow POST", "Slow PREFACE", "Slow HEADERS", "Slow SETTINGS", "Normal HTTP/2 Connections"]
    total_http2 = sum(i for i in captured_attacks.values())

    fig = go.Figure()
    fig.update_layout(title="Slow DoS Attack Detection",
                      xaxis_title="Type of Attack",
                      yaxis_title="Number of HTTP/2 Connections",
                      font=dict(
                          size=18,
                          color="black"
                      ),
                      barmode="stack")
    fig.add_trace(go.Bar(name="Number of HTTP/2 Connections Containing Slow DoS Attacks",
                         x=x_features, y=[value for value in captured_attacks.values()], marker_color='steelblue'))
    fig.add_trace(go.Bar(name="Total Number of Captured HTTP/2 Connections",
                          x=x_features, y=[total_http2-captured_attacks[i] for i in captured_attacks.keys()], marker_color='tomato'))
    fig.write_html("slowhttp2detect.html", auto_open=True)
    