#!/usr/bin/python

import sys
import traceback
import argparse

import scapy
from scapy.all import rdpcap, TCP
from dnspy import dnspy


dnspy = dnspy.Dnspy(etld_url='file:///usr/share/dnspy/mozilla_etlds.dat')


def user_fn(sess_id, http_req_rsp):
    """Description

    Args:
        sess_id (str)           : Session ID being analyzed
        http_req_rsp (dict)     : Contains the HTTP Request and Response
                                  content
    Returns:
        bool: True if x. False if y
    """
    return


def user_fn_example(sess_id, http_req_rsp):
    """Description

    Args:
        sess_id (str)           : Session ID being analyzed
        http_req_rsp (dict)     : Contains the HTTP Request and Response
                                  content
    Returns:
        bool: True if x. False if y
    """
    # Analyze HTTP-Request
    req_payload, _ = http_req_rsp['req']

    try:
        headers_raw = req_payload[:req_payload.index("\r\n\r\n")+1]
    except ValueError:
        traceback.print_exc()
        return      # Do not return {}
    headers = headers_raw.split('\r\n')

    for header in headers[1:]:              # Skip the first line
        field, content = header.split(':', 1)
        field = field.lower()
        content = content.strip()

        # Domain
        if field.startswith('host'):
            e2ld = dnspy.subdoms(content)[1]
            print 'Effective second-level domain: %s' % e2ld

    # Analyze HTTP-Response
    rsp_payload, _ = http_req_rsp['rsp']
    try:
        headers_raw = rsp_payload[:rsp_payload.index("\r\n\r\n")+1]
    except ValueError:
        traceback.print_exc()
        return      # Do not return {}

    headers = headers_raw.split('\r\n')

    for header in headers[1:]:              # Skip the first line
        field, content = header.split(':', 1)
        field = field.lower()
        content = content.strip()

        # Content type
        if field.startswith('content-type'):
            print 'Content-type returned: %s' % content

    return


def filter_fn(pkt):
    """Filtering condition for relevant packets wanted from the PCAP. Since
    we only want HTTP based TCP packets

    Args:
        pkt (scapy.layers.l2.Ether)     : Each on which to apply the filter

    Returns:
        bool: True if the pkt met the filter condition. Else, False.
    """
    return ((TCP in pkt) and ((pkt[TCP].sport == 80) or (pkt[TCP].dport == 80)))


def parse_pcap(pcapfile):
    """Collect request and response HTTP sessions.

    Args:
        pcapfile (str)  : Name of the PCAP file to build the sessions from.

    Returns:
        Nothing
    """
    pinf = rdpcap(pcapfile)
    sessions = pinf.filter(filter_fn).sessions()

    sessions_cache = {}
    for sessid, pkts in sessions.iteritems():

        http_payload = ''
        for pkt in pkts:
            # Pretty important: pkt may contain Padding which messes up the
            # built HTTP content
            if type(pkt[TCP].payload) != scapy.packet.Raw:
                continue
            http_payload += str(pkt[TCP].payload)
        pet = int(pkts[-1].time)     # Page end time

        # Determine type: Request/Response
        if pkts[0].dport == 80:
            # Check if the flow tuple is present in the cache
            if sessid not in sessions_cache:
                sessions_cache[sessid] = {}
            # HTTP request
            sessions_cache[sessid]['req'] = (http_payload, pet)
        else:
            # HTTP response
            proto, src, _, dst = sessid.split(' ')
            req_sessid = '%s %s > %s' % (proto, dst, src)
            # Check if the flow tuple is present in the cache
            if req_sessid not in sessions_cache:
                sessions_cache[req_sessid] = {}
            sessions_cache[req_sessid]['rsp'] = (http_payload, pet)

    for sess_id, v in sessions_cache.iteritems():
        # Check if HTTP payload is not empty
        if ('rsp' in v) and (v['rsp'][0] != ''):
            # Replace with user_fn(sess_id, v)
            user_fn_example(sess_id, v)

    return


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description='Analyze HTTP sessions in\
                                                  pcap files')
    parser.add_argument('-f', dest='pcapfile', help='PCAP file to parse')
    args = parser.parse_args()

    parse_pcap(args.pcapfile)
    return


if __name__ == '__main__':
    sys.exit(main())
