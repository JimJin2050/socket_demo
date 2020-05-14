# -*- coding=utf-8 -*-
import os
import time
import socket
import struct
import select
import random

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris.

ICMP_CODE = socket.getprotobyname('icmp')
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
}


def checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    l = len(source_string)
    count_to = (l / 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff  # Necessary?
        count = count + 2
    if count_to < l:
        sum = sum + source_string[l - 1]
        sum = sum & 0xffffffff  # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(pack_id, data):
    """Create a new echo request packet based on the given "pack_id"."""
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, pack_id, 1)

    data = data[:192] if len(data) > 192 else data + (192 - len(data)) * b'@'

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
                         socket.htons(my_checksum), pack_id, 1)
    print(ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), pack_id, 1)
    print(header)
    print(header.decode("utf-8"))
    return header + data


def send_raw_msg(dest_addr, data, timeout=1):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.

    Returns either the delay (in seconds) or None on timeout and an invalid
    address, respectively.

    """
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except socket.error as e:
        if e.errno in ERROR_DESCR:
            # Operation not permitted
            raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
        raise  # raise the original error
    try:
        host = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return
    # Maximum for an unsigned short int c object counts to 65535 so
    # we have to sure that our packet id is not greater than that.
    packet_id = int((id(timeout) * random.random()) % 65535)
    packet = create_packet(packet_id, data)
    print("packet:", packet)
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (dest_addr, 8088))
        packet = packet[sent:]
    delay = receive_raw_msg(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return delay


def receive_raw_msg(my_socket, packet_id, time_sent, timeout):
    # Receive the ping from the socket.
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []:  # Timeout
            return
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(65565)
        print(rec_packet, addr)
        icmp_header = rec_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack(
            'bbHHh', icmp_header)
        print(type, code, checksum, p_id, sequence)
        if p_id == packet_id:
            return time_received - time_sent
        time_left -= time_received - time_sent
        if time_left <= 0:
            return


def raw_msg_receive(host_ip):
    # if os.name == "nt":
    #     protocol = socket.IPPROTO_IP
    # else:
    #     protocol = socket.IPPROTO_ICMP
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    except socket.error as e:
        if e.errno in ERROR_DESCR:
            raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
        raise
    my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    my_socket.bind((host_ip, 0))
    print("start...")
    while True:
        rec_packet, addr = my_socket.recvfrom(1024)
        print(rec_packet)
        print((rec_packet[-192:].decode("utf-8").strip("@")))
        if not rec_packet:
            break


if __name__ == '__main__':
    pass
    raw_msg_receive("192.168.36.181")