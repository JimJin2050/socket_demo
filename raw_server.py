# -*- coding=utf-8 -*-
import os
import time
from time import ctime
import json
import struct
import socket
import random
import threading
import logging.config
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import askyesno
from utilities import *

logging.config.dictConfig(json.load(open("config/log.json")))


class Server(object):
    logger = StreamLogger = logging.getLogger("FileLogger")

    def __init__(self):
        self.tcp_client_sock = None
        self.host = conf_read("config/config.conf", "local", "host")
        self.port = conf_read("config/config.conf", "local", "port")
        self.buffer = conf_read("config/config.conf", "local", "buffer")

        self.target_host = conf_read("config/config.conf", "target", "host")
        self.target_port = conf_read("config/config.conf", "target", "port")

        self.raw_msg_listen = False

        self.window = Tk()
        self.window.title("Raw Socket ICMP Server")
        self.window.geometry("630x560")
        Label(self.window, text='Local IP: ').place(x=25, y=30)
        Label(self.window, text='Target IP: ').place(x=25, y=70)
        Label(self.window, text='Port: ').place(x=25, y=110)
        Label(self.window, text='Buffer: ').place(x=25, y=150)

        self.var_local_host = StringVar()
        self.var_local_host.set(conf_read("config/config.conf", "local", "host"))
        entry_host = Entry(self.window, state="disabled", textvariable=self.var_local_host)
        entry_host.place(x=95, y=30)

        self.var_target_host = StringVar()
        self.var_target_host.set(conf_read("config/config.conf", "target", "host"))
        entry_target_host = Entry(self.window, state="disabled", textvariable=self.var_target_host)
        entry_target_host.place(x=95, y=70)

        self.var_port = StringVar()
        self.var_port.set(conf_read("config/config.conf", "local", "port"))
        entry_port = Entry(self.window, state="disabled", textvariable=self.var_port)
        entry_port.place(x=95, y=110)
        self.var_buffer = StringVar()
        self.var_buffer.set(conf_read("config/config.conf", "local", "buffer"))
        entry_buffer = Entry(self.window, state="disabled", textvariable=self.var_buffer)
        entry_buffer.place(x=95, y=150)

        Label(self.window, text='ICMP Type: ').place(x=310, y=30)
        Label(self.window, text='ICMP Code: ').place(x=310, y=70)
        Label(self.window, text='ICMP Seq: ').place(x=310, y=110)
        Label(self.window, text='ICMP ID: ').place(x=310, y=150)
        Label(self.window, text='ICMP LEN: ').place(x=310, y=190)

        self.var_type = StringVar()
        self.var_type.set(conf_read("config/config.conf", "icmp", "type"))
        entry_type = Entry(self.window, state="disabled", textvariable=self.var_type)
        entry_type.place(x=405, y=30)
        self.var_code = StringVar()
        self.var_code.set(conf_read("config/config.conf", "icmp", "code"))
        entry_code = Entry(self.window, state="disabled", textvariable=self.var_code)
        entry_code.place(x=405, y=70)
        self.var_seq = StringVar()
        self.var_seq.set(conf_read("config/config.conf", "icmp", "seq"))
        entry_seq = Entry(self.window, state="disabled", textvariable=self.var_seq)
        entry_seq.place(x=405, y=110)
        self.var_packet_id = StringVar()
        self.var_packet_id.set(random.randint(0, 0xffff))
        entry_packet_id = Entry(self.window, textvariable=self.var_packet_id)
        entry_packet_id.place(x=405, y=150)
        self.var_packet_len = StringVar()
        self.var_packet_len.set(conf_read("config/config.conf", "icmp", "len"))
        entry_packet_len = Entry(self.window, textvariable=self.var_packet_len)
        entry_packet_len.place(x=405, y=190)

        Label(self.window, text='Received msg: ').place(x=25, y=200)

        self.txt_rev_msg = ScrolledText(
            self.window,
            height=10,
            bd=2,
            relief='groove',
            wrap=CHAR,
            bg="WhiteSmoke"
        )
        self.txt_rev_msg.place(x=25, y=220)

        Label(self.window, text='Your msg: ').place(x=25, y=390)
        self.txt_msg = ScrolledText(
            self.window,
            height=6.5,
            width=55,
            bd=2,
            wrap=WORD,
            relief='groove',
            bg="WhiteSmoke")

        self.txt_msg.place(x=25, y=410)
        self.btn_send = Button(
            self.window,
            text='Send',
            width=15,
            activeforeground='blue',
            command=self.send_msg)
        self.btn_send.place(x=472, y=490)

        self.window.protocol('WM_DELETE_WINDOW', self.close_window)
        self.window.mainloop()

    def send_msg(self):
        data = self.txt_msg.get("0.0", "end")
        self.btn_send.config({"state": "disabled"})
        self.send_raw_msg(
            self.var_target_host.get(),
            data.encode("utf-8"),
            int(self.var_type.get()),
            int(self.var_code.get()),
            int(self.var_packet_id.get()),
            int(self.var_seq.get()))
        self.txt_msg.delete('0.0', 'end')
        self.btn_send.config({"state": "normal"})

        if not self.raw_msg_listen:
            self.start_server_thread(self._start_raw_listen, (self.var_local_host.get(),))
            self.raw_msg_listen = True

        new_packet_id = (int(self.var_packet_id.get()) + 1) % 65535
        self.var_packet_id.set(str(new_packet_id))

    def send_raw_msg(
            self,
            dest_addr,
            data,
            icmp_type,
            code,
            pack_id,
            seq):
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            self._insert_text(e.strerror, "[ERROR]")
            print(e.strerror)
            raise
        if isinstance(data, str):
            data = data.encode("utf-8")
        packet = self.create_packet(
            icmp_type,
            code,
            pack_id,
            seq,
            data)
        while packet:
            sent = my_socket.sendto(packet, (dest_addr, 1))
            packet = packet[sent:]
        rec_packet, addr = my_socket.recvfrom(int(self.var_buffer.get()))
        print(rec_packet)
        self._insert_text(dest_addr, "[Target IP]")
        my_socket.close()

    def _start_raw_listen(self, host_ip):
        length = int(self.var_packet_len.get())
        # if os.name == "nt":
        #     protocol = socket.IPPROTO_IP
        # else:
        #     protocol = socket.IPPROTO_ICMP
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            self._insert_text(e.strerror, "[ERROR]")
            print(e.strerror)
            raise
        my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        my_socket.bind((host_ip, 0))
        self._insert_text("Waiting RAW socket message......")
        while True:
            rec_packet, addr = my_socket.recvfrom(int(self.var_buffer.get()))
            if len(rec_packet) == (28 + length):
                msg = rec_packet[-length:].decode("utf-8", "ignore").strip("@")
                icmp_header = rec_packet[20:28]
                type, code, checksum, p_id, sequence = struct.unpack(
                    'bbHHh', icmp_header)
                print(type, code, checksum, p_id, sequence)
                self._insert_text(str(rec_packet), "[ICMP FULL PACKET]")
                self._insert_text(len(rec_packet), "[ICMP LENGTH]")
                self._insert_text(addr[0], "[ICMP SOURCE IP]")
                self._insert_text(msg, "[ICMP MSG]")
                self._insert_text(p_id, "[ICMP PACKET ID]")
                self._insert_text(type, "[ICMP TYPE]")
                self._insert_text(code, "[ICMP CODE]")
                self._insert_text(sequence, "[ICMP SEQ]")
            if not rec_packet:
                break

    def stop_server(self):
        self.window.destroy()

    def _insert_text(self, msg, type_msg=""):
        self.txt_rev_msg.insert(END, "[{}]-{}: {}".format(ctime(), type_msg, msg))
        self.txt_rev_msg.insert(END, "\n")
        self.txt_rev_msg.update()

    def close_window(self):
        ans = askyesno(title='Confirm', message='Close the window?')
        if ans:
            self.stop_server()
        else:
            return

    def create_packet(
            self,
            icmp_type,
            code,
            pack_id,
            seq,
            data,
            chksum=0):
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        header = struct.pack('bbHHh', icmp_type, code, chksum, pack_id, seq)
        length = int(self.var_packet_len.get())
        data = data[:length] if len(data) > length else data + (length - len(data)) * b'@'

        # Calculate the checksum on the data and the dummy header.
        my_checksum = self.checksum(header + data)
        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack('bbHHh', icmp_type, 0,
                             socket.htons(my_checksum), pack_id, 1)
        print(icmp_type, 0, socket.htons(my_checksum), pack_id, 1)
        print(header)
        return header + data


    @staticmethod
    def checksum(source_string):
        sum = 0
        l = len(source_string)
        count_to = (l / 2) * 2
        count = 0
        while count < count_to:
            this_val = source_string[count + 1] * 256 + source_string[count]
            sum = sum + this_val
            sum = sum & 0xffffffff
            count = count + 2
        if count_to < l:
            sum = sum + source_string[l - 1]
            sum = sum & 0xffffffff
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff

        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    @staticmethod
    def start_server_thread(func, args=()):
        t = threading.Thread(target=func, args=args)
        t.setDaemon(True)
        t.start()


if __name__ == "__main__":
    Server()
    pass
