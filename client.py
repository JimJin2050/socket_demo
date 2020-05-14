# -*- coding=utf-8 -*-
import time
import json
import socket
import threading
import logging.config
from time import ctime
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import askyesno
from utilities import *
from raw_socket_icmp import *


logging.config.dictConfig(json.load(open("config/log.json")))


class Client(object):

    logger = StreamLogger = logging.getLogger("FileLogger")

    def __init__(self):
        self.is_connected = False
        self.udp_server_started = False
        self.raw_server_started = False
        self.tcp_listen_started = False
        self.host = conf_read("config/config.conf", "target", "host")
        self.port = conf_read("config/config.conf", "target", "port")
        self.buffer = conf_read("config/config.conf", "target", "buffer")

        self.local_host = conf_read("config/config.conf", "local", "host")
        self.local_port = conf_read("config/config.conf", "local", "port")

        self.tcp_sock = None
        self.udp_sock = None
        self.raw_sock = None

        self.window = Tk()
        self.window.title("Client")
        self.window.geometry("700x510")
        Label(self.window, text='Host: ').place(x=25, y=30)
        Label(self.window, text='Port: ').place(x=25, y=70)
        Label(self.window, text='Buffer: ').place(x=25, y=110)

        self.var_host = StringVar()
        self.var_host.set(conf_read("config/config.conf", "target", "host"))
        entry_host = Entry(self.window, textvariable=self.var_host)
        entry_host.place(x=140, y=30)
        self.btn_connect = Button(
            self.window,
            text='Connect',
            width=12,
            activeforeground='blue',
            relief=RAISED,
            command=self.connect)
        self.btn_connect.place(x=350, y=30)
        self.btn_disconnect = Button(
            self.window,
            text='Disconnect',
            width=12,
            activeforeground='blue',
            relief=RAISED,
            command=self.disconnect)
        self.btn_disconnect.place(x=470, y=30)
        self.btn_disconnect.config(state="disabled")
        self.var_port = StringVar()
        self.var_port.set(conf_read("config/config.conf", "target", "port"))
        entry_port = Entry(self.window, textvariable=self.var_port)
        entry_port.place(x=140, y=70)
        self.var_buffer = StringVar()
        self.var_buffer.set(conf_read("config/config.conf", "target", "buffer"))
        entry_buffer = Entry(self.window, textvariable=self.var_buffer)
        entry_buffer.place(x=140, y=110)

        self.var_trans_mode = StringVar()
        Label(self.window, text='Transmission mode').place(x=400, y=65)

        r1 = Radiobutton(
            self.window,
            text='TCP',
            variable=self.var_trans_mode,
            activeforeground='blue',
            value='tcp',
            command=self.radio_button_changed_tcp)
        r1.place(x=400, y=85)
        r1.select()
        Radiobutton(
            self.window,
            text='UDP',
            variable=self.var_trans_mode,
            activeforeground='blue',
            value='udp',
            command=self.radio_button_changed).place(x=400, y=105)

        Label(self.window, text='Received msg: ').place(x=25, y=150)

        self.txt_rev_msg = ScrolledText(
            self.window,
            height=10,
            bd=2,
            wrap=CHAR,
            relief='groove',
            bg="WhiteSmoke"
        )
        self.txt_rev_msg.place(x=25, y=170)

        Label(self.window, text='Your msg: ').place(x=25, y=350)
        self.txt_msg = ScrolledText(
            self.window,
            height=6.5,
            width=57,
            bd=2,
            wrap=WORD,
            relief='groove',
            bg="WhiteSmoke")

        self.txt_msg.place(x=25, y=380)
        self.btn_send = Button(
            self.window,
            text='Send',
            width=15,
            activeforeground='blue',
            command=self.send_msg)
        self.btn_send.place(x=500, y=470)

        self.window.protocol('WM_DELETE_WINDOW', self.close_window)
        self.window.mainloop()

    def connect(self):
        sock = None
        self.btn_connect.config({"state": "disabled"})
        trans_mode = self.var_trans_mode.get()
        addr = (self.var_host.get(), int(self.var_port.get()))
        try:
            if trans_mode == "tcp":
                if self.tcp_sock is None or "closed" in str(self.tcp_sock):
                    self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock = self.tcp_sock
            elif trans_mode == "udp":
                if self.udp_sock is None or "closed" in str(self.udp_sock):
                    self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock = self.udp_sock
            sock.connect(addr)
            self.is_connected = True

        except socket.error as e:
            self._insert_text(e.strerror)
            print(e)
            pass
        finally:
            time.sleep(0.5)
        if trans_mode == "tcp":
            self._receive_data(trans_mode)
        if trans_mode == "udp":
            self._insert_text("UDP connected".encode("utf-8"), trans_mode)
        self.btn_disconnect.config(state="normal")

    def radio_button_changed(self):
        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="disabled")

    def radio_button_changed_tcp(self):
        if self.tcp_sock:
            if "closed" not in str(self.tcp_sock):
                self.btn_connect.config(state="normal")
                self.btn_disconnect.config(state="disabled")
            else:
                self.btn_connect.config(state="disabled")
                self.btn_disconnect.config(state="normal")
        else:
            self.btn_connect.config(state="normal")
            self.btn_disconnect.config(state="disabled")

    def disconnect(self):
        self._send_data(self.var_trans_mode.get(), "Connection closed")
        self._insert_text("Connection closed".encode("utf-8"), self.var_trans_mode.get())

        self.btn_disconnect.config(state="disabled")
        if self.tcp_sock and "closed" not in str(self.tcp_sock):
            self.tcp_sock.shutdown(2)
            self.tcp_sock.close()
        if self.udp_sock and "closed" not in str(self.udp_sock):
            self.udp_sock.shutdown(2)
            self.udp_sock.close()
        self.is_connected = False
        time.sleep(0.5)
        self.btn_connect.config(state="normal")

    def send_msg(self):
        trans_mode = self.var_trans_mode.get()
        self.btn_send.config({"state": "disabled"})
        data = self.txt_msg.get("0.0", "end")
        if data:
            if self.is_connected:
                self._send_data(trans_mode, data)
                if not self.tcp_listen_started:
                    self.start_thread(self._start_tcp_listen, (self.tcp_sock,))
                    self.tcp_listen_started = True
            else:
                if trans_mode == "udp":
                    udp_interval = conf_read("config/config.conf", "udp", "interval")
                    try:
                        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    except socket.error as e:
                        self._insert_text(e.strerror)
                    self._send_data(trans_mode, data)
                    if not self.udp_server_started:
                        self.start_thread(self._start_udp_server)
                        self.udp_server_started = True
                    time.sleep(float(udp_interval))
                elif trans_mode == "raw_socket":
                    self.send_raw_msg(self.host, data.encode("utf-8"))
                    if not self.raw_server_started:
                        self.start_thread(self._start_raw_server, (self.local_host,))
                        self.udp_server_started = True
                else:
                    self._insert_text("Please connect to a server at first".encode("utf-8"), trans_mode)

        self.btn_send.config({"state": "normal"})

    def send_raw_msg(self, dest_addr, data, packet_id=None):
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            self._insert_text(e.strerror)
            print(e.strerror)
            raise
        packet_id = packet_id if packet_id else random.randint(0, 0xffff)
        packet = create_packet(packet_id, data)
        print("packet:", packet)
        while packet:
            sent = my_socket.sendto(packet, (dest_addr, 1))
            packet = packet[sent:]
        rec_packet, addr = my_socket.recvfrom(1024)
        print(rec_packet)
        self._insert_text(rec_packet, "raw_socket")
        self.txt_msg.delete('0.0', 'end')
        my_socket.close()

    def start_thread(self, func, params=()):
        t = threading.Thread(target=func, args=params)
        t.setDaemon(True)
        t.start()

    def _start_raw_server(self, host_ip):
        if os.name == "nt":
            protocol = socket.IPPROTO_IP
        else:
            protocol = socket.IPPROTO_ICMP
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
        except socket.error as e:
            print(e.strerror)
            raise
        my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        my_socket.bind((host_ip, 0))
        while True:
            rec_packet, addr = my_socket.recvfrom(1024)
            print(rec_packet)
            #msg = rec_packet[-192:].decode("utf-8").strip("@")
            self._insert_text("Raw socket msg: {}\n".format(str(rec_packet)))
            time.sleep(0.1)
            if not rec_packet:
                break

    def _start_udp_server(self):
        try:
            my_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            my_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_sock.bind((self.local_host, int(self.local_port)))
            while True:
                rev_data, address = my_sock.recvfrom(int(self.buffer))
                print(rev_data)
                self.txt_rev_msg.insert(END, "Msg from server: {}".format(rev_data))
                self.txt_rev_msg.insert(END, "\n")
                self.txt_rev_msg.update()
                if not rev_data:
                    break
            my_sock.close()
        except socket.error as e:
            self._insert_text(e.strerror)
            print(e)
        finally:
            pass

    def _start_tcp_listen(self, tcp_sock):
        try:
            while True:
                rev_data = tcp_sock.recv(int(self.buffer))
                print(rev_data)
                self.txt_rev_msg.insert(END, "Msg from server: {}".format(rev_data))
                self.txt_rev_msg.insert(END, "\n")
                self.txt_rev_msg.update()
                if not rev_data:
                    break
            tcp_sock.close()
        except socket.error as e:
            self._insert_text(e.strerror)
            print(e)
        finally:
            pass

    def _multiple_send(self, data, mysock, addr=None):
        tcp_interval = conf_read("config/config.conf", "tcp", "interval")
        udp_interval = conf_read("config/config.conf", "tcp", "interval")
        sd_buffer = int(self.var_buffer.get())
        data_len = len(data)
        start = 0
        while start <= data_len:
            end_len = sd_buffer if (start + sd_buffer) <= data_len else data_len
            if not addr:
                mysock.send(data[start: end_len].encode("utf-8"))
                time.sleep(float(tcp_interval))
            else:
                mysock.sendto(data[start: end_len].encode("utf-8"), addr)
                time.sleep(float(udp_interval))
            start = start + sd_buffer

    def _send_data(self, trans_mode, data):
        addr = (self.var_host.get(), int(self.var_port.get()))
        tcp_interval = conf_read("config/config.conf", "tcp", "interval")
        sd_buffer = int(self.var_buffer.get())
        data_len = len(data)
        try:
            if trans_mode == "tcp":
                self._multiple_send(data, self.tcp_sock)
                #self.tcp_sock.send(data.encode("utf-8"))
            elif trans_mode == "udp":
                if self.is_connected:
                    self.udp_sock.send(
                        data.encode("utf-8")
                    )
                else:
                    # self.udp_sock.sendto(
                    #     data.encode("utf-8"),
                    #     addr)
                    self._multiple_send(data, self.udp_sock, addr)
            elif trans_mode == "raw_socket":
                packet_id = random.randint(0, 0xffff)
                packet = create_packet(packet_id, data.encode("utf-8"))
                while packet:
                    # The icmp protocol does not use a port, but the function
                    # below expects it, so we just give it a dummy port.
                    sent = self.raw_sock.sendto(packet, (self.var_host.get(), 0))
                    packet = packet[sent:]
            else:
                self.tcp_sock.send(data.encode("utf-8"))
            #self._receive_data(trans_mode)
        except socket.error as e:
            self._insert_text(e.strerror)
            print(e)
        finally:
            time.sleep(float(tcp_interval))
        self.txt_msg.delete('0.0', 'end')

    def _receive_data(self, trans_mode):
        if trans_mode == "tcp":
            pass
            #rev_data = self.tcp_sock.recv(int(self.buffer))
        elif trans_mode == "udp":
            print("udp")
            rev_data, address = self.udp_sock.recvfrom(int(self.buffer))
        elif trans_mode == "raw_socket":
            rev_data, addr = self.raw_sock.recvfrom(int(self.buffer))
            print(rev_data, addr)
        else:
            rev_data = self.tcp_sock.recv(int(self.buffer))
        #self._insert_text(rev_data, trans_mode)

    def _insert_text(self, data, trans_mode="na"):
        if trans_mode == "na":
            self.txt_rev_msg.insert(END, data)
        elif trans_mode != "raw_socket":
            self.txt_rev_msg.insert(END, data.decode("utf-8"))
        else:
            self.txt_rev_msg.insert(END, "Raw socket Msg: {}".format(str(data)))
        self.txt_rev_msg.insert(END, "\n")
        self.txt_rev_msg.update()

    def close_window(self):
        ans = askyesno(title='Confirm', message='Close the window?')
        if ans:
            self.window.destroy()
            if self.tcp_sock and "closed" not in str(self.tcp_sock):
                self.tcp_sock.shutdown(2)
                self.tcp_sock.close()
            if self.udp_sock and "closed" not in str(self.udp_sock):
                self.udp_sock.close()
        else:
            return


if __name__ == "__main__":
    Client()
    pass
