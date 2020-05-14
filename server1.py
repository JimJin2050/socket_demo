# -*- coding=utf-8 -*-
import os
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


class Server(object):
    logger = StreamLogger = logging.getLogger("FileLogger")

    def __init__(self):
        self.tcp_client_sock = None
        self.host = conf_read("config/config.conf", "local", "host")
        self.port = conf_read("config/config.conf", "local", "port")
        self.buffer = conf_read("config/config.conf", "local", "buffer")

        self.target_host = conf_read("config/config.conf", "target", "host")
        self.target_port = conf_read("config/config.conf", "target", "port")

        self.tcp_server_sock = None
        self.udp_server_sock = None
        self.raw_server_sock = None

        self.window = Tk()
        self.window.title("Server")
        self.window.geometry("700x510")
        Label(self.window, text='Host: ').place(x=25, y=30)
        Label(self.window, text='Port: ').place(x=25, y=70)
        Label(self.window, text='Buffer: ').place(x=25, y=110)

        self.var_host = StringVar()
        self.var_host.set(conf_read("config/config.conf", "local", "host"))
        entry_host = Entry(self.window, textvariable=self.var_host)
        entry_host.place(x=140, y=30)
        self.btn_start = Button(
            self.window,
            text='Start Server',
            width=12,
            activeforeground='blue',
            relief=GROOVE,
            command=self.start_server_thread)
        self.btn_start.place(x=350, y=30)

        self.btn_stop = Button(
            self.window,
            text='Stop Server',
            width=12,
            activeforeground='blue',
            relief=GROOVE,
            command=self.stop_server)
        self.btn_stop.place(x=470, y=30)

        self.var_port = StringVar()
        self.var_port.set(conf_read("config/config.conf", "local", "port"))
        entry_port = Entry(self.window, textvariable=self.var_port)
        entry_port.place(x=140, y=70)
        self.var_buffer = StringVar()
        self.var_buffer.set(conf_read("config/config.conf", "local", "buffer"))
        entry_buffer = Entry(self.window, textvariable=self.var_buffer)
        entry_buffer.place(x=140, y=110)

        self.var_trans_mode = StringVar()
        Label(self.window, text='Transmission mode').place(x=400, y=65)

        r1 = Radiobutton(
            self.window,
            text='TCP',
            variable=self.var_trans_mode,
            activeforeground='blue',
            value='tcp')
        r1.place(x=400, y=85)
        r1.select()
        Radiobutton(
            self.window,
            text='UDP',
            variable=self.var_trans_mode,
            activeforeground='blue',
            value='udp').place(x=400, y=105)

        Label(self.window, text='Received msg: ').place(x=25, y=150)

        self.txt_rev_msg = ScrolledText(
            self.window,
            height=10,
            bd=2,
            relief='groove',
            wrap=CHAR,
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

    def start_server_thread(self):
        t = threading.Thread(target=self.start_server, args=())
        t.setDaemon(True)
        t.start()

    def send_msg(self):
        trans_mode = self.var_trans_mode.get()
        data = self.txt_msg.get("0.0", "end")
        self.btn_send.config({"state": "disabled"})

        try:
            if trans_mode == "udp":
                udp_interval = conf_read("config/config.conf", "udp", "interval")
                self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.udp_sock.sendto(
                    data.encode("utf-8"),
                    (self.target_host, int(self.target_port)))
                time.sleep(float(udp_interval))
            elif trans_mode == "tcp":
                tcp_interval = conf_read("config/config.conf", "tcp", "interval")
                self.tcp_client_sock.send(data.encode("utf-8"))
                time.sleep(float(tcp_interval))
            elif trans_mode == "raw_socket":
                self.send_raw_msg(self.target_host, data.encode("utf-8"))
            else:
                pass
        except socket.error as e:
            self._insert_text(e.strerror)
        self.txt_msg.delete('0.0', 'end')
        self.btn_send.config({"state": "normal"})

    def _start_tcp_server(self, addr):
        try:
            self.tcp_server_sock.bind(addr)
            self.tcp_server_sock.listen(5)
            self.receive_data("Waiting TCP connection......\n")
            while True:
                accept = conf_read("config/config.conf", "tcp", "accept") == "1"
                if accept:
                    self.tcp_client_sock, addr = self.tcp_server_sock.accept()
                self.receive_data("Receive TCP connection: {}\n".format(addr))
                self.tcp_client_sock.send('TCP Connection created successfully'.encode("utf-8"))
                while True:
                    rev_data = self.tcp_client_sock.recv(int(self.buffer))
                    if not rev_data:
                        break
                    self.receive_data(rev_data.decode("utf-8"))
                    #self.tcp_client_sock.send('[{}]-TCP: {}'.format(ctime(), rev_data).encode("utf-8"))
                self.tcp_client_sock.close()
        except socket.error as e:
            self._insert_text(e.strerror)
            print(e)
        finally:
            pass

    def _start_udp_server(self, addr):
        try:
            self.udp_server_sock.bind(addr)
            self.receive_data("Waiting UDP Message/connection......\n")
            while True:
                rev_data, address = self.udp_server_sock.recvfrom(int(self.buffer))
                print(rev_data)
                if not rev_data:
                    break
                self.receive_data(rev_data.decode("utf-8"))
                self.udp_server_sock.sendto(
                    '[{}] - UDP: {}'.format(ctime(), rev_data).encode("utf-8"),
                    address)
            self.udp_server_sock.close()
        except socket.error as e:
            self._insert_text(e.strerror)
            print(e)
        finally:
            pass

    def _start_raw_server(self, host_ip):
        if os.name == "nt":
            protocol = socket.IPPROTO_IP
        else:
            protocol = socket.IPPROTO_ICMP
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        except socket.error as e:
            print(e.strerror)
            raise
        my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        my_socket.bind((host_ip, 0))
        self.receive_data("Waiting RAW socket message......\n")
        while True:
            rec_packet, addr = my_socket.recvfrom(1024)
            print(rec_packet)
            msg = rec_packet[-192:].decode("utf-8").strip("@")
            self.receive_data("Raw socket msg: {}\n".format(msg))
            if not rec_packet:
                break

    def send_raw_msg(self, dest_addr, data, packet_id=None):
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            packet_id = packet_id if packet_id else random.randint(0, 0xffff)
            packet = create_packet(packet_id, data)
            while packet:
                sent = my_socket.sendto(packet, (dest_addr, 1))
                packet = packet[sent:]
            rec_packet, addr = my_socket.recvfrom(1024)
            self._insert_text(rec_packet, "raw_socket")
            my_socket.close()
        except socket.error as e:
            self._insert_text(e.strerror)
            print(e.strerror)
            raise

    def _insert_text(self, data, trans_mode="na"):
        if trans_mode != "raw_socket":
            data = data if isinstance(data, str) else data.decode("utf-8", "ignore")
            self.txt_rev_msg.insert(END, data)
        else:
            self.txt_rev_msg.insert(END, "Raw socket Msg: {}".format(str(data)))
        self.txt_rev_msg.insert(END, "\n")
        self.txt_rev_msg.update()

    def start_server(self):
        self.btn_start.config({"state": "disabled"})
        trans_mode = self.var_trans_mode.get()
        addr = (self.var_host.get(), int(self.var_port.get()))
        recv_buffer = int(conf_read("config/config.conf", "udp", "recv_buffer"))
        send_buffer = int(conf_read("config/config.conf", "udp", "send_buffer"))
        try:
            if trans_mode == "tcp":
                self.tcp_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.tcp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._start_tcp_server(addr)
            elif trans_mode == "udp":
                self.udp_server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.udp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buffer)
                self.udp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buffer)
                self._start_udp_server(addr)
            elif trans_mode == "raw_socket":
                self._start_raw_server(self.host)
            else:
                self.tcp_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.tcp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._start_tcp_server(addr)
        except socket.error as e:
            self._insert_text(e.strerror)

        self.btn_start.config({"state": "normal"})

    def stop_server(self):
        if self.tcp_client_sock:
            if "closed" not in str(self.tcp_client_sock):
                self.tcp_client_sock.close()
        if self.tcp_server_sock:
            if "closed" not in str(self.tcp_server_sock):
                self.tcp_server_sock.close()
        if self.udp_server_sock:
            if "closed" not in str(self.udp_server_sock):
                #self.udp_server_sock.close()
                pass
        self.window.destroy()

    def receive_data(self, msg):
        self.txt_rev_msg.insert(END, "Receive msg: {}".format(msg))
        self.txt_rev_msg.update()

    def close_window(self):
        ans = askyesno(title='Confirm', message='Close the window?')
        if ans:
            self.stop_server()
        else:
            return


if __name__ == "__main__":
    Server()
    pass
