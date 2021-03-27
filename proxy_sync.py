#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket, threading, re, select, struct
import sni_helper

TIME_OUT_ERR = socket.timeout
def recv(socket, bufferSize=1024):
    try:
        return socket.recv(bufferSize)
    except TIME_OUT_ERR: # socket.timeout changes into a number when timeout is set
        if not stop:
            return recv(socket, bufferSize)
            
def socket_handler(clientSock, addr):
    clientSock.settimeout(5)
    data = recv(clientSock)
    if not data:
        return
    is_https_proxy = False; is_socks5_proxy = False
    if data == b'\x05\x01\x00':
        try:
            # 1. no auth https://tools.ietf.org/html/rfc1928#page-3
            clientSock.send(b"\x05\x00")
            # 2. https://tools.ietf.org/html/rfc1928#page-4
            data = recv(clientSock, 4)
            mode = data[1]
            addrtype = data[3]
            # 3. reply https://tools.ietf.org/html/rfc1928#page-5
            # Command not support          b"\x05\x07\x00\x01"
            # Address type not supported   b"\x05\x08\x00\x01"
            # Connection refused           b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
            if mode == 1:  # 1. Tcp connect
                # print('addrtype', addrtype)
                if addrtype == 1:       # IPv4
                    sni = socket.inet_ntoa(recv(clientSock, 4))
                elif addrtype == 3:     # Domain name
                    addr_len = recv(clientSock, 1)[0]
                    sni = recv(clientSock, addr_len)
                port = struct.unpack('>H', recv(clientSock, 2))[0]
                # 构建回复
                reply = b"\x05\x00\x00\x01"
                is_socks5_proxy = True
            else:
                clientSock.send(b"\x05\x07\x00\x01")
        except Exception as e:
            print(e)
            clientSock.close()
            return
    elif data.startswith(b'CONNECT'):
        head = data.decode('latin1')
        search = re.search(r'^CONNECT ([^:]+)(?::([0-9]+))? HTTP[0-9/\.]+\r\n', head)
        if search:
            sni = search.group(1)
            port = int(search.group(2)) if search.group(2) else 443
            is_https_proxy = True
    elif data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"PUT ") or data.startswith(b"DELETE ") or data.startswith(b"OPTIONS ") or data.startswith(b"UPDATE "):
        head = data.decode('latin1')
        search = re.search(r'\r\nHost: ([^:]+)(?::([0-9]+))?\r\n', head)
        if search:
            sni = search.group(1)
            port = int(search.group(2)) if search.group(2) else 80
    else:
        sni = sni_helper.GetSniFromSslPlainText(data)
        port = 443
        
    if 'sni' not in locals():
        print('sni not found')
        return
    #print('Accept new connection from %s:%s...' % addr)
    print('Establishing new connection to %s:%d' %(sni, port))
    
    try:
        serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #serverSock.connect((sni, port))
        serverSock.connect((getHost(sni), port))
        if is_https_proxy:
            clientSock.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        elif is_socks5_proxy:
            local_host, local_port = serverSock.getsockname()
            reply += socket.inet_aton(local_host) + struct.pack(">H", local_port)
            clientSock.send(reply)
        else:
            serverSock.send(data)
        serverSock.settimeout(5)
        '''
        t1 = threading.Thread(target=fromTo, args=(clientSock, serverSock), name='thread-%s-toServer'%sni)
        t2 = threading.Thread(target=fromTo, args=(serverSock, clientSock), name='thread-%s-toClient'%sni)
        t1.start(); t2.start(); #t1.join(); t2.join()
        '''
        fdset = [clientSock, serverSock]
        while not stop:
            r, w, e = select.select(fdset, [], [], 5)
            if clientSock in r:
                if serverSock.send(clientSock.recv(1024)) <= 0: break
            if serverSock in r:
                if clientSock.send(serverSock.recv(1024)) <= 0: break
    except Exception as e:
        pass
    finally:
        print(f'{sni} connection closed')
        clientSock.close()
        serverSock.close()

def getHost(sni):
    host = hosts.get(sni, sni)
    return host
def fromTo(fromSock, toSock):
    try:
        data = recv(fromSock)
        while data and not stop:
            toSock.send(data)
            data = recv(fromSock)
    except:
        pass
    finally:
        fromSock.close()
        toSock.close()

def startServer(port: int = 443, maxLink = 5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen(maxLink)
    s.settimeout(5.0)
    #print('Waiting for connection...')
    print(f'Serving on {s.getsockname()}')
    while not stop:
        try:
            sock, addr = s.accept()
            t = threading.Thread(target=socket_handler, args=(sock, addr), name='thread-dealSocket %s:%s'%addr)
            t.start()
        except socket.timeout as e:
            pass


stop = False
hosts = {
    "www.baidu.com":"14.215.177.38",
}
if __name__ == '__main__':
    threadServer = threading.Thread(target=startServer, args=(443, 5), name='thread-startServer')
    threadServer.start()

    try:
        input('Enter any key to stop.\r\n')
    finally:
        stop = True