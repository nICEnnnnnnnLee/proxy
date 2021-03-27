#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio, sys, re, socket, struct
import sni_helper

async def socket_handler(client_reader, client_writer):
    checkTasks()
    data = await client_reader.read(1024)
    if not data:
        return
    #addr = writer.get_extra_info('peername')
    is_https_proxy = False; is_socks5_proxy = False

    if data == b'\x05\x01\x00':
        try:
            # 1. no auth https://tools.ietf.org/html/rfc1928#page-3
            client_writer.write(b"\x05\x00")
            await client_writer.drain()
            # 2. https://tools.ietf.org/html/rfc1928#page-4
            data = await client_reader.readexactly(4)
            mode = data[1]
            addrtype = data[3]
            # 3. reply https://tools.ietf.org/html/rfc1928#page-5
            # Command not support          b"\x05\x07\x00\x01"
            # Address type not supported   b"\x05\x08\x00\x01"
            # Connection refused           b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
            if mode == 1:  # 1. Tcp connect
                # print('addrtype', addrtype)
                if addrtype == 1:       # IPv4
                    host = socket.inet_ntoa(await client_reader.readexactly(4))
                elif addrtype == 3:     # Domain name
                    addr_len = await client_reader.readexactly(1)[0]
                    host = await client_reader.readexactly(addr_len)
                port = struct.unpack('>H', await client_reader.readexactly(2))[0]
                # 构建回复
                reply = b"\x05\x00\x00\x01"
                is_socks5_proxy = True
            else:
                client_writer.write(b"\x05\x07\x00\x01")  # Command not supported
                await client_writer.drain()
        except:
            client_writer.close()
            return
    elif data.startswith(b'CONNECT'):
        head = data.decode('latin1')
        search = re.search(r'^CONNECT ([^:]+)(?::([0-9]+))? HTTP[0-9/\.]+\r\n', head)
        if search:
            host = search.group(1)
            port = int(search.group(2)) if search.group(2) else 443
            is_https_proxy = True
    elif data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"PUT ") or data.startswith(b"DELETE ") or data.startswith(b"OPTIONS ") or data.startswith(b"UPDATE "):
        head = data.decode('latin1')
        search = re.search(r'\r\nHost: ([^:]+)(?::([0-9]+))?\r\n', head)
        if search:
            host = search.group(1)
            port = int(search.group(2)) if search.group(2) else 80
    else:
        host = sni_helper.GetSniFromSslPlainText(data)
        port = 443
        
    if 'host' not in locals():
        print('host not found')
        return
    server_reader, server_writer = await asyncio.open_connection(getHost(host), port)
    if is_https_proxy:
        client_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    elif is_socks5_proxy:
        local_host, local_port = server_writer.get_extra_info('sockname')
        reply += socket.inet_aton(local_host) + struct.pack(">H", local_port)
        client_writer.write(reply)
    else:
        server_writer.write(data)
    # use this if you wanna keep the connetion alive util the client/server close it
    #task = asyncio.create_task(pip(client_reader, server_writer))
    # close the connection if it lives for 2 min
    task = asyncio.create_task(asyncio.wait_for(pip(client_reader, server_writer), timeout=120.0))
    tasks.append(task)
    task = asyncio.create_task(pip(server_reader, client_writer))
    tasks.append(task)
    
async def pip(from_reader, to_writer):
    try:
        await to_writer.drain()
        data = await from_reader.read(1024)
        while data:
            to_writer.write(data)
            await to_writer.drain()
            data = await from_reader.read(1024)
    except:
        pass
    finally:
        if not to_writer.is_closing():
            to_writer.close()
            await to_writer.wait_closed()

async def serve_forever(server):
    try:
        async with server:
            await server.serve_forever()
    except:
        pass

async def main():
    server = await asyncio.start_server(
        socket_handler, '0.0.0.0', 443)
    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')
    task = asyncio.create_task(serve_forever(server))
    tasks.append(task)
    loop = asyncio.get_event_loop()
    inp = await loop.run_in_executor(None, input, 'Enter anything to stop.\r\n')
    for task in tasks:
        task.cancel()

def getHost(sni):
    host = hosts.get(sni, sni)
    return host
def checkTasks():
    if len(tasks) >= 30:
        for task in tasks:
            if  task.done():
                tasks.remove(task)
hosts = {
    "www.baidu.com":"14.215.177.38",
}
tasks = []
if __name__ == '__main__':
    asyncio.run(main())