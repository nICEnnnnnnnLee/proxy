# proxy
## WHAT  
A proxy demo that surport HTTP, HTTPS and SNI proxy.   
NO extra dependency.
    
## HOW  
+ Just run it.  
```
$ python proxy_async.py
or 
$ python proxy_sync.py
```
+ There's nothing to talk about `HTTP` or `HTTPS` proxy.  
+ For `SNI` proxy, let the HTTPS domain directs to the ip of proxy server, and the proxy serves.  
    e.g. suppose a proxy runs on a machine which binds ip `192.168.0.1`,   
        and you insert an DNS record `192.168.0.1 www.baidu.com` into host file in the client PC,   
        then you can visit `https://www.baidu.com` in the browser via a proxy.  
+ There's two version of implements, the sync one may support more widely since the async one uses `asyncio`.   