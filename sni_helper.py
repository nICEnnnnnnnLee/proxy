#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct

ProtocolVersionSize = 2
RandomSize = 32

def GetSniFromSslPlainText(sslPlainText: bytes):
    '''
    https://tools.ietf.org/html/rfc6101#section-5.2.1
    struct {
        ContentType type;
        ProtocolVersion version;
        uint16 length;
        opaque fragment[SSLPlaintext.length];
    } SSLPlaintext;
    '''
    ContentTypeOffset = 0
    ProtocolVersionOffset = ContentTypeOffset + 1
    LengthOffset = ProtocolVersionOffset + ProtocolVersionSize
    HandshakeOffset = LengthOffset + 2;
    # SSL v2's ContentType has 0x80 bit set.
    # We do not care about SSL v2 here because it does not support client hello extensions
    if len(sslPlainText) < HandshakeOffset or sslPlainText[ContentTypeOffset] != 0x16 : #Handshake
        print('not SSLv3')
        return None
        
    handshakeLength = struct.unpack_from('>H' ,sslPlainText, LengthOffset)[0]
    sslHandshake = sslPlainText[HandshakeOffset:]
    if handshakeLength != len(sslHandshake):
        print('handshakeLength is not right')
        return None
    return GetSniFromSslHandshake(sslHandshake);

def GetSniFromSslHandshake(sslHandshake: bytes):
    '''
    https://tools.ietf.org/html/rfc6101#section-5.6
    struct {
        HandshakeType msg_type;    /* handshake type */
        uint24 length;             /* bytes in message */
        select (HandshakeType) {
            ...
            case client_hello: ClientHello;
            ...
        } body;
    } Handshake;
    '''
    HandshakeTypeOffset = 0;
    ClientHelloLengthOffset = HandshakeTypeOffset + 1;
    ClientHelloOffset = ClientHelloLengthOffset + 3;
    if len(sslHandshake) < ClientHelloOffset or sslHandshake[HandshakeTypeOffset] != 0x01: #ClientHello
        print('not a ClientHello msg')
        return None
    #clientHelloLength = struct.unpack_from('>?????' ,sslHandshake, ClientHelloLengthOffset)[0]
    clientHelloLength = ReadUInt24BigEndian(sslHandshake, ClientHelloLengthOffset)
    clientHello = sslHandshake[ClientHelloOffset:]
    if clientHelloLength != len(clientHello):
        print('clientHelloLength is not right')
        return None

    return GetSniFromClientHello(clientHello);

    
def SkipBytes(data: bytes, numberOfBytesToSkip:int):
        if data and numberOfBytesToSkip < len(data):
            return data[numberOfBytesToSkip:]
        
    
def SkipOpaqueType1(data: bytes):
    '''
    Opaque type is of structure:
      - length (minimum number of bytes to hold the max value)
      - data (length bytes)
    We will only use opaque types which are of max size: 255 (length = 1) or 2^16-1 (length = 2).
    We will call them SkipOpaqueType`length`
    '''
    if data:
        length = data[0]
        totalBytes = 1 + length
        return SkipBytes(data, totalBytes)

def SkipOpaqueType2(data: bytes):
    if data:
        length = struct.unpack_from('>H' ,data, 0)[0]
        totalBytes = 2 + length
        valid = len(data) >= totalBytes;
        if valid:
            return data[totalBytes:]
            
def GetSniFromClientHello(clientHello: bytes):
    '''
    Basic structure: https://tools.ietf.org/html/rfc6101#section-5.6.1.2
    Extended structure: https://tools.ietf.org/html/rfc3546#section-2.1
    struct {
        ProtocolVersion client_version; 2x uint8
        Random random; 32 bytes
        SessionID session_id; opaque type
        CipherSuite cipher_suites<2..2^16-1>; opaque type
        CompressionMethod compression_methods<1..2^8-1>; opaque type
        Extension client_hello_extension_list<0..2^16-1>;
    } ClientHello;
    '''
    p = SkipBytes(clientHello, ProtocolVersionSize + RandomSize);
    # Skip SessionID (max size 32 => size fits in 1 byte)
    p = SkipOpaqueType1(p);
    # Skip cipher suites (max size 2^16-1 => size fits in 2 bytes)
    p = SkipOpaqueType2(p);
    # Skip compression methods (max size 2^8-1 => size fits in 1 byte)
    p = SkipOpaqueType1(p);
    # is invalid structure or no extensions?
    if not p:
        print('invalid structure or no extensions')
        return None

    # client_hello_extension_list (max size 2^16-1 => size fits in 2 bytes)
    extensionListLength = struct.unpack_from('>H' ,p, 0)[0]
    p = SkipBytes(p, 2);
    if extensionListLength != len(p):
        print('extensionListLength is not right: (%d, %d)'%(extensionListLength, len(p)))
        return None
    while p:
        sni, p, invalid = GetSniFromExtension(p)
        if sni:
            return sni
        if invalid:
            return None
    print('sni not found util end')

def GetSniFromExtension(extension: bytes):
    '''
    https://tools.ietf.org/html/rfc3546#section-2.3
    struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension;
    '''
    ExtensionDataOffset = 2 # ushort sizeof(ExtensionType);
    if len(extension) < ExtensionDataOffset:
        return None, None, True
    extensionType = struct.unpack_from('>H' , extension, 0)[0]
    extensionData = extension[ExtensionDataOffset:]
    if extensionType == 0x00: #ExtensionType.ServerName
        sni = GetSniFromServerNameList(extensionData)
        return sni, None, sni == None;
    else:
        remainingBytes = SkipOpaqueType2(extensionData);
        return None, remainingBytes, remainingBytes == None

def GetSniFromServerNameList(serverNameListExtension: bytes):
    '''
    https://tools.ietf.org/html/rfc3546#section-3.1
    struct {
        ServerName server_name_list<1..2^16-1>
    } ServerNameList;
    ServerNameList is an opaque type (length of sufficient size for max data length is prepended)
    '''
    ServerNameListOffset = 2 #sizeof(ushort);
    if len(serverNameListExtension) < 2: # 
        print('invalid serverNameListExtension length')
        return None
    serverNameListLength = struct.unpack_from('>H' , serverNameListExtension, 0)[0]
    serverNameList = serverNameListExtension[ServerNameListOffset:]
    if serverNameListLength > len(serverNameList):
        print('serverNameListExtension length is not right')
        return None

    #remainingBytes = serverNameList.Slice(serverNameListLength);
    serverName = serverNameList[:serverNameListLength]

    return GetSniFromServerName(serverName);

def GetSniFromServerName(serverName: bytes):
    '''
    https://tools.ietf.org/html/rfc3546#section-3.1
    struct {
        NameType name_type;
        select (name_type) {
            case host_name: HostName;
        } name;
    } ServerName;
    ServerName is an opaque type (length of sufficient size for max data length is prepended)
    '''
    ServerNameLengthOffset = 0;
    NameTypeOffset = ServerNameLengthOffset + 2;
    HostNameStructOffset = NameTypeOffset + 1; # HostName = 0x00

    if len(serverName) < HostNameStructOffset:
        print('serverName len is not right')
        return None

    hostNameStructLength = struct.unpack_from('>H' , serverName, 0)[0]  -1
    nameType = serverName[NameTypeOffset]
    hostNameStruct = serverName[HostNameStructOffset:]
    if hostNameStructLength != len(hostNameStruct) or nameType != 0x00:
        print('nameType is not Hostname')
        return None
    return GetSniFromHostNameStruct(hostNameStruct);

    
def GetSniFromHostNameStruct(hostNameStruct: bytes):
    '''
    https://tools.ietf.org/html/rfc3546#section-3.1
    HostName is an opaque type (length of sufficient size for max data length is prepended)
    '''
    HostNameLengthOffset = 0
    HostNameOffset = HostNameLengthOffset + 2 #sizeof(ushort);

    hostNameLength = struct.unpack_from('>H' , hostNameStruct, 0)[0]
    hostName = hostNameStruct[HostNameOffset:]
    if hostNameLength != len(hostName):
        print('hostName len is not valid')
        return None
    return hostName.decode("utf-8")


def ReadUInt24BigEndian(data: bytes, offset: int):
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]