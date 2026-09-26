                                                                            
import ipaddress
import socket

HOST = 'apitest.zulaoyun.com'


def verify_remote_client_route(server, *, resolver=None):
    address = ipaddress.ip_address(server)
    if address.version != 4 or int(address) >> 24 == 0 or int(address) >> 24 >= 224:
        raise ValueError('Remote server must be an explicit unicast IPv4 address')
    try:
        records = (resolver or socket.getaddrinfo)(HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
        addresses = {row[4][0] for row in records if row[0] == socket.AF_INET}
    except (OSError, IndexError, TypeError):
        raise ValueError('Remote API name could not be resolved; use Zula-Baslat.bat --server') from None
    if addresses != {str(address)}:
        raise ValueError('Remote API hosts mapping differs from selected server; use Zula-Baslat.bat --server')
    return str(address)
