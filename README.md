# tiny-vpn – Simple SOCKS5 Server in Python

This project contains a tiny, basic SOCKS5 proxy server written in Python 3.6+.  
It follows the SOCKS5 protocol as described in [RFC 1928] and is intended as a learning example for how SOCKS works internally.

> Note: This is an educational implementation, not a production-ready VPN/proxy.

---

## Introduction

[SOCKS](https://en.wikipedia.org/wiki/SOCKS) is a generic proxy protocol that relays TCP connections from one point to another through an intermediate server (the SOCKS server).

Originally, SOCKS proxies were mostly used as [circuit-level](https://en.wikipedia.org/wiki/Circuit-level_gateway) gateways, acting as a firewall between local and external resources (the internet). Today, they’re also popular for:

- Censorship circumvention  
- Web scraping  
- General-purpose tunneling of TCP connections

This implementation focuses on the [SOCKS5](https://www.ietf.org/rfc/rfc1928.txt) version of the protocol and the `CONNECT` command (TCP connections only).

---

## How It Works (High Level)

The SOCKS5 protocol is layered on top of TCP. For each remote server a client wants to talk to, it opens a **separate TCP connection** to the SOCKS server.

The flow is:

1. **TCP connection**: Client connects to the SOCKS server.
2. **Method negotiation**: Client sends supported authentication methods; server chooses one.
3. **Authentication**: Client sends credentials (username/password).
4. **Request**: Client specifies command (`CONNECT`) and target address/port.
5. **Server connects**: SOCKS server connects to the remote host.
6. **Data exchange**: Server relays data between client and remote host in both directions.

---

## TCP Session Handling

I use Python’s built-in [socketserver](https://docs.python.org/3/library/socketserver.html) module to handle TCP sessions in a threaded manner:

```python
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):

    def handle(self):
        # Main SOCKS logic goes here
        pass


if __name__ == '__main__':
    with ThreadingTCPServer(('127.0.0.1', 9011), SocksProxy) as server:
        server.serve_forever()
```

Here the `ThreadingTCPServer` creates a threading version of TCP server and listens for incoming connections on a specified address and port. Every time there is a new incoming TCP connection (session) the server spawns a new thread with `SocksProxy` instance running inside it. It gives us an easy way to handle concurrent connections.

The `ThreadingMixIn` can be replaced by `ForkingTCPServer`, which uses *forking* approach, that is, it spawns a new process for each TCP session.

## Connection establishment and negotiation

When a client establishes a TCP session to the SOCKS server, it must send a greeting message.

The message consists of 3 fields:

| Version | nmethods | methods |
| :-------------------:| :--------------------: | :--------------------: |
| 1 byte            | 1 byte                | 0 to 255 bytes      |


Here `version` field represents a version of the protocol, which equals to 5 in our case. The `nmethods` field contains the number of authentication methods supported by the client. The `methods` field consists of a sequence of supported method by the client. Thus the `methods` field indicates the length of a `methods` sequence.

According to the RFC 1928, the supported values of methods field defined as follows:

| Code | Message |
| :---: | :---: |
| `X'00'` | NO AUTHENTICATION REQUIRED | 
| `X'01'` | GSSAPI | 
| `X'02'` | USERNAME/PASSWORD |
| `X'03'` | to X'7F' IANA ASSIGNED | 
| `X'80'` | to X'FE' RESERVED FOR PRIVATE METHODS |
| `X'FF'` | NO ACCEPTABLE METHODS | 


When the SOCKS server receives such message, it should choose an appropriate method and answer back. Let's pretend I only support a `USERNAME/PASSWORD` method.

The format of the answer looks as follows:

| version | method |
| :---: | :---: |
| 1 byte | 1 byte |

Here is how the whole process looks in Python:

```python
def handle(self):
    # Greeting header: read and unpack 2 bytes
    header = self.connection.recv(2)
    version, nmethods = struct.unpack("!BB", header)

    assert version == SOCKS_VERSION
    assert nmethods > 0

    # Read methods
    methods = self.get_available_methods(nmethods)

    # Accept only USERNAME/PASSWORD auth (0x02)
    if 2 not in set(methods):
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0xFF))
        self.server.close_request(self.request)
        return

    # Send server choice
    self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))


def get_available_methods(self, n):
    methods = []
    for _ in range(n):
        methods.append(ord(self.connection.recv(1)))
    return methods

```

Here the [recv](https://docs.python.org/2/library/socket.html#socket.socket.recv) function reads $n$ bytes from the client and the [struct](https://docs.python.org/2/library/struct.html#struct.pack) module helps to pack and unpack binary data using specified format.

Once the client has received the server choice, it responds with username and password credentials.

| version | usr_len | usr_name | pwd_len | passwd |
| :-------------------:| :--------------------: | :--------------------: | :---: | :---: |
| 1 byte            | 1 byte                | 0 to 255 bytes      | 1 byte | 0 to 255 bytes |

The `version` field represents the authentication version, which is equals to 1 in our case. The `usr_len` and `pwd_len` fields represent lengths of text fields so the server knows how much data it should read from the client.

The server response should look as follows:

| version | status |
| :---: | :---: |
| 1 byte | 1 byte |

The `status` field of 0 indicates a successful authorization, while other values treated as a failure.

Python version of authorization looks as follows:

```python 
def verify_credentials(self):
    version = ord(self.connection.recv(1))
    assert version == 1

    username_len = ord(self.connection.recv(1))
    username = self.connection.recv(username_len).decode('utf-8')

    password_len = ord(self.connection.recv(1))
    password = self.connection.recv(password_len).decode('utf-8')

    if username == self.username and password == self.password:
        # Success, status = 0
        response = struct.pack("!BB", version, 0)
        self.connection.sendall(response)
        return True


    # Failure, status != 0
    response = struct.pack("!BB", version, 0xFF)
    self.connection.sendall(response)
    self.server.close_request(self.request)
    return False
```

Once the authorization has completed the client can send request details.

| version | cmd | rsv | atyp | dst.addr | dst.port |
| :---:| :---: | :---: |:---:| :---: | :---: |
| 1 byte | 1 byte  | `X'00'` | 1 byte | 4 to 255 bytes | 2 bytes |

- **VER** protocol version: `X'05'`

- **CMD**
    - **CONNECT** `X'01'`
    - **BIND** `X'02'`
    - **UDP ASSOCIATE** `X'03'`

- **ATYP** address type of following address
    - **IPv4** address: `X'01'`
    - **DOMAINNAME**: `X'03'`
    - **IPv6** address: `X'04'`

**DST.ADDR** desired destination address
**DST.PORT** desired destination port in network octet order

The `cmd` field indicates the type of connection. This article is limited to CONNECT method only, which is used for TCP connections. For more details, please read the SOCKS RFC.

If a client sends a domain name, it **should be resolved by the DNS on the server side**. Thus a client has no need for a working DNS server when working with SOCKS.

As soon as server establishes a connection to the desired destination it should reply with a status and remote address.

| version | rep | rsv | atyp | bnd.addr | bnd.port |
| :---:| :---: | :---: |:---:| :---: | :---: |
| 1 byte | 1 byte  | `X'00'` | 1 byte | 4 to 255 bytes | 2 bytes |


- **VER** protocol version: `X'05'`

- **REP** Reply field:

|Code | Message |
| :---: | :---: |
| `X'00'` | succeeded     |
| `X'01'` | general SOCKS server failure      |
| `X'02'` | connection not allowed by ruleset     |
| `X'03'` | Network unreachable       |
| `X'04'` | Host unreachable      |
| `X'05'` | Connection refused        |
| `X'06'` | TTL expired       |
| `X'07'` | Command not supported     |
| `X'08'` | Address type not supported        |
| `X'09'` | to X'FF' unassigned       |

- **ATYP** address type of following address:
    - **IPv4** address:        `X'01'`
    - **DOMAINNAME**:           `X'03'`
    - **IPv6** address:        `X'04'`

- **BND.ADDR** server bound address
- **BND.PORT** server bound port in network octet order

Here is how it looks in Python:

```Python
# client request
version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
assert version == SOCKS_VERSION

if address_type == 1:  # ipv4
    address = socket.inet_ntoa(self.connection.recv(4))
elif address_type == 3:  # domain
    domain_length = ord(self.connection.recv(1)[0])
    address = self.connection.recv(domain_length)

port = struct.unpack('!H', self.rfile.read(2))[0]

# server reply
try:
    if cmd == 1:  # CONNECT
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((address, port))
        bind_address = remote.getsockname()
    else:
        self.server.close_request(self.request)

    addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
    port = bind_address[1]
    reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,
                        addr, port)

except Exception as err:
    # return Connection refused error
    reply = self.generate_failed_reply(address_type, 5)

self.connection.sendall(reply)

# Establish data exchange
if reply[1] == 0 and cmd == 1:
    self.exchange_loop(self.connection, remote)

 self.server.close_request(self.request)

```

If server's reply indicates a success, the client may now start passing the data. In order to work with both client and remote hosts concurrently I can use [select](https://docs.python.org/2/library/select.html#select.select) library which supports select and pool Unix interfaces.

Here is how I can read and resend data in one loop both from client and remote host:

```python 
def exchange_loop(self, client, remote):
    while True:

        # wait until client or remote is available for read
        r, w, e = select.select([client, remote], [], [])

        if client in r:
            data = client.recv(4096)
            if remote.send(data) <= 0:
                break

        if remote in r:
            data = remote.recv(4096)
            if client.send(data) <= 0:
                break
```

Now we can test it using `curl`:

```python
curl -v  --socks5 127.0.0.1:9011 -U username:password https://github.com
```

## Limitations
1. Currently, the proxy doesn't work on **Firefox**, as USERNAME/PASSWORD authentication doesn't support by this browser.