# NOTE: Adapted from https://github.com/rushter/socks5

import select
import socket
import struct
import logging
import traceback
import random
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

log = logging.getLogger("trevorproxy.socks")
SOCKS_VERSION = 5


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    def __init__(self, *args, **kwargs):
        self.username = kwargs.pop("auth_username", "")
        self.password = kwargs.pop("auth_password", "")
        self.proxy = kwargs.pop("proxy")
        self.allow_reuse_address = True
        super().__init__(*args, **kwargs)


class ThreadingTCPServer6(ThreadingTCPServer):
    address_family = socket.AF_INET6


class SocksProxy(StreamRequestHandler):
    def handle(self):
        log.debug("Accepting connection from %s:%s", *self.client_address[:2])

        # greeting header
        try:
            # read and unpack 2 bytes from a client
            header = self.connection.recv(2)
            version, nmethods = struct.unpack("!BB", header)

            # socks 5
            assert version == SOCKS_VERSION
            assert nmethods > 0

            # get available methods
            methods = self.get_available_methods(nmethods)

            if 2 not in set(methods):  # If authentication is not offered
                log.error("Client doesn't support username/password authentication")
                # Send no acceptable methods
                response = struct.pack("!BB", SOCKS_VERSION, 0xFF)
                self.connection.sendall(response)
                return

            if not self.verify_credentials(methods):
                return

        except Exception as e:
            if log.level <= logging.DEBUG:
                e = traceback.format_exc()
            log.error(f"Error in greeting: {e}")
            return

        # request
        try:
            version, cmd, _, address_type = struct.unpack(
                "!BBBB", self.connection.recv(4)
            )
            assert version == SOCKS_VERSION

            address = None
            # Determine address family based on the chosen subnet
            random_subnet = random.choice(self.server.proxy.subnets)
            self.address_family = (
                socket.AF_INET6
                if random_subnet.version == 6
                else socket.AF_INET
            )

            if address_type == 1:  # IPv4
                log.debug("Address type == IPv4")
                address = socket.inet_ntop(socket.AF_INET, self.connection.recv(4))
                self.address_family = socket.AF_INET

            if address_type == 4:  # IPv6
                log.debug("Address type == IPv6")
                address = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
                self.address_family = socket.AF_INET6

            elif address_type == 3:  # Domain name
                log.debug(f"Address type == domain name")
                domain_length = self.connection.recv(1)[0]
                domain = self.connection.recv(domain_length)
                if random_subnet.version == 6: # Use randomly chosen subnet for resolution order
                    resolve_order = [socket.AF_INET6, socket.AF_INET]
                else:
                    resolve_order = [socket.AF_INET, socket.AF_INET6]
                for family in resolve_order:
                    try:
                        log.debug(f"Trying to resolve {domain} via {str(family)}")
                        address = socket.getaddrinfo(domain, 0, family)[0][-1][0]
                        self.address_family = family
                        log.debug(
                            f"Successfully resolved {domain} to {address} via {str(family)}"
                        )
                        break
                    except Exception as e:
                        log.debug(f"Failed to resolve {domain} via {str(family)}")
                        continue
                if address is None:
                    log.error(f"Could not resolve hostname {address}")
                    return
            log.debug(f"Destination address: {address}")
            port = struct.unpack("!H", self.connection.recv(2))[0]

        except Exception as e:
            if log.level <= logging.DEBUG:
                e = traceback.format_exc()
            log.error(f"Error in request: {e}")
            return

        # reply
        try:
            if cmd == 1:  # CONNECT
                # Select a random subnet and its corresponding generator
                random_subnet = random.choice(self.server.proxy.subnets)
                random_ipgen_index = self.server.proxy.subnets.index(random_subnet)
                random_ipgen = self.server.proxy.ipgens[random_ipgen_index]
                subnet_family = (
                    socket.AF_INET
                    if random_subnet.version == 4
                    else socket.AF_INET6
                )
                remote = socket.socket(self.address_family, socket.SOCK_STREAM)

                # if the IP families match, then randomize source address
                if subnet_family == self.address_family:
                    log.debug(
                        f"{str(self.address_family)} matches address family ({subnet_family}), randomizing source address"
                    )
                    random_source_addr = str(next(random_ipgen))
                    log.info(f"Using random source address: {random_source_addr}")

                    # special case for IPv6
                    if self.address_family == socket.AF_INET6:
                        remote.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

                    remote.bind((random_source_addr, 0))

                # otherwise, passthrough
                else:
                    log.warning(
                        f"{str(self.address_family)} does not match that of subnet ({str(subnet_family)}), source IP randomization is impossible."
                    )

                remote.connect((address, port))
                bind_address = remote.getsockname()
                log.debug(f"Connected to {address}:{port}")
            else:
                self.server.close_request(self.request)

            addr_format = "I" if self.address_family == socket.AF_INET else "IIII"
            addr, port = bind_address[:2]
            reply = struct.pack(f"!BBBBIH", SOCKS_VERSION, 0, 0, 1, address_type, port)

        except Exception as e:
            if log.level <= logging.DEBUG:
                e = traceback.format_exc()
            log.error(f"Error in reply: {e}")
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)
            return

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self, methods):
        # Envoi de la méthode d'authentification choisie (2 = username/password)
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

        try:
            version = ord(self.connection.recv(1))
            assert version == 1  # Version du sous-protocole d'authentification

            username_len = ord(self.connection.recv(1))
            username = self.connection.recv(username_len).decode("utf-8")

            password_len = ord(self.connection.recv(1))
            password = self.connection.recv(password_len).decode("utf-8")

            # Vérification des credentials
            if username == self.server.username and password == self.server.password:
                # Authentification réussie
                log.debug(f"Successful authentication for user: {username}")
                response = struct.pack("!BB", version, 0)
                self.connection.sendall(response)
                return True
            else:
                # Authentification échouée
                log.error(f"Failed authentication attempt for user: {username}")
                response = struct.pack("!BB", version, 0xFF)
                self.connection.sendall(response)
                self.server.close_request(self.request)
                return False

        except Exception as e:
            log.error(f"Authentication error: {str(e)}")
            if version:
                response = struct.pack("!BB", version, 0xFF)
            else:
                response = struct.pack("!BB", SOCKS_VERSION, 0xFF)
            self.connection.sendall(response)
            return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack(
            "!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0
        )

    def exchange_loop(self, client, remote):
        while 1:
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
