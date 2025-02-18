# NOTE: Adapted from https://github.com/rushter/socks5

import select
import socket
import struct
import logging
import traceback
import random
import threading
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

log = logging.getLogger("trevorproxy.socks")
SOCKS_VERSION = 5

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    def __init__(self, *args, **kwargs):
        self.username = kwargs.pop("auth_username", "")
        self.password = kwargs.pop("auth_password", "")
        self.proxy = kwargs.pop("proxy")
        self.allow_reuse_address = True
        # Compteur de connexions actives et verrou associé
        self.active_connections = 0
        self.active_lock = threading.Lock()
        super().__init__(*args, **kwargs)

class ThreadingTCPServer6(ThreadingTCPServer):
    address_family = socket.AF_INET6

class SocksProxy(StreamRequestHandler):
    def handle(self):
        log.debug("Accepting connection from %s:%s", *self.client_address[:2])
        remote = None
        try:
            # Incrémenter le compteur de connexions actives
            with self.server.active_lock:
                self.server.active_connections += 1
                log.debug("Active connections: %d", self.server.active_connections)

            # --- Greeting Header ---
            header = self.connection.recv(2)
            version, nmethods = struct.unpack("!BB", header)
            assert version == SOCKS_VERSION
            assert nmethods > 0

            methods = self.get_available_methods(nmethods)
            if 2 not in set(methods):
                log.error("Client doesn't support username/password authentication")
                response = struct.pack("!BB", SOCKS_VERSION, 0xFF)
                self.safe_sendall(self.connection, response, "client")
                return

            if not self.verify_credentials(methods):
                return

            # --- Request ---
            request = self.connection.recv(4)
            version, cmd, _, address_type = struct.unpack("!BBBB", request)
            assert version == SOCKS_VERSION

            address = None
            random_subnet = random.choice(self.server.proxy.subnets)
            self.address_family = socket.AF_INET6 if random_subnet.version == 6 else socket.AF_INET

            if address_type == 1:  # IPv4
                log.debug("Address type == IPv4")
                addr_bytes = self.connection.recv(4)
                address = socket.inet_ntop(socket.AF_INET, addr_bytes)
                self.address_family = socket.AF_INET
            elif address_type == 4:  # IPv6
                log.debug("Address type == IPv6")
                addr_bytes = self.connection.recv(16)
                address = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                self.address_family = socket.AF_INET6
            elif address_type == 3:  # Domain name
                log.debug("Address type == domain name")
                domain_length = self.connection.recv(1)[0]
                domain = self.connection.recv(domain_length)
                if random_subnet.version == 6:
                    resolve_order = [socket.AF_INET6, socket.AF_INET]
                else:
                    resolve_order = [socket.AF_INET, socket.AF_INET6]
                for family in resolve_order:
                    try:
                        log.debug("Trying to resolve domain via %s", str(family))
                        address = socket.getaddrinfo(domain, 0, family)[0][-1][0]
                        self.address_family = family
                        log.debug("Successfully resolved domain to %s via %s", address, str(family))
                        break
                    except Exception as e:
                        log.debug("Failed to resolve domain via %s", str(family))
                        continue
                if address is None:
                    log.error("Could not resolve hostname %s", domain)
                    return

            log.debug("Destination address: %s", address)
            port_bytes = self.connection.recv(2)
            port = struct.unpack("!H", port_bytes)[0]

            # --- Reply and Remote Connection ---
            if cmd == 1:  # CONNECT
                random_subnet = random.choice(self.server.proxy.subnets)
                random_ipgen_index = self.server.proxy.subnets.index(random_subnet)
                random_ipgen = self.server.proxy.ipgens[random_ipgen_index]
                subnet_family = socket.AF_INET if random_subnet.version == 4 else socket.AF_INET6

                remote = socket.socket(self.address_family, socket.SOCK_STREAM)
                remote.settimeout(30)  # Timeout de 30 secondes d'inactivité

                if subnet_family == self.address_family:
                    log.debug("%s matches subnet family %s, randomizing source address", str(self.address_family), str(subnet_family))
                    random_source_addr = str(next(random_ipgen))
                    log.info("Using random source address: %s", random_source_addr)
                    if self.address_family == socket.AF_INET6:
                        remote.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
                    remote.bind((random_source_addr, 0))
                else:
                    log.warning("%s does not match subnet family %s; source IP randomization is impossible.", str(self.address_family), str(subnet_family))

                try:
                    remote.connect((address, port))
                except Exception as e:
                    log.error("Failed to connect to %s:%s : %s", address, port, e)
                    reply = self.generate_failed_reply(address_type, 5)
                    self.safe_sendall(self.connection, reply, "client")
                    return

                bind_address = remote.getsockname()
                log.debug("Connected to %s:%s", address, port)

                # Construction de la réponse SOCKS5 avec l'adresse du proxy (BND.ADDR et BND.PORT)
                proxy_ip = bind_address[0]
                proxy_port = bind_address[1]
                if self.address_family == socket.AF_INET:
                    reply_atyp = 1
                    addr_bin = socket.inet_aton(proxy_ip)
                else:
                    reply_atyp = 4
                    addr_bin = socket.inet_pton(socket.AF_INET6, proxy_ip)
                reply = struct.pack("!BBBB", SOCKS_VERSION, 0, 0, reply_atyp) + addr_bin + struct.pack("!H", proxy_port)
            else:
                self.server.close_request(self.request)
                return

            self.safe_sendall(self.connection, reply, "client")

            # --- Data Exchange ---
            if reply[1] == 0 and cmd == 1:
                self.exchange_loop(self.connection, remote)

        except Exception as e:
            log.error("Error in handle: %s", traceback.format_exc())
        finally:
            if remote:
                self.close_socket(remote, "remote")
            self.close_socket(self.connection, "client")
            # Décrémenter le compteur de connexions actives
            with self.server.active_lock:
                self.server.active_connections -= 1
                log.debug("Active connections: %d", self.server.active_connections)
            self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            byte = self.connection.recv(1)
            if byte:
                methods.append(ord(byte))
        return methods

    def verify_credentials(self, methods):
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))
        try:
            version_byte = self.connection.recv(1)
            if not version_byte:
                return False
            version = ord(version_byte)
            assert version == 1  # Version du sous-protocole d'authentification
            username_len = ord(self.connection.recv(1))
            username = self.connection.recv(username_len).decode("utf-8")
            password_len = ord(self.connection.recv(1))
            password = self.connection.recv(password_len).decode("utf-8")
            if username == self.server.username and password == self.server.password:
                log.debug("Successful authentication for user: %s", username)
                response = struct.pack("!BB", version, 0)
                self.safe_sendall(self.connection, response, "client")
                return True
            else:
                log.error("Failed authentication attempt for user: %s", username)
                response = struct.pack("!BB", version, 0xFF)
                self.safe_sendall(self.connection, response, "client")
                self.server.close_request(self.request)
                return False
        except Exception as e:
            log.error("Authentication error: %s", str(e))
            try:
                response = struct.pack("!BB", SOCKS_VERSION, 0xFF)
                self.safe_sendall(self.connection, response, "client")
            except Exception:
                pass
            return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):
        try:
            while True:
                r, _, _ = select.select([client, remote], [], [])
                if client in r:
                    data = client.recv(4096)
                    if not data:
                        break
                    if not self.safe_sendall(remote, data, "remote"):
                        break
                if remote in r:
                    data = remote.recv(4096)
                    if not data:
                        break
                    if not self.safe_sendall(client, data, "client"):
                        break
        except Exception as e:
            log.error("Error during data exchange: %s", traceback.format_exc())

    def safe_sendall(self, sock, data, sockname="socket"):
        try:
            sock.sendall(data)
            return True
        except Exception as e:
            log.debug("Error sending data on %s: %s", sockname, e)
            return False

    def close_socket(self, sock, name="socket"):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            log.debug("Error shutting down %s: %s", name, e)
        finally:
            sock.close()
            log.debug("%s closed", name)
