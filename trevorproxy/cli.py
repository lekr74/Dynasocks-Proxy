#!/usr/bin/env python

# by TheTechromancer

import sys
import time
import logging
import argparse
import ipaddress
from shutil import which
from pathlib import Path

package_path = Path(__file__).resolve().parent
sys.path.append(str(package_path))

import lib.logger
from lib import util
from lib import logger
from lib.errors import *
from lib.socks import ThreadingTCPServer, ThreadingTCPServer6, SocksProxy
from lib.ssh import SSHLoadBalancer
from lib.subnet import SubnetProxy

# Credentials for SOCKS authentication
SOCKS_USERNAME = "user"
SOCKS_PASSWORD = "password"

log = logging.getLogger("trevorproxy.cli")


def main():
    parser = argparse.ArgumentParser(
        description="Round-robin requests through multiple SSH tunnels via a single SOCKS server"
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=1080,
        help="Port for SOCKS server to listen on (default: 1080)",
    )
    parser.add_argument(
        "-l",
        "--listen-address",
        default="0.0.0.0",
        help="Listen address for SOCKS server (default: 127.0.0.1)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Be quiet")
    parser.add_argument(
        "-v", "-d", "--verbose", "--debug", action="store_true", help="Be verbose"
    )

    subparsers = parser.add_subparsers(dest="proxytype", help="proxy type")

    subnet = subparsers.add_parser("subnet", help="round-robin traffic from subnet")
    subnet.add_argument("-i", "--interface", help="Interface to send packets on")
    subnet.add_argument(
        "-c",
        "--config",
        default="subnets_config.json",
        help="Path to the subnets config file (default: subnets_config.json)",
    )

    ssh = subparsers.add_parser("ssh", help="round-robin traffic through SSH hosts")
    ssh.add_argument(
        "ssh_hosts",
        nargs="+",
        help="Round-robin load-balance through these SSH hosts (user@host)",
    )
    ssh.add_argument(
        "-k", "--key", help="Use this SSH key when connecting to proxy hosts"
    )
    ssh.add_argument("-kp", "--key-pass", action="store_true", help=argparse.SUPPRESS)
    ssh.add_argument(
        "--base-port",
        default=32482,
        type=int,
        help="Base listening port to use for SOCKS proxies (default: 32482)",
    )

    try:
        options = parser.parse_args()

        if not options.quiet:
            logging.getLogger("trevorproxy").setLevel(logging.DEBUG)

        if options.proxytype == "ssh":
            # make sure executables exist
            for binary in SSHLoadBalancer.dependencies:
                if not which(binary):
                    log.error(f"Please install {binary}")
                    sys.exit(1)

            options.key_pass = util.get_ssh_key_passphrase(options.key)

            load_balancer = SSHLoadBalancer(
                hosts=options.ssh_hosts,
                key=options.key,
                key_pass=options.key_pass,
                base_port=options.base_port,
                socks_server=True,
                socks_username=SOCKS_USERNAME,  # Ajout des credentials
                socks_password=SOCKS_PASSWORD,  # pour l'authentification
            )

            try:
                load_balancer.start()
                log.info(
                    f"Listening on socks5://{SOCKS_USERNAME}:{SOCKS_PASSWORD}@{options.listen_address}:{options.port}"
                )

                # serve forever
                while 1:
                    # rebuild proxy if it goes down
                    for proxy in load_balancer.proxies.values():
                        if not proxy.is_connected():
                            log.debug(
                                f"SSH Proxy {proxy} went down, attempting to rebuild"
                            )
                            proxy.start()
                    time.sleep(1)

            finally:
                load_balancer.stop()

        elif options.proxytype == "subnet":
            # make sure executables exist
            for binary in ["iptables"]:
                if not which(binary):
                    log.error(f"Please install {binary}")
                    sys.exit(1)

            listen_address = ipaddress.ip_address(options.listen_address)

            subnet_proxy = SubnetProxy(
                config_file=options.config,
                interface=options.interface,
                socks_username=SOCKS_USERNAME,
                socks_password=SOCKS_PASSWORD,
            )
            try:
                tcp_server = (
                    ThreadingTCPServer
                    if listen_address.version == 4
                    else ThreadingTCPServer6
                )
                with tcp_server(
                    (options.listen_address, options.port),
                    SocksProxy,
                    proxy=subnet_proxy,
                    auth_username=SOCKS_USERNAME,
                    auth_password=SOCKS_PASSWORD,
                ) as server:
                    subnet_proxy.start()
                    log.info(
                        f"Listening on socks5://{SOCKS_USERNAME}:{SOCKS_PASSWORD}@{options.listen_address}:{options.port}"
                    )
                    server.serve_forever()
            finally:
                subnet_proxy.stop()

    except argparse.ArgumentError as e:
        log.error(e)
        log.error("Check your syntax")
        sys.exit(2)

    except TrevorProxyError as e:
        log.error(f"Error in TREVORproxy: {e}")

    except Exception as e:
        if options.verbose:
            import traceback

            log.error(traceback.format_exc())
        else:
            log.error(f"Unhandled error (-v to debug): {e}")

    except KeyboardInterrupt:
        log.error("Interrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()
