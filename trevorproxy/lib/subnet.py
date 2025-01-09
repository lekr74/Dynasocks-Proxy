import logging
    import ipaddress
    import threading
    import time
    import json
    from pathlib import Path
    from .errors import *
    import subprocess as sp
    from .cyclic import ipgen
    from .util import autodetect_address_pool, autodetect_interface, sudo_run
    
    log = logging.getLogger("trevorproxy.interface")
    
    
    class SubnetProxy:
        def __init__(self, config_file="subnets_config.json", interface=None, version=6, pool_netmask=16, socks_username=None, socks_password=None):
            self.lock = threading.Lock()
            self.socks_username = socks_username
            self.socks_password = socks_password
            self.config_file = Path(config_file)
            self.subnets = []
            self.interface = interface
            self.version = version
            self.pool_netmask = pool_netmask
            self.ipgens = []
            self._stop_event = threading.Event()
            self._config_thread = None
            self._running = False
    
            self._load_subnets_from_config()
    
            if not self.subnets:
                log.info(f"No subnet specified, detecting IPv{version} interfaces.")
                self.subnets = autodetect_address_pool(version=version)
                if not self.subnets:
                    raise SubnetProxyError("Failed to detect any IPv6 subnets")
                log.debug(f"Successfully detected subnets: {self.subnets}")
    
            if self.interface is None:
                log.info(f"No interface specified, detecting.")
                self.interface = autodetect_interface(version=version)
                if not self.interface:
                    raise SubnetProxyError("Failed to detect interface")
                log.debug(f"Successfully detected interface: {self.interface}")
    
            self._update_ipgens()
    
        def _load_subnets_from_config(self):
            try:
                with open(self.config_file, "r") as f:
                    config = json.load(f)
                    self.subnets = [
                        ipaddress.ip_network(subnet, strict=False)
                        for subnet in config.get("subnets", [])
                    ]
            except (FileNotFoundError, json.JSONDecodeError) as e:
                log.warning(f"Could not load config file {self.config_file}: {e}")
                self.subnets = []
    
        def _update_ipgens(self):
            self.ipgens = [ipgen(subnet) for subnet in self.subnets]
    
        def _config_monitor(self):
            while not self._stop_event.is_set():
                time.sleep(5)
                try:
                    with self.lock:
                        old_subnets = list(self.subnets)
                        self._load_subnets_from_config()
                        if old_subnets != self.subnets:
                            log.info("Subnet configuration changed, updating...")
                            self._update_ipgens()
                            self._apply_routes()
                except Exception as e:
                    log.error(f"Error during config monitoring: {e}")
    
        def _apply_routes(self):
            self._remove_routes()
            self._add_routes()
    
        def _add_routes(self):
            for subnet in self.subnets:
                cmd = [
                    "ip",
                    "route",
                    "add",
                    "local",
                    str(subnet),
                    "dev",
                    str(self.interface),
                ]
                sudo_run(cmd)
    
        def _remove_routes(self):
            for subnet in self.subnets:
                cmd = [
                    "ip",
                    "route",
                    "del",
                    "local",
                    str(subnet),
                    "dev",
                    str(self.interface),
                ]
                sudo_run(cmd)
    
        def start(self):
            if not self._running:
                self._running = True
                self._add_routes()
                self._stop_event.clear()
                self._config_thread = threading.Thread(target=self._config_monitor)
                self._config_thread.start()
    
        def stop(self):
            if self._running:
                self._running = False
                self._stop_event.set()
                if self._config_thread:
                    self._config_thread.join()
                self._remove_routes()
