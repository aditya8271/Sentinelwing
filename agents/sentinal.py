import psutil
import logging
import time
import threading
import json
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from queue import Queue
from typing import Dict, List, Any
import redis
from dataclasses import dataclass, asdict

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)


@dataclass
class Event:
    """Standard event structure for inter-agent communication"""
    timestamp: str
    agent: str = "sentinel"
    event_id: str = None
    type: str = None
    severity: str = "info"  # info, warning, critical
    data: Dict[str, Any] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    def to_dict(self) -> Dict:
        return asdict(self)


class MessageQueue:
    """Redis-based message queue for inter-agent communication"""

    def __init__(self, host='localhost', port=6379, db=0):
        self.logger = logging.getLogger('MessageQueue')
        try:
            self.redis_client = redis.Redis(host=host, port=port, db=db, decode_responses=True)
            self.redis_client.ping()
            self.logger.info("Connected to Redis message queue")
        except redis.ConnectionError:
            self.logger.error("Redis not available, using local queue fallback")
            self.redis_client = None
            self.local_queue = Queue()

    def publish(self, channel: str, message: str):
        """Publish message to channel"""
        try:
            if self.redis_client:
                self.redis_client.publish(channel, message)
            else:
                # Fallback to local queue
                self.local_queue.put((channel, message))
        except Exception as e:
            self.logger.error(f"Failed to publish message: {e}")

    def push_to_list(self, key: str, value: str):
        """Push to Redis list for persistent queue"""
        try:
            if self.redis_client:
                self.redis_client.rpush(key, value)
            else:
                self.local_queue.put((key, value))
        except Exception as e:
            self.logger.error(f"Failed to push to list: {e}")

    def set_data(self, key: str, value: str, expiry: int = None):
        """Store data with optional expiry"""
        try:
            if self.redis_client:
                self.redis_client.set(key, value, ex=expiry)
        except Exception as e:
            self.logger.error(f"Failed to set data: {e}")


class FileMonitor(FileSystemEventHandler):
    """File system change detector using watchdog"""

    def __init__(self, event_callback):
        self.event_callback = event_callback
        self.logger = logging.getLogger('FileMonitor')
        self.sensitive_extensions = ['.exe', '.dll', '.sh', '.bat', '.ps1', '.py']
        self.sensitive_paths = ['/etc', '/bin', '/sbin', '/usr/bin', '/root']

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event('file_modified', event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._handle_event('file_created', event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_event('file_deleted', event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle_event('file_moved', event.src_path, event.dest_path)
            
            
            # Inside sentinel.py -> SentinelAgent class
def handle_event(self, event: Event):
    try:
        # ... (your existing logging code) ...
        
        # Add a flag if the severity is warning or critical
        event_dict = event.to_dict()
        event_dict['popup_required'] = event.severity in ['warning', 'critical']
        
        # Publish the enriched event
        message_json = json.dumps(event_dict)
        self.mq.publish(self.analyst_channel, message_json)
        self.mq.push_to_list(self.event_list_key, message_json)
        
        # ... (rest of your stats code) ...
    except Exception as e:
        self.logger.error(f"Failed to handle event: {e}")
            
            
        
    def _handle_event(self, event_type: str, src_path: str, dest_path: str = None):
        # Determine severity
        severity = 'info'
        if any(src_path.startswith(sp) for sp in self.sensitive_paths):
            severity = 'warning'
        if any(src_path.endswith(ext) for ext in self.sensitive_extensions):
            severity = 'warning'

        event = Event(
            timestamp=datetime.now().isoformat(),
            event_id=f"file_{int(time.time() * 1000)}",
            type='file_event',
            severity=severity,
            data={
                'event_type': event_type,
                'src_path': src_path,
                'dest_path': dest_path
            }
        )
        self.event_callback(event)


class ProcessMonitor:
    """Process and system activity monitor using psutil"""

    def __init__(self, event_callback):
        self.event_callback = event_callback
        self.logger = logging.getLogger('ProcessMonitor')
        self.known_processes = {}  # pid -> process_info
        self.cpu_threshold = 80.0
        self.mem_threshold = 80.0
        self.suspicious_names = ['nc', 'netcat', 'mimikatz', 'psexec']
        # Network monitoring additions
        self.known_open_ports = set()
        self.known_outbound_connections = set()
        self.previous_net_stats = None
        self.traffic_threshold = 1024 * 1024  # 1MB/s threshold for spikes

    def monitor_processes(self):
        """Monitor running processes"""
        try:
            current_pids = set()

            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent',
                                            'memory_percent', 'create_time', 'cmdline']):
                try:
                    info = proc.info
                    pid = info['pid']
                    current_pids.add(pid)

                    # New process detected
                    if pid not in self.known_processes:
                        severity = 'info'
                        if any(susp in info['name'].lower() for susp in self.suspicious_names):
                            severity = 'critical'

                        event = Event(
                            timestamp=datetime.now().isoformat(),
                            event_id=f"proc_new_{pid}",
                            type='process_event',
                            severity=severity,
                            data={
                                'event_type': 'new_process',
                                'pid': pid,
                                'name': info['name'],
                                'username': info['username'],
                                'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else '',
                                'create_time': info['create_time']
                            }
                        )
                        self.event_callback(event)
                        self.known_processes[pid] = info

                    # High resource usage
                    if info['cpu_percent'] and info['cpu_percent'] > self.cpu_threshold:
                        event = Event(
                            timestamp=datetime.now().isoformat(),
                            event_id=f"proc_cpu_{pid}",
                            type='process_event',
                            severity='warning',
                            data={
                                'event_type': 'high_cpu_usage',
                                'pid': pid,
                                'name': info['name'],
                                'cpu_percent': info['cpu_percent']
                            }
                        )
                        self.event_callback(event)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Detect terminated processes
            terminated = set(self.known_processes.keys()) - current_pids
            for pid in terminated:
                proc_info = self.known_processes.pop(pid)
                event = Event(
                    timestamp=datetime.now().isoformat(),
                    event_id=f"proc_term_{pid}",
                    type='process_event',
                    severity='info',
                    data={
                        'event_type': 'process_terminated',
                        'pid': pid,
                        'name': proc_info.get('name', 'unknown')
                    }
                )
                self.event_callback(event)

        except Exception as e:
            self.logger.error(f"Process monitoring error: {e}")

    def monitor_system(self):
        """Monitor system metrics"""
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()

            severity = 'info'
            if cpu > 90 or mem.percent > 90:
                severity = 'warning'

            event = Event(
                timestamp=datetime.now().isoformat(),
                event_id=f"sys_{int(time.time())}",
                type='system_metrics',
                severity=severity,
                data={
                    'cpu_percent': cpu,
                    'memory_percent': mem.percent,
                    'memory_available_gb': mem.available / (1024**3),
                    'disk_percent': disk.percent,
                    'network_bytes_sent': net.bytes_sent,
                    'network_bytes_recv': net.bytes_recv
                }
            )
            self.event_callback(event)

        except Exception as e:
            self.logger.error(f"System monitoring error: {e}")

    def monitor_network(self):
        """Monitor network connections"""
        try:
            suspicious_ports = [4444, 5555, 6666, 31337, 1337]
            connections = psutil.net_connections(kind='inet')

            # Get current network stats for traffic spike detection
            current_net = psutil.net_io_counters()
            current_time = time.time()

            # Detect traffic spikes
            if self.previous_net_stats:
                time_diff = current_time - self.previous_net_stats['time']
                if time_diff > 0:
                    sent_rate = (current_net.bytes_sent - self.previous_net_stats['bytes_sent']) / time_diff
                    recv_rate = (current_net.bytes_recv - self.previous_net_stats['bytes_recv']) / time_diff

                    if sent_rate > self.traffic_threshold or recv_rate > self.traffic_threshold:
                        event = Event(
                            timestamp=datetime.now().isoformat(),
                            event_id=f"traffic_{int(current_time * 1000)}",
                            type='network_event',
                            severity='warning',
                            data={
                                'event_type': 'traffic_spike',
                                'sent_rate_bps': sent_rate,
                                'recv_rate_bps': recv_rate,
                                'threshold_bps': self.traffic_threshold
                            }
                        )
                        self.event_callback(event)

            self.previous_net_stats = {
                'time': current_time,
                'bytes_sent': current_net.bytes_sent,
                'bytes_recv': current_net.bytes_recv
            }

            # Detect open ports (listening sockets)
            current_open_ports = set()
            for conn in connections:
                if conn.status == 'LISTEN':
                    port = conn.laddr.port if conn.laddr else None
                    if port:
                        current_open_ports.add(port)

            new_ports = current_open_ports - self.known_open_ports
            for port in new_ports:
                event = Event(
                    timestamp=datetime.now().isoformat(),
                    event_id=f"port_open_{port}_{int(time.time() * 1000)}",
                    type='network_event',
                    severity='info',
                    data={
                        'event_type': 'open_port',
                        'port': port,
                        'protocol': 'tcp'  # Assuming TCP for now
                    }
                )
                self.event_callback(event)

            self.known_open_ports = current_open_ports

            # Detect outbound connections
            current_outbound = set()
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    current_outbound.add((remote_ip, remote_port))

            new_outbound = current_outbound - self.known_outbound_connections
            for remote_ip, remote_port in new_outbound:
                event = Event(
                    timestamp=datetime.now().isoformat(),
                    event_id=f"outbound_{remote_ip.replace(':', '_').replace('.', '_')}_{remote_port}_{int(time.time() * 1000)}",
                    type='network_event',
                    severity='info',
                    data={
                        'event_type': 'outbound_connection',
                        'remote_ip': remote_ip,
                        'remote_port': remote_port
                    }
                )
                self.event_callback(event)

            self.known_outbound_connections = current_outbound

            # Existing suspicious connection detection
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    local_port = conn.laddr.port if conn.laddr else None
                    remote_port = conn.raddr.port if conn.raddr else None

                    if local_port in suspicious_ports or remote_port in suspicious_ports:
                        event = Event(
                            timestamp=datetime.now().isoformat(),
                            event_id=f"net_{int(time.time() * 1000)}",
                            type='network_event',
                            severity='critical',
                            data={
                                'event_type': 'suspicious_connection',
                                'local_addr': f"{conn.laddr.ip}:{local_port}" if conn.laddr else "N/A",
                                'remote_addr': f"{conn.raddr.ip}:{remote_port}" if conn.raddr else "N/A",
                                'status': conn.status,
                                'pid': conn.pid
                            }
                        )
                        self.event_callback(event)

        except (psutil.AccessDenied, Exception) as e:
            self.logger.warning(f"Network monitoring limited: {e}")


class LoginMonitor:
    """Monitor authentication and login events"""

    def __init__(self, event_callback):
        self.event_callback = event_callback
        self.logger = logging.getLogger('LoginMonitor')
        self.known_sessions = set()

    def monitor_users(self):
        """Monitor logged-in users"""
        try:
            current_sessions = set()

            for user in psutil.users():
                session_id = f"{user.name}@{user.host}_{user.started}"
                current_sessions.add(session_id)

                if session_id not in self.known_sessions:
                    event = Event(
                        timestamp=datetime.now().isoformat(),
                        event_id=f"login_{int(time.time() * 1000)}",
                        type='login_event',
                        severity='info',
                        data={
                            'event_type': 'new_login',
                            'username': user.name,
                            'host': user.host,
                            'terminal': user.terminal,
                            'started': datetime.fromtimestamp(user.started).isoformat()
                        }
                    )
                    self.event_callback(event)
                    self.known_sessions.add(session_id)

            # Detect logouts
            logged_out = self.known_sessions - current_sessions
            for session in logged_out:
                self.known_sessions.remove(session)

        except Exception as e:
            self.logger.error(f"User monitoring error: {e}")


class SentinelAgent:
    """
    Main Sentinel Agent - Monitors system and sends events to Message Queue
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger('SentinelAgent')
        self.config = config or {}
        self.running = False
        self.log_callback = self.config.get('log_callback')  # Callback for GUI logging

        # Initialize message queue
        self.mq = MessageQueue(
            host=self.config.get('redis_host', 'localhost'),
            port=self.config.get('redis_port', 6379)
        )

        # Event channels for other agents
        self.analyst_channel = 'sentinel_to_analyst'
        self.event_list_key = 'events_queue'

        # Initialize monitors with callback
        self.process_monitor = ProcessMonitor(self.handle_event)
        self.login_monitor = LoginMonitor(self.handle_event)

        # File monitoring
        watch_paths = self.config.get('watch_paths', ['.'])
        self.file_observer = Observer()
        self.file_handler = FileMonitor(self.handle_event)

        for path in watch_paths:
            try:
                self.file_observer.schedule(self.file_handler, path, recursive=True)
                self.logger.info(f"Watching: {path}")
            except Exception as e:
                self.logger.error(f"Cannot watch {path}: {e}")

        # Statistics
        self.stats = {
            'events_sent': 0,
            'start_time': None,
            'last_event_time': None
        }

    def handle_event(self, event: Event):
        """
        Central event handler - receives events from all monitors
        and forwards to Message Queue
        """
        try:
            # Log event
            log_level = {
                'info': logging.INFO,
                'warning': logging.WARNING,
                'critical': logging.CRITICAL
            }.get(event.severity, logging.INFO)

            msg = f"Event: {event.type} | {event.data.get('event_type', 'N/A')}"
            self.logger.log(log_level, msg)

            # Log to GUI if callback provided
            if self.log_callback:
                self.log_callback(msg, event.severity, "SENTINEL")

            # Send to Analyst Agent via message queue
            self.mq.publish(self.analyst_channel, event.to_json())
            self.mq.push_to_list(self.event_list_key, event.to_json())

            # Store event metadata in Redis
            event_key = f"event:{event.event_id}"
            self.mq.set_data(event_key, event.to_json(), expiry=86400)  # 24 hour expiry

            # Update stats
            self.stats['events_sent'] += 1
            self.stats['last_event_time'] = datetime.now().isoformat()

        except Exception as e:
            self.logger.error(f"Failed to handle event: {e}")

    def start(self):
        """Start the Sentinel Agent"""
        self.logger.info("SENTINEL AGENT STARTING...")
        self.running = True
        self.stats['start_time'] = datetime.now().isoformat()

        # Send startup event
        startup_event = Event(
            timestamp=datetime.now().isoformat(),
            event_id=f"startup_{int(time.time())}",
            type='agent_status',
            severity='info',
            data={'status': 'started', 'agent': 'sentinel'}
        )
        self.handle_event(startup_event)

        # Start file monitoring
        self.file_observer.start()

        # Start monitoring threads
        threads = [
            threading.Thread(target=self._process_loop, daemon=True),
            threading.Thread(target=self._system_loop, daemon=True),
            threading.Thread(target=self._network_loop, daemon=True),
            threading.Thread(target=self._login_loop, daemon=True),
            threading.Thread(target=self._heartbeat_loop, daemon=True)
        ]

        for thread in threads:
            thread.start()

        self.logger.info("SENTINEL AGENT ACTIVE - Monitoring system...")

    def stop(self):
        """Stop the Sentinel Agent"""
        self.logger.info("Stopping Sentinel Agent...")
        self.running = False

        # Send shutdown event
        shutdown_event = Event(
            timestamp=datetime.now().isoformat(),
            event_id=f"shutdown_{int(time.time())}",
            type='agent_status',
            severity='info',
            data={'status': 'stopped', 'agent': 'sentinel'}
        )
        self.handle_event(shutdown_event)

        self.file_observer.stop()
        self.file_observer.join()
        self.logger.info("Sentinel Agent stopped")

    def _process_loop(self):
        while self.running:
            self.process_monitor.monitor_processes()
            time.sleep(5)

    def _system_loop(self):
        while self.running:
            self.process_monitor.monitor_system()
            time.sleep(10)

    def _network_loop(self):
        while self.running:
            self.process_monitor.monitor_network()
            time.sleep(8)

    def _login_loop(self):
        while self.running:
            self.login_monitor.monitor_users()
            time.sleep(15)

    def _heartbeat_loop(self):
        """Send periodic heartbeat to show agent is alive"""
        while self.running:
            heartbeat = Event(
                timestamp=datetime.now().isoformat(),
                event_id=f"heartbeat_{int(time.time())}",
                type='agent_heartbeat',
                severity='info',
                data={
                    'agent': 'sentinel',
                    'uptime_seconds': (datetime.now() - datetime.fromisoformat(self.stats['start_time'])).total_seconds(),
                    'events_sent': self.stats['events_sent']
                }
            )
            self.mq.set_data('sentinel:heartbeat', heartbeat.to_json(), expiry=60)
            time.sleep(30)

    def get_stats(self) -> Dict[str, Any]:
        """Get current agent statistics"""
        return {
            'agent': 'sentinel',
            'status': 'running' if self.running else 'stopped',
            **self.stats,
            'known_processes': len(self.process_monitor.known_processes),
            'known_sessions': len(self.login_monitor.known_sessions)
        }

    def detect_threat(self, threat_type):
        """Mock threat detection for simulation"""
        threats = {
            "file": {"event": "Unauthorized File Modification", "source": "malicious.exe", "port": "N/A", "files": 3},
            "login": {"event": "Brute Force Login Attempt", "source": "185.220.101.47", "port": 22, "attempts": 247},
            "malware": {"event": "Malware Signature Detected", "source": "setup.exe", "port": 443, "hash": "a3f5c2d1"}
        }
        return threats.get(threat_type, threats["malware"])


# Main execution
if __name__ == "__main__":
    import os

    # Create logs directory
    os.makedirs('logs', exist_ok=True)

    # Configuration
    config = {
        'redis_host': 'localhost',
        'redis_port': 6379,
        'watch_paths': ['.', '/tmp']  # Adjust paths as needed
    }

    # Initialize and start Sentinel Agent
    sentinel = SentinelAgent(config)

    try:
        sentinel.start()

        # Keep running and show stats periodically
        while True:
            time.sleep(30)
            stats = sentinel.get_stats()
            print(f"\n{'='*60}")
            print(f"SENTINEL STATS")
            print(f"{'='*60}")
            print(f"Events Sent: {stats['events_sent']}")
            print(f"Known Processes: {stats['known_processes']}")
            print(f"Active Sessions: {stats['known_sessions']}")
            print(f"Last Event: {stats['last_event_time']}")
            print(f"{'='*60}\n")

    except KeyboardInterrupt:
        print("\n\n🛑 Shutdown initiated...")
        sentinel.stop()
        print("Sentinel Agent stopped cleanly")
