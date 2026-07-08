
import os
import argparse
import csv
import fnmatch
import json
import re
import socket
import struct
import sys
import urllib.request
import tarfile
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
import asyncio

try:
    import maxminddb
    MAXMIND_AVAILABLE = True
except ImportError:
    MAXMIND_AVAILABLE = False

try:
    from mcstatus import JavaServer
    JAVA_SERVER_AVAILABLE = True
except ImportError:
    JAVA_SERVER_AVAILABLE = False

MINECRAFT_DEFAULT_PORT = '25565-25566'
DEFAULT_TIMEOUT = 15
DEFAULT_CONCURRENCY = 256

@dataclass
class ScanResult:
    ip: str
    port: int
    version: str = ""
    players_online: int = 0
    players_max: int = 0
    description: str = ""
    country: str = ""
    latitude: float = 0.0
    longitude: float = 0.0

class MinecraftScanner:
    def __init__(self, args=None):
        self.geoip_reader = None

        self.target_hosts = '0.0.0.0/0'
        self.target_ports = MINECRAFT_DEFAULT_PORT
        self.min_players = 0
        self.max_players = None
        self.version_filter = '*'
        self.concurrency = DEFAULT_CONCURRENCY
        self.timeout = DEFAULT_TIMEOUT
        self.output_file = None
        self.output_format = 'csv'
        self.show_desc = False
        self.geo_ip = False
        self.geo_coords = False
        self.quiet = False
        self.maxmind_key = None

        if args:
            self.target_hosts = args.get('ip', self.target_hosts)
            self.target_ports = args.get('port', self.target_ports)
            self.min_players = args.get('min_players', self.min_players)
            self.max_players = args.get('max_players', self.max_players)
            self.version_filter = args.get('version', self.version_filter)
            self.concurrency = args.get('conc', self.concurrency)
            self.timeout = args.get('timeout', self.timeout)
            self.output_file = args.get('out', self.output_file)
            self.output_format = args.get('format', self.output_format)
            self.show_desc = args.get('show_desc', self.show_desc)
            self.geo_ip = args.get('geo_ip', self.geo_ip)
            self.geo_coords = args.get('geo_coords', self.geo_coords)
            self.quiet = args.get('quiet', self.quiet)
            self.maxmind_key = args.get('maxmind_key', self.maxmind_key)

        if self.quiet and not self.output_file:
            raise ValueError("You have asked for --quiet output, but did not specify an --out file. This scan is pointless!")

        if self.geo_ip:
            self._setup_geoip()

    def _setup_geoip(self):
        geoip_file = "./GeoLite2.mmdb"

        if not os.path.exists(geoip_file):
            if not self.maxmind_key:
                raise ValueError("NO MAXMIND DOWNLOAD KEY WAS PROVIDED! CANNOT DOWNLOAD THE DATABASE WITHOUT A KEY!")

            print("Downloading GeoIP database...")
            self._download_geoip_database()

        if MAXMIND_AVAILABLE:
            try:
                self.geoip_reader = maxminddb.open_database(geoip_file)
                print("GeoIP database loaded ok.")
            except Exception as err:
                raise Exception(f"Error loading GeoIP database: {err}")
        else:
            raise Exception("maxminddb library not available. Install with: pip install maxminddb")

    def _download_geoip_database(self):
        url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={self.maxmind_key}&suffix=tar.gz"

        try:
            print("Downloading GeoIP database...")
            with urllib.request.urlopen(url) as response:
                data = response.read()

            with open("./GeoLite2.tar.gz", "wb") as f:
                f.write(data)

            with tarfile.open("./GeoLite2.tar.gz", "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith('.mmdb'):
                        member.name = os.path.basename(member.name)
                        tar.extract(member, path="./")
                        break

            os.remove("./GeoLite2.tar.gz")
            print("GeoIP database ready.")

        except Exception as err:
            raise Exception(f"Error downloading GeoIP database: {err}")

    def _parse_port_range(self, port_string: str) -> List[int]:
        ports = []

        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))

        return ports

    def _parse_ip_range(self, ip_string: str) -> List[str]:
        if '/' in ip_string:
            base_ip = ip_string.split('/')[0]
            if ip_string == '0.0.0.0/0':
                return ['127.0.0.1']
            return [base_ip]
        else:
            return [ip_string]

    def _minecraft_ping(self, ip: str, port: int) -> Optional[Dict]:
        try:
            if not JAVA_SERVER_AVAILABLE:
                return self._manual_minecraft_ping(ip, port)

            server = JavaServer(ip, port)
            status = server.status()

            return {
                'version': status.version.name,
                'protocol': status.version.protocol,
                'players_online': status.players.online,
                'players_max': status.players.max,
                'description': status.description.get('text', '') if hasattr(status.description, 'get') else str(status.description),
                'latency': status.latency
            }

        except Exception:
            return None

    def _manual_minecraft_ping(self, ip: str, port: int) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            sock.connect((ip, port))

            packet_id = 0x00
            protocol_version = 47
            server_address = ip
            server_port = port
            next_state = 1

            data = bytearray()
            data.extend(self._write_varint(packet_id))
            data.extend(self._write_varint(protocol_version))
            data.extend(self._write_string(server_address))
            data.extend(struct.pack('>H', server_port))
            data.extend(self._write_varint(next_state))

            packet_length = len(data)
            sock.send(self._write_varint(packet_length) + data)

            sock.send(self._write_varint(1) + self._write_varint(0x00))

            response_length = self._read_varint(sock)
            response_data = sock.recv(response_length)

            sock.close()

            return self._parse_status_response(response_data)

        except Exception:
            return None

    def _write_varint(self, value: int) -> bytes:
        data = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value != 0:
                byte |= 0x80
            data.append(byte)
            if value == 0:
                break
        return bytes(data)

    def _read_varint(self, sock: socket.socket) -> int:
        result = 0
        shift = 0
        while True:
            byte = sock.recv(1)
            if not byte:
                raise Exception("Connection closed")

            byte = byte[0]
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result

    def _write_string(self, string: str) -> bytes:
        string_bytes = string.encode('utf-8')
        return self._write_varint(len(string_bytes)) + string_bytes

    def _read_string(self, data: bytearray, offset: int) -> Tuple[str, int]:
        length, offset = self._read_varint_from_data(data, offset)
        string_bytes = data[offset:offset + length]
        return string_bytes.decode('utf-8'), offset + length

    def _read_varint_from_data(self, data: bytearray, offset: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, offset

    def _parse_status_response(self, data: bytearray) -> Optional[Dict]:
        try:
            offset = 0

            _, offset = self._read_varint_from_data(data, offset)

            json_string, offset = self._read_string(data, offset)
            status_data = json.loads(json_string)

            version = status_data.get('version', {})
            players = status_data.get('players', {})
            description = status_data.get('description', {})

            return {
                'version': version.get('name', 'Unknown'),
                'protocol': version.get('protocol', 0),
                'players_online': players.get('online', 0),
                'players_max': players.get('max', 0),
                'description': description.get('text', '') if isinstance(description, dict) else str(description),
                'latency': 0
            }

        except Exception:
            return None

    def _get_geoip_info(self, ip: str) -> Tuple[str, float, float]:
        if not self.geoip_reader:
            return "", 0.0, 0.0

        try:
            response = self.geoip_reader.get(ip)
            if response:
                country = response.get('country', {}).get('iso_code', '')
                location = response.get('location', {})
                latitude = location.get('latitude', 0.0)
                longitude = location.get('longitude', 0.0)
                return country, latitude, longitude
        except Exception:
            pass

        return "", 0.0, 0.0

    def _matches_version_filter(self, version: str) -> bool:
        return fnmatch.fnmatch(version, self.version_filter)

    def _format_description(self, description: str) -> str:
        text = re.sub(r'§[0-9a-fk-or]', '', description)
        text = re.sub(r'\n', ' ', text)
        return text.strip()

    def _format_result_line(self, result: ScanResult) -> str:
        the_text = f"{result.ip}:{result.port}\t{result.version}\t{result.players_online} of {result.players_max} players"

        if self.show_desc:
            the_text += f"\t{self._format_description(result.description)}"

        if self.geo_ip and result.country:
            geo_text = result.country
            if self.geo_coords:
                geo_text += f" ({result.latitude},{result.longitude})"
            the_text = f"[{geo_text}] {the_text}"

        return the_text

    def _format_connect_only(self, result: ScanResult) -> str:
        return f"{result.ip}:{result.port}"

    def _format_line_for_output(self, result: ScanResult) -> str:
        if self.output_format == 'txt-connect-only':
            return self._format_connect_only(result)
        return self._format_result_line(result)

    def _format_csv_row(self, result: ScanResult) -> List[str]:
        row = [f"{result.ip}:{result.port}",
               result.version.replace(',', '+'),
               f"{result.players_online}/{result.players_max}"]

        if self.show_desc:
            row.append(self._format_description(result.description).replace(',', ';'))

        if self.geo_ip:
            geo_text = result.country
            if self.geo_coords:
                geo_text += f" ({result.latitude},{result.longitude})"
            row.append(geo_text)

        return row

    async def _scan_port(self, ip: str, port: int) -> Optional[ScanResult]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        try:
            result = sock.connect_ex((ip, port))
            if result != 0:
                return None
        except Exception:
            return None
        finally:
            sock.close()

        ping_res = self._minecraft_ping(ip, port)
        if not ping_res:
            return None

        if not self._matches_version_filter(ping_res['version']):
            return None

        if ping_res['players_online'] < self.min_players:
            return None

        if self.max_players and ping_res['players_max'] > self.max_players:
            return None

        country, latitude, longitude = "", 0.0, 0.0
        if self.geo_ip:
            country, latitude, longitude = self._get_geoip_info(ip)

        return ScanResult(
            ip=ip,
            port=port,
            version=ping_res['version'],
            players_online=ping_res['players_online'],
            players_max=ping_res['players_max'],
            description=ping_res['description'],
            country=country,
            latitude=latitude,
            longitude=longitude
        )

    async def _scan_worker(self, queue: asyncio.Queue, results: List[ScanResult]):
        while True:
            try:
                ip, port = await asyncio.wait_for(queue.get(), timeout=1.0)
                result = await self._scan_port(ip, port)
                if result:
                    results.append(result)
                queue.task_done()
            except asyncio.TimeoutError:
                break
            except Exception as e:
                print(f"Error in scan worker: {e}")
                queue.task_done()

    async def run_scan(self) -> List[ScanResult]:
        print(f"Scanning ports {self.target_ports} on {self.target_hosts} with {self.concurrency} connections.")

        ips = self._parse_ip_range(self.target_hosts)
        ports = self._parse_port_range(self.target_ports)

        queue = asyncio.Queue()
        results = []

        for ip in ips:
            for port in ports:
                await queue.put((ip, port))

        workers = []
        for _ in range(min(self.concurrency, queue.qsize())):
            worker = asyncio.create_task(self._scan_worker(queue, results))
            workers.append(worker)

        await queue.join()

        for worker in workers:
            worker.cancel()

        print("Scan finished!")
        return results

def main():
    parser = argparse.ArgumentParser(description='zping Minecraft Scanner')

    parser.add_argument('--ip', help='IP or range to scan (default: 0.0.0.0/0)')
    parser.add_argument('--port', help=f'Port or port range (default: {MINECRAFT_DEFAULT_PORT})')
    parser.add_argument('--min-players', type=int, help='Minimum number of connected players filter')
    parser.add_argument('--max-players', type=int, help='Maximum number of players allowed by the server filter')
    parser.add_argument('--version', help='Minecraft version filter (default: *)')
    parser.add_argument('--conc', type=int, help=f'Concurrency level (default: {DEFAULT_CONCURRENCY})')
    parser.add_argument('--timeout', type=int, help=f'Timeout in seconds per server (default: {DEFAULT_TIMEOUT})')

    parser.add_argument('--out', help='Output file to save results to')
    parser.add_argument('--format', choices=['csv', 'txt', 'txt-connect-only'], help='Output format')
    parser.add_argument('--show-desc', action='store_true', help="Show the server's MOTD/description")
    parser.add_argument('--quiet', action='store_true', help='Quiet mode, no console output (requires --out)')

    parser.add_argument('--geo-ip', action='store_true', help='Enable IP geolocation')
    parser.add_argument('--geo-coords', action='store_true', help='Include coordinates (lat/long) in the geolocation')
    parser.add_argument('--maxmind-key', help='MaxMind download key for the GeoIP database')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not JAVA_SERVER_AVAILABLE:
        print("Warning: mcstatus library not available. Install with: pip install mcstatus")
        print("Falling back to manual implementation.")

    if args.geo_ip and not MAXMIND_AVAILABLE:
        print("Error: maxminddb library required for GeoIP. Install with: pip install maxminddb")
        sys.exit(1)

    try:
        scanner_args = {
            'ip': args.ip,
            'port': args.port,
            'min_players': args.min_players,
            'max_players': args.max_players,
            'version': args.version,
            'conc': args.conc,
            'timeout': args.timeout,
            'out': args.out,
            'format': args.format,
            'show_desc': args.show_desc,
            'geo_ip': args.geo_ip,
            'geo_coords': args.geo_coords,
            'quiet': args.quiet,
            'maxmind_key': args.maxmind_key
        }

        scanner_args = {k: v for k, v in scanner_args.items() if v is not None}

        scanner = MinecraftScanner(scanner_args)
        results = asyncio.run(scanner.run_scan())

        if not args.quiet:
            for result in results:
                print(scanner._format_line_for_output(result))

        if args.out:
            try:
                with open(args.out, 'w', newline='', encoding='utf-8') as f:
                    if args.format == 'csv':
                        writer = csv.writer(f)
                        for result in results:
                            writer.writerow(scanner._format_csv_row(result))
                    else:
                        for result in results:
                            f.write(scanner._format_line_for_output(result) + '\n')
                print(f"Results saved to {args.out}")
            except Exception as e:
                print(f"Error saving file: {e}")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
