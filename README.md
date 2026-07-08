# zping Minecraft Scanner

A command-line tool written in Python to scan Minecraft servers, check how many players are connected, filter by version, geolocate their IPs, and export the results to a file.

## Installation

1. Clone repository

  ```
  git clone https://github.com/zpiping/Minecraft-Scanner.git
  ```
   
3. Install the dependencies:

```
pip install -r requirements.txt
```

This installs:

- **mcstatus**: used to query a Minecraft server's status (version, online players, description/MOTD). If it's not installed, the script automatically falls back to a manual implementation of the Minecraft ping protocol, which is a bit more limited.
- **maxminddb**: only used if you enable geolocation (`--geo-ip`), to read the GeoLite2 database and get the country/coordinates of each IP.

The rest of the modules used by the script (`socket`, `struct`, `json`, `csv`, `argparse`, etc.) are part of Python's standard library and don't need to be installed separately.

## Basic usage

```
python3 mc_server_scanner.py --ip <IP or range> [options]
```

If you don't specify `--ip`, the scanner defaults to `0.0.0.0/0` (full range, though the current implementation limits this to `127.0.0.1` to avoid accidental mass scans).

## Available options

### Main scan options

| Option | Description | Default |
|---|---|---|
| `--ip` | IP or range to scan (e.g. `1.2.3.4` or `1.2.3.0/24`) | `0.0.0.0/0` |
| `--port` | Port or port range (e.g. `25565` or `25565-25570`) | `25565-25566` |
| `--min-players` | Only show servers with at least N players connected | no filter |
| `--max-players` | Only show servers that allow at most N players | no filter |
| `--version` | Minecraft version filter, supports wildcards (e.g. `"1.20.*"`) | `*` (all) |
| `--conc` | Number of concurrent connections used during the scan | `256` |
| `--timeout` | Maximum wait time per server, in seconds | `15` |

### Output options

| Option | Description |
|---|---|
| `--out` | File to save results to (e.g. `results.csv`) |
| `--format` | Output format: `csv`, `txt`, or `txt-connect-only` |
| `--show-desc` | Include the server's MOTD/description in the results |
| `--quiet` | Don't print anything to the console, only save to the file given with `--out` (must be used together with `--out`) |

### Geolocation (GeoIP)

| Option | Description |
|---|---|
| `--geo-ip` | Enables geolocation for each IP found |
| `--geo-coords` | Includes latitude and longitude in addition to the country |
| `--maxmind-key` | MaxMind download key, only needed if you don't already have the `GeoLite2.mmdb` file in the script's folder |

If you enable `--geo-ip` and the `./GeoLite2.mmdb` file doesn't exist yet, the script tries to download it automatically from MaxMind using the key you pass with `--maxmind-key`. You can get a free key by creating an account at [maxmind.com](https://www.maxmind.com/).

## Usage examples

Scan a single IP on the default port:

```
python3 mc_server_scanner.py --ip 1.2.3.4 --port 25565
```

Scan an IP range (CIDR notation) while showing the server description:

```
python3 mc_server_scanner.py --ip 1.2.3.0/24 --port 25565-25566 --show-desc
```

Filter by version and minimum players, saving the result as CSV:

```
python3 mc_server_scanner.py --ip 1.2.3.0/24 --version "1.20.*" --min-players 1 --out results.csv --format csv
```

Scan with geolocation, including coordinates:

```
python3 mc_server_scanner.py --ip 1.2.3.0/24 --geo-ip --geo-coords --maxmind-key YOUR_LICENSE_KEY
```

Silent scan, saving only to a file:

```
python3 mc_server_scanner.py --ip 1.2.3.0/24 --quiet --out results.csv --format txt-connect-only
```

## Output formats

- **csv**: each row contains IP:port, version, online/max players, and optionally description and geolocation data.
- **txt**: one human-readable line per server, with the same kind of information as the CSV.
- **txt-connect-only**: just the list of `ip:port` addresses found, with no extra data.

## See all options from the terminal

```
python3 mc_server_scanner.py --help
```

## Notes

- If `mcstatus` isn't installed, the script still works but uses a manual implementation of the Minecraft ping protocol (less complete than the library's).
- The `--quiet` option requires `--out` as well; otherwise the scan wouldn't have any visible output.
- Scanning very wide IP ranges can take a long time and generate a lot of network traffic: adjust `--conc` and `--timeout` based on your connection and hardware.
