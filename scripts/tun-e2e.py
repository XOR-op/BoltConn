#!/usr/bin/env python3
"""Real BoltConn TUN E2E tests and optional iperf comparison, isolated on Linux.

Build binaries as your normal user, then run this script with sudo. No packages
are installed and no host network interfaces, routes, firewall or DNS are changed.
"""

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.request

REMOTE = "203.0.113.2"
PEER = "192.0.2.2"
NETNS = "boltconn-e2e-server"
TCP_PORT = 19001
UDP_PORT = 19002
WG_PORT = 51820
WG_CLIENT = "10.88.0.2"
WG_SERVER = "10.88.0.1"
WG_MTU = 1420
IPERF_CASES = {
    "upload": [],
    "download": ["-R"],
    "download-parallel4": ["-R", "-P", "4"],
    "download-paced200m": ["-R", "-b", "200M"],
    "parallel4": ["-P", "4"],
    "paced200m": ["-b", "200M"],
    "udp-download": ["-u", "-R", "-b", "200M", "-l", "1472"],
    "udp-small": ["-u", "-R", "-b", "10M", "-l", "64"],
}


def command(*args, timeout=15, **kwargs):
    result = subprocess.run([str(a) for a in args], text=True,
                            capture_output=True, timeout=timeout, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args}\n"
                           f"{result.stdout}{result.stderr}")
    return result.stdout


def namespace_ids():
    return {name: os.readlink(f"/proc/self/ns/{name}") for name in ("net", "mnt", "pid")}


def stop(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGCONT)
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        while data := self.request.recv(65536):
            self.request.sendall(data)


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class DnsUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        end = 12
        while data[end]:
            end += data[end] + 1
        end += 1
        qtype, qclass = struct.unpack("!HH", data[end:end + 4])
        answer = b""
        if (qtype, qclass) == (1, 1):
            answer = struct.pack("!HHHIH4s", 0xC00C, 1, 1, 60, 4,
                                 socket.inet_aton(REMOTE))
        header = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0],
                             0x8180, 1, bool(answer), 0, 0)
        sock.sendto(header + data[12:end + 4] + answer, self.client_address)


def server():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    services = [socketserver.ThreadingTCPServer((REMOTE, TCP_PORT), EchoTCP),
                socketserver.ThreadingUDPServer((REMOTE, UDP_PORT), EchoUDP),
                socketserver.ThreadingUDPServer((PEER, 53), DnsUDP)]
    for service in services:
        threading.Thread(target=service.serve_forever, daemon=True).start()
    print("ready", flush=True)
    signal.pause()


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise AssertionError("TCP peer closed before the full payload arrived")
        data.extend(part)
    return bytes(data)


def tcp_integrity(flow, host=REMOTE):
    total = 0
    digest = hashlib.sha256()
    with socket.create_connection((host, TCP_PORT), timeout=5) as sock:
        sock.settimeout(5)
        # Tiny/odd writes and bulk payloads exercise both NAT directions and
        # packet-buffer reuse. No assumptions about TCP segmentation are made.
        for size in [1, 3, 17, 63, 64, 511, 1460, 8191, 32768] * 16:
            data = bytes(((i * 31 + flow * 17 + total) & 255) for i in range(size))
            sock.sendall(data)
            actual = receive_exact(sock, size)
            assert actual == data, f"TCP payload mismatch in flow {flow}, offset {total}"
            digest.update(actual)
            total += size
    return {"flow": flow, "bytes_each_direction": total, "sha256": digest.hexdigest()}


def udp_integrity(flow, max_payload=1472):
    count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        for size in [1, 3, 63, 64, 511, min(1400, max_payload), max_payload] * 8:
            data = bytes(((i + flow * 23 + count) & 255) for i in range(size))
            sock.sendto(data, (REMOTE, UDP_PORT))
            actual, source = sock.recvfrom(65536)
            assert actual == data and source == (REMOTE, UDP_PORT), "UDP packet mismatch"
            count += 1
    return count


def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def tun_stats(name):
    link = json.loads(command("ip", "-j", "-s", "link", "show", "dev", name))[0]
    stats = link.get("stats64", link.get("stats"))
    return {f"{direction}_{kind}": stats[direction][kind]
            for direction in ("rx", "tx") for kind in ("bytes", "packets")}


def route_to_server():
    return json.loads(command("ip", "-j", "route", "get", REMOTE))[0]


def wait_ready(process):
    deadline = time.monotonic() + 15
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"BoltConn exited early with {process.returncode}; see its log")
        try:
            with opener.open("http://127.0.0.1:18086/tun", timeout=0.3) as response:
                status = json.load(response)
            route = route_to_server()
            if route["dev"].startswith("tun"):
                return route["dev"], status
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(0.05)
    raise RuntimeError("BoltConn TUN did not become ready")


def setup_isolation():
    parent = json.loads(os.environ["BOLTCONN_E2E_PARENT_NS"])
    current = namespace_ids()
    if not all(current[key] != parent[key] for key in current):
        raise RuntimeError("refusing host namespace setup")
    command("mount", "--make-rprivate", "/")
    # BoltConn uses fixed files in /tmp and /run, plus a resolv.conf bind mount.
    # Private mounts contain all of these side effects, including on failure.
    resolv = Path("/etc/resolv.conf").resolve()
    resolv_text = Path("/etc/resolv.conf").read_text()
    command("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", "/run")
    command("mount", "-t", "tmpfs", "-o", "mode=1777", "tmpfs", "/tmp")
    if resolv.is_relative_to("/run"):
        resolv.parent.mkdir(parents=True, exist_ok=True)
        resolv.write_text(resolv_text)
    command("ip", "link", "set", "lo", "up")
    command("ip", "netns", "add", NETNS)
    command("ip", "link", "add", "eth0", "type", "veth", "peer", "name", "server0")
    command("ip", "link", "set", "server0", "netns", NETNS)
    command("ip", "addr", "add", "192.0.2.1/30", "dev", "eth0")
    command("ip", "link", "set", "eth0", "up")
    command("ip", "route", "add", "default", "via", PEER)
    for args in [("link", "set", "lo", "up"),
                 ("addr", "add", f"{PEER}/30", "dev", "server0"),
                 ("link", "set", "server0", "up"),
                 ("addr", "add", f"{REMOTE}/32", "dev", "lo")]:
        command("ip", "netns", "exec", NETNS, "ip", *args)


def wireguard_counters():
    fields = command("ip", "netns", "exec", NETNS, "wg", "show", "wg0", "transfer").split()
    assert len(fields) == 3, "expected one WireGuard peer"
    return {"received_bytes": int(fields[1]), "sent_bytes": int(fields[2])}


def setup_wireguard(path):
    client_key = command("wg", "genkey").strip()
    client_public = command("wg", "pubkey", input=client_key + "\n").strip()
    server_key = command("wg", "genkey").strip()
    server_public = command("wg", "pubkey", input=server_key + "\n").strip()
    key_path = path / "wireguard-server.key"
    key_path.write_text(server_key + "\n")
    key_path.chmod(0o600)
    command("ip", "netns", "exec", NETNS, "ip", "link", "add", "wg0", "type", "wireguard")
    command("ip", "netns", "exec", NETNS, "wg", "set", "wg0", "listen-port", str(WG_PORT),
            "private-key", key_path, "peer", client_public, "allowed-ips", WG_CLIENT + "/32")
    command("ip", "netns", "exec", NETNS, "ip", "addr", "add", WG_SERVER + "/24", "dev", "wg0")
    command("ip", "netns", "exec", NETNS, "ip", "link", "set", "wg0", "mtu", str(WG_MTU), "up")
    return client_key, server_public


def write_config(path, transport):
    path.mkdir()
    proxy_config = ""
    fallback = "DIRECT"
    if transport == "wireguard":
        client_key, server_public = setup_wireguard(path)
        proxy_config = f"""proxy-local:
  wg-e2e:
    type: wireguard
    local-addr: {WG_CLIENT}
    private-key: '{client_key}'
    public-key: '{server_public}'
    endpoint: '{PEER}:{WG_PORT}'
    dns: '{PEER}'
    dns-preference: ipv4-only
    mtu: {WG_MTU}
"""
        fallback = "wg-e2e"
    (path / "config.yml").write_text(f"""interface: eth0
inbound:
  enable-tun: true
  enable-icmp-proxy: true
  firewall:
    kill-switch: false
    docker-masquerade:
      enabled: false
web-controller:
  api-addr: '127.0.0.1:18086'
dns:
  bootstrap: [{PEER}]
  nameserver: ['udp, {PEER}']
{proxy_config}proxy-group: {{}}
rules:
  - FALLBACK, {fallback}
""")
    (path / "state.yml").write_text("group-selection: {}\n")
    cert = path / "cert"
    cert.mkdir()
    command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "1", "-subj", "/CN=BoltConn isolated E2E test",
            "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", cert / "key.pem",
            "-out", cert / "crt.pem")


def integrity_checks(process, tun, allow_half_close_timeout=False, transport="direct"):
    before = tun_stats(tun)
    wg_before = wireguard_counters() if transport == "wireguard" else None
    assert route_to_server()["dev"] == tun
    half_close = "passed"
    with socket.create_connection((REMOTE, TCP_PORT), timeout=2) as sock:
        sock.sendall(b"half-close probe")
        assert receive_exact(sock, 16) == b"half-close probe"
        sock.shutdown(socket.SHUT_WR)
        try:
            assert sock.recv(1) == b"", "TCP FIN did not propagate"
        except TimeoutError:
            if not allow_half_close_timeout:
                raise AssertionError("TCP FIN did not propagate within 2 seconds") from None
            half_close = "known baseline failure: FIN timeout"

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        tcp = list(pool.map(tcp_integrity, range(8)))
        udp = list(pool.map(lambda flow: udp_integrity(
            flow, WG_MTU - 28 if transport == "wireguard" else 1472), range(8)))
    # Resolve through BoltConn's TUN DNS server, then connect via its fake-IP map.
    resolved = socket.gethostbyname("e2e.test")
    assert ipaddress.ip_address(resolved) in ipaddress.ip_network("198.18.0.0/15"), resolved
    dns_tcp = tcp_integrity(99, "e2e.test")
    ping = command("ping", "-n", "-c", "3", "-W", "2", REMOTE)
    after = tun_stats(tun)
    assert all(after[key] > before[key] for key in before), "TUN counters did not advance"
    # A route alone is insufficient evidence: stop the userspace forwarding task
    # and require a new TCP connection to stall; it must recover on resume.
    process.send_signal(signal.SIGSTOP)
    try:
        try:
            probe = socket.create_connection((REMOTE, TCP_PORT), timeout=0.5)
        except (TimeoutError, socket.timeout):
            pass
        else:
            probe.close()
            raise AssertionError("TCP connected while BoltConn was stopped (TUN bypass)")
    finally:
        process.send_signal(signal.SIGCONT)
    tcp_integrity(100)
    wg_delta = None
    if wg_before is not None:
        wg_after = wireguard_counters()
        wg_delta = {key: wg_after[key] - wg_before[key] for key in wg_before}
        payload_bytes = sum(item["bytes_each_direction"] for item in tcp) + dns_tcp["bytes_each_direction"]
        assert all(value >= payload_bytes for value in wg_delta.values()), "payload bypassed WireGuard"
    return {"tcp": tcp, "udp_echoes": sum(udp), "dns_fake_ip": resolved,
            "wireguard_counter_delta": wg_delta,
            "dns_tcp": dns_tcp, "icmp": ping, "tcp_half_close": half_close, "tun_counter_delta":
            {key: after[key] - before[key] for key in before}, "stop_control": "passed"}


def udp_kernel_stats():
    lines = Path("/proc/net/snmp").read_text().splitlines()
    for header, values in zip(lines[::2], lines[1::2]):
        if header.startswith("Udp:"):
            return dict(zip(header.split()[1:], map(int, values.split()[1:])))
    raise RuntimeError("UDP kernel counters unavailable")


def iperf_sample(process, tun, case, duration, client_cpu, path, transport, profile):
    options = list(IPERF_CASES[case])
    if transport == "wireguard" and "-l" in options:
        size = options.index("-l") + 1
        options[size] = str(min(int(options[size]), WG_MTU - 28))
    wg_before = wireguard_counters() if transport == "wireguard" else None
    udp_before = udp_kernel_stats() if transport == "wireguard" else None
    if transport == "wireguard" and shutil.which("ss"):
        path.with_suffix(".sockets-before.txt").write_text(command("ss", "-unam"))
    profiler = None
    profile_log = None
    if profile:
        profile_log = path.with_suffix(".perf.log").open("w")
        profiler = subprocess.Popen(["perf", "record", "-F", "499", "--call-graph", "fp",
                                     "-p", str(process.pid), "-o", str(path.with_suffix(".perf.data"))],
                                    stdout=profile_log, stderr=subprocess.STDOUT)
        time.sleep(0.2)
        assert profiler.poll() is None, "perf failed to attach; see its log"
    before = tun_stats(tun)
    cpu = cpu_seconds(process.pid)
    start = time.monotonic()
    try:
        output = command("taskset", "-c", str(client_cpu), "iperf3", "-c", REMOTE,
                         "-t", str(duration), "-J", *options, timeout=duration + 20)
        elapsed = time.monotonic() - start
        cpu = cpu_seconds(process.pid) - cpu
    finally:
        if profiler is not None:
            profiler.send_signal(signal.SIGINT)
            profiler.wait(timeout=10)
            profile_log.close()
            assert profiler.returncode in (0, -signal.SIGINT, 128 + signal.SIGINT), (
                f"perf exited with {profiler.returncode}; see its log")
            data_path = path.with_suffix(".perf.data")
            assert data_path.exists() and data_path.stat().st_size > 0, "perf produced no data"
            report = command("perf", "report", "--stdio", "--no-children", "--percent-limit", "0.5",
                             "-i", data_path, timeout=60)
            path.with_suffix(".perf.txt").write_text(report)
    path.write_text(output)
    result = json.loads(output)
    assert "error" not in result, result.get("error")
    received = result["end"]["sum_received"]
    assert received["bytes"] > 0
    after = tun_stats(tun)
    assert after["tx_packets"] > before["tx_packets"] and after["rx_packets"] > before["rx_packets"]
    row = {"case": case, "profiled": profile, "received_bytes": received["bytes"],
            "bits_per_second": received["bits_per_second"], "elapsed_seconds": elapsed,
            "boltconn_cpu_seconds": cpu, "boltconn_cpu_percent": cpu / elapsed * 100,
            "cpu_seconds_per_gib": cpu * 2**30 / received["bytes"],
            "tun_counter_delta": {key: after[key] - before[key] for key in before}}
    if not case.startswith("udp-"):
        row["tcp_retransmits"] = result["end"]["sum_sent"].get("retransmits")
    if wg_before is not None:
        wg_after = wireguard_counters()
        row["wireguard_counter_delta"] = {key: wg_after[key] - wg_before[key] for key in wg_before}
        direction = "sent_bytes" if "-R" in options else "received_bytes"
        assert row["wireguard_counter_delta"][direction] >= received["bytes"], "payload bypassed WireGuard"
        udp_after = udp_kernel_stats()
        row["udp_kernel_counter_delta"] = {
            key: udp_after[key] - udp_before[key] for key in udp_before}
        if shutil.which("ss"):
            path.with_suffix(".sockets-after.txt").write_text(command("ss", "-unam"))
    if case.startswith("udp-"):
        row["datagram_payload_bytes"] = int(options[options.index("-l") + 1])
        row.update({key: received[key] for key in ("packets", "lost_packets", "lost_percent")})
        assert received["lost_percent"] < 1, f"UDP loss exceeds 1%: {received['lost_percent']}"
    return row


def inside(args):
    output = Path(args.output)
    setup_isolation()
    write_config(output / "config", args.path)
    cpus = [int(cpu) for cpu in args.cpus.split(",")]
    server_process = iperf_server = app = None
    results = {"kernel": os.uname().release, "cpus": cpus, "path": args.path,
               "profiled": args.profile,
               "duration": args.duration, "runs": args.runs, "cases": args.cases,
               "integrity": {}, "samples": [],
               "binaries": {file.name: {"sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                                        "version": command(file, "--version").strip()}
                            for file in (output / "bin").iterdir()}}
    variants = [("optimized", output / "bin" / "optimized")]
    if args.baseline:
        variants.insert(0, ("baseline", output / "bin" / "baseline"))
    try:
        with (output / "server.log").open("w") as log:
            server_process = subprocess.Popen(["ip", "netns", "exec", NETNS, sys.executable,
                                               str(Path(__file__).resolve()), "--_server"],
                                              stdout=log, stderr=subprocess.STDOUT)
        with (output / "iperf-server.log").open("w") as log:
            iperf_server = subprocess.Popen(["ip", "netns", "exec", NETNS, "taskset", "-c", str(cpus[3]),
                                             "iperf3", "-s", "-B", REMOTE], stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection((REMOTE, TCP_PORT), timeout=0.2):
                    break
            except OSError:
                assert time.monotonic() < deadline, "test server did not start"
                time.sleep(0.05)
        def start_app(label, binary, run):
            with (output / f"{label}-{run}.log").open("w") as log:
                process = subprocess.Popen(["taskset", "-c", f"{cpus[0]},{cpus[1]}", str(binary), "start",
                                            "-c", str(output / "config"), "-d", str(output / "config")],
                                           stdout=log, stderr=subprocess.STDOUT,
                                           env={**os.environ, "RUST_LOG": "warn"})
            return process

        # Correctness runs are separate so any baseline half-close timeout or
        # completed integrity sessions cannot bias the timed process samples.
        for label, binary in variants:
            app = start_app(label, binary, "integrity")
            tun, status = wait_ready(app)
            results["integrity"][label] = integrity_checks(
                app, tun, (label == "baseline" and args.allow_baseline_half_close_timeout)
                or (args.path == "wireguard" and args.allow_wireguard_half_close_timeout), args.path)
            results["integrity"][label]["controller_tun_status"] = status
            print(f"{label}: TCP/UDP/DNS/ICMP integrity and TUN stop control passed; "
                  f"half-close: {results['integrity'][label]['tcp_half_close']}", flush=True)
            stop(app)
            assert app.returncode == 0, f"BoltConn shutdown failed: {app.returncode}"
            app = None
        if not args.check_only:
            for run in range(args.runs):
                order = variants if run % 2 == 0 else list(reversed(variants))
                for case in args.cases:
                    for label, binary in order:
                        # A fresh process keeps completed connections from earlier cases
                        # out of the measured socket tables, including the known WG FIN issue.
                        app = start_app(label, binary, f"{run}-{case}")
                        tun, _ = wait_ready(app)
                        # Establish the shared tunnel and worker threads before timing/profiling.
                        command("taskset", "-c", str(cpus[2]), "iperf3", "-c", REMOTE,
                                "-t", "1", "-J", timeout=20)
                        row = iperf_sample(app, tun, case, args.duration, cpus[2],
                                           output / f"{label}-{run}-{case}.json", args.path, args.profile)
                        row.update(variant=label, run=run)
                        results["samples"].append(row)
                        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                        print(f"{label} run {run} {case}: {row['bits_per_second']/1e9:.3f} Gbit/s, "
                              f"{row['cpu_seconds_per_gib']:.3f} CPU s/GiB", flush=True)
                        stop(app)
                        assert app.returncode == 0, f"BoltConn shutdown failed: {app.returncode}"
                        app = None
        results["passed"] = True
    finally:
        stop(app)
        stop(iperf_server)
        stop(server_process)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        command("ip", "netns", "del", NETNS)


def main():
    if not __debug__:
        raise RuntimeError("run without -O: integrity assertions must remain enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="optimized release binary")
    parser.add_argument("--baseline", type=Path, help="optional baseline release binary")
    parser.add_argument("--path", choices=("direct", "wireguard"), default="direct",
                        help="forward directly or through a real kernel WireGuard peer")
    parser.add_argument("--profile", action="store_true",
                        help="record perf stacks per workload; profile timings are not benchmark results")
    parser.add_argument("--output", type=Path, help="new artifact directory outside /tmp and /run")
    parser.add_argument("--duration", type=int, default=3, help="iperf seconds per sample")
    parser.add_argument("--runs", type=int, default=3, help="alternating before/after runs")
    parser.add_argument("--cases", nargs="+", choices=IPERF_CASES, default=list(IPERF_CASES),
                        help="iperf workloads to measure (default: all TCP and UDP cases)")
    parser.add_argument("--cpus", help="four CPUs: two for BoltConn, client, server")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--allow-baseline-half-close-timeout", action="store_true",
                        help="record the known old relay FIN bug; optimized must still pass")
    parser.add_argument("--allow-wireguard-half-close-timeout", action="store_true",
                        help="record the existing WireGuard FIN timeout while checking payload integrity")
    parser.add_argument("--_inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--_server", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args._server:
        server()
        return
    if args._inside:
        inside(args)
        return
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run on Linux using sudo; builds do not need sudo")
    if not args.binary or args.duration < 1 or args.runs < 1:
        parser.error("provide --binary and positive --duration/--runs")
    required = ["unshare", "ip", "mount", "openssl", "iperf3", "taskset", "ping"]
    if args.path == "wireguard":
        required.append("wg")
    if args.profile:
        required.append("perf")
    for executable in required:
        if not shutil.which(executable):
            parser.error(f"missing required command: {executable}")
    available = sorted(os.sched_getaffinity(0))
    cpus = [int(cpu) for cpu in args.cpus.split(",")] if args.cpus else available[:4]
    if len(cpus) != 4 or len(set(cpus)) != 4 or not set(cpus) <= set(available):
        parser.error("four distinct available CPUs are required")
    args.cpus = ",".join(map(str, cpus))
    output = (args.output or Path("target") / f"tun-e2e-{time.time_ns()}").resolve()
    if any(output.is_relative_to(root) or Path(__file__).resolve().is_relative_to(root)
           for root in ("/tmp", "/run")):
        parser.error("script and output must be outside /tmp and /run (private tmpfs mounts)")
    output.mkdir(parents=True, exist_ok=False)
    (output / "bin").mkdir()
    for label, binary in [("optimized", args.binary), ("baseline", args.baseline)]:
        if binary:
            shutil.copy2(binary.resolve(), output / "bin" / label)
    host_routes = command("ip", "-j", "route", "show", "table", "all")
    host_dns = Path("/etc/resolv.conf").read_bytes()
    try:
        child = ["unshare", "--net", "--mount", "--pid", "--fork", "--mount-proc", "--kill-child",
                 sys.executable, str(Path(__file__).resolve()), "--_inside", "--output", str(output),
                 "--cpus", args.cpus, "--duration", str(args.duration), "--runs", str(args.runs),
                 "--path", args.path]
        child += ["--cases", *args.cases]
        if args.baseline:
            child += ["--baseline", str(output / "bin" / "baseline")]
        if args.check_only:
            child += ["--check-only"]
        if args.profile:
            child += ["--profile"]
        if args.allow_baseline_half_close_timeout:
            child += ["--allow-baseline-half-close-timeout"]
        if args.allow_wireguard_half_close_timeout:
            child += ["--allow-wireguard-half-close-timeout"]
        subprocess.run(child, check=True, env={**os.environ,
                       "BOLTCONN_E2E_PARENT_NS": json.dumps(namespace_ids())})
    finally:
        assert command("ip", "-j", "route", "show", "table", "all") == host_routes, "host routes changed"
        assert Path("/etc/resolv.conf").read_bytes() == host_dns, "host DNS changed"
        uid, gid = int(os.environ.get("SUDO_UID", 0)), int(os.environ.get("SUDO_GID", 0))
        for parent, directories, files in os.walk(output):
            for name in directories + files:
                os.chown(Path(parent) / name, uid, gid, follow_symlinks=False)
        os.chown(output, uid, gid)
        print(f"Artifacts: {output}", flush=True)


if __name__ == "__main__":
    main()
