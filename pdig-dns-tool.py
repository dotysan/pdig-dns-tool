#! /usr/bin/env -S uv run --script --python=3
# /// script
# dependencies = [
#     "dnspython",
#     "netifaces",
#     "numpy",
#     "requests",
# ]
# ///

"""
DNS latency measurement tool that walks the delegation chain from root
nameservers to authoritative servers, measuring response times at each step.

Reports per-query latency and aggregated statistics (min, max, avg, stddev)
for each delegation point. Supports IPv4/IPv6, UDP/TCP, and optional reporting.
"""

import argparse
import contextlib
import json
import operator
import os
from pathlib import Path
import socket
import statistics
import sys
import time
from typing import TYPE_CHECKING

# 3rd party imports
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import numpy.random
import requests

if TYPE_CHECKING:
    from collections.abc import Sequence

addrinfo_cache = []

addrinfo_cache_hits = 0


def cached_getaddrinfo(
        hostname: str,
        port: int | str | None,
        family: socket.AddressFamily | int,
    ) -> list[tuple] | None:
    """ Return cached getaddrinfo results for a host/family pair, or resolve and cache them.

    Returns:
        Cached or newly resolved ``socket.getaddrinfo()`` results for the given
        host and address family, or ``None`` if resolution fails.
    """

    global addrinfo_cache_hits
    for a in addrinfo_cache:
        if a.get('hostname') == hostname and a.get('family') == family:
            addrinfo_cache_hits += 1
            return a.get('cache')
    try:
        add_info = socket.getaddrinfo(host=hostname, port=port, family=family)
    except socket.gaierror as e:
        if e.errno == -2:  # Name or service not known
            add_entry = {"hostname": hostname, "family": family, "cache": None}
            addrinfo_cache.append(add_entry)
#        print(f"DNS resolution error for {hostname}: {e.errno}")
        return None
    except OSError as e:
        print(f"Socket error for {hostname}: {e}")
        return None

    add_entry = {"hostname": hostname, "family": family, "cache": add_info}
    addrinfo_cache.append(add_entry)
    return add_info


def query_all(full_qname: str,  # domain name to query for
              prev_cache: list,  # list of nameservers to query
              qtype_list: list,  # is array of possible query types eg: [dns.rdatatype.A, dns.rdatatype.AAAA]
              tcp: bool,  # when true, send query over tcp
              file_handle: int | None,
              high_latency: bool,
              ip_list: dict,
              socket_types: Sequence[socket.AddressFamily | int],
        ) -> tuple:
    """ query_all handles making the query for each dns server """

    # Add new data structure to store TTL and latency info
    query_stats = []
    cname_reply = None
    new_cache = []
    times = []
    query_ip = {}
    domain_exists = True

    for qtype in qtype_list:

        try:
            q = dns.message.make_query(full_qname, qtype)
        except (dns.exception.DNSException, ValueError, TypeError) as e:
            print(f"{e}:{full_qname}:{qtype}")
            if file_handle is not None:
                os.write(file_handle, str.encode(f"{e}:{full_qname}:{qtype}\n"))
            continue

        for x in prev_cache:
            qip: str = x['addrinfo']
            # Skip problematic IPv6 addresses
            if (qip.startswith(('fc',      # ULA
                                'fd',      # ULA
                                'fe80::',  # Link-local
                                'ff',      # Multicast IPv6
                                '224.',    # Multicast IPv4
                                '225.',    # Multicast IPv4
                                '226.',    # Multicast IPv4
                                '227.',    # Multicast IPv4
                                '228.',    # Multicast IPv4
                                '229.',    # Multicast IPv4
                                '230.',    # Multicast IPv4
                                '231.',    # Multicast IPv4
                                '232.',    # Multicast IPv4
                                '233.',    # Multicast IPv4
                                '234.',    # Multicast IPv4
                                '235.',    # Multicast IPv4
                                '236.',    # Multicast IPv4
                                '237.',    # Multicast IPv4
                                '238.',    # Multicast IPv4
                                '239.'))
                or qip in {
                                '::',      # Unspecified IPv6
                                '0.0.0.0'  # Unspecified IPv4
                }):
                continue
            # check if we have talked to this IP + QTYPE this round
            if query_ip.get(qip + str(qtype)) is None:
                query_ip[qip + str(qtype)] = 1

                # store list of all IPs
                ip_list[qip] = 1

                # timer
                start_time = time.time()
                try:
                    resp = dns.query.tcp(q, qip, timeout=3) if tcp else dns.query.udp(q, qip, timeout=3)
                    stop_time = time.time()

                    latency = stop_time - start_time
                    latency_ms = latency * 1000
                    times.append(latency_ms)

                    if latency_ms > 100 or high_latency is False:
                        log_line = (
                            f"ns={x['qname']}, qtype={dns.rdatatype.to_text(qtype)}, "
                            f"addr={qip}, latency={latency_ms:.3f} ms"
                        )
                        print(log_line)
                        if file_handle is not None:
                            os.write(file_handle, str.encode(log_line + '\n'))

                    if resp.rcode() == dns.rcode.NXDOMAIN:
                        domain_exists = False
                        continue
                    if resp.rcode() != dns.rcode.NOERROR:
                        print(f"{dns.rcode.to_text(resp.rcode())} for {full_qname} at {qip}")
                        continue

                    # parse the response packet
                    # if we are not yet to an authoritative server
                    if not resp.flags & dns.flags.AA or len(resp.answer) > 0 or len(resp.authority) > 0:
                        ttl = None
                        vname = None
#                        print("parsing resp.answer", time.time())
                        for var in resp.answer:
                            ttl = var.ttl
                            vname = str(var.name)
#                            print("var.name=", vname)
                            for i in var.items:
                                if var.rdtype == dns.rdatatype.CNAME:
                                    cname_reply = str(i)
                            if latency_ms > 100 or high_latency is False:
                                ans_line = f'"{latency_ms}";ans="{vname}";qip="{qip}";TTL={ttl}'
                                if file_handle is not None:
                                    os.write(file_handle, str.encode(ans_line + '\n'))
                                print(ans_line)

                        # Store TTL and latency information
                        if ttl is not None:
                            query_stats.append({
                                'latency': latency_ms,
                                'ttl': ttl,
                                'nameserver': vname,
                                'ip': qip,
                                'nsname': x['qname'],
                            })
                        ttl = None
                        vname = None
#                        print("parsing resp.authority", time.time())
                        # parse the authority portion of response packet
                        for var in resp.authority:
                            ttl = var.ttl
                            vname = str(var.name)
#                            print("var.name=", vname)
                            for i in var.items:
                                # check NS responses
                                if i.rdtype == dns.rdatatype.NS:
                                    # both address families
                                    for fam in socket_types:
                                        str_name = str(i.to_text())
#                                        print("time=", time.time(), " getaddrinfo:", str_name)
                                        add_info = cached_getaddrinfo(str_name, None, fam)
                                        if add_info is not None:
                                            for a in add_info:
                                                addr_list = a[4]
                                                new_cache.append({
                                                    'qname': str_name,
                                                    'af_type': a[0],
                                                    'addrinfo': addr_list[0],
                                                })
                        # Store TTL and latency information
                        if ttl is not None:
                            query_stats.append({
                                'latency': latency_ms,
                                'ttl': ttl,
                                'nameserver': vname,
                                'ip': qip,
                                'nsname': x['qname'],
                            })

                except dns.query.BadResponse as e:
                    print(f"error {e} querying {qip} for {full_qname}")
                    if file_handle is not None:
                        os.write(file_handle, str.encode(f"error {e} querying {qip} for {full_qname}\n"))
                except dns.exception.Timeout:
                    print(f"timeout querying: {qip} - {x['qname']}")
                    if file_handle is not None:
                        os.write(file_handle, str.encode(f"timeout querying: {qip} - {x['qname']}\n"))
                except OSError as e:
                    # This is the new block to catch network unreachable errors
                    print(f"Network error: {e} when trying to query {qip} for {x['qname']}")
                    if file_handle is not None:
                        os.write(file_handle, str.encode(f"Network error: {e} when trying to query {qip} for {x['qname']}"))
                    continue  # Skip this address and try the next one

    # output some statistics at the end
    min_value = 0 if len(times) == 0 else min(times)
    max_value = 0 if len(times) == 0 else max(times)
    avg_value = 0 if len(times) == 0 else sum(times)/len(times)
    min_max_range = max_value - min_value
    stddev = 0 if len(times) < 2 else statistics.stdev(times)
    min_max_ratio = 0 if min_value == 0 else max_value / min_value
    latency = f"latency: min={min_value:.3f} ms max={max_value:.3f} ms avg={avg_value:.3f} ms"
    variance = f"stdev={stddev:.3f} ms max-min={min_max_range:.3f} ms max/min={min_max_ratio:.2f} x latency variance"
    print(latency)
    print(variance)
    if file_handle is not None:
        os.write(file_handle, str.encode(latency + '\n'))
        os.write(file_handle, str.encode(variance + '\n'))

    if not domain_exists:
        print(f"NXDOMAIN for {full_qname}, stopping...")
        if file_handle is not None:
            os.write(file_handle, str.encode(f"NXDOMAIN for {full_qname}, stopping..." + '\n'))
        return ([], None, [])
    # See bug #5. This is to prevent some endless loops if we do not
    # progress in the domain name tree.
    if sorted(new_cache, key=operator.itemgetter("qname")) == \
       sorted(prev_cache, key=operator.itemgetter("qname")):
        new_cache = []
    return (new_cache, cname_reply, query_stats)


def query_domain(
        fqdn: str,
        cli_args: argparse.Namespace,
        socket_types: Sequence[socket.AddressFamily | int],
        *,
        verbose: bool = False,
    ) -> str | None:
    """Start the top of the query chain for a domain.

    Args:
        fqdn: Fully qualified domain name to query.
        cli_args: Parsed command-line arguments.
        socket_types: Address families to use for DNS lookups.
        verbose: Enable verbose debug output when True.

    Returns:
        The report filename when report output is enabled and created successfully;
        otherwise ``None``.
    """

    print(f"querying for {fqdn}")

    fd, filename = _open_report_file(cli_args.report, fqdn)
    if cli_args.report and fd is None:
        return None

    # preseed the data
    root_hints = _seed_root_hints(cli_args.tcp, socket_types, verbose, fd)
    if root_hints is None:
        if fd is not None:
            os.close(fd)
        return None

    all_ips = {}
    # run through the domain tree until done
    all_query_stats = _run_query_chain(fqdn, root_hints, cli_args, fd, all_ips, socket_types)

    ts = time.ctime()
    print(f"end={ts}")
    if fd is not None:
        _write_report_line(fd, f"end={ts}")
        _write_identity_queries(fd, all_ips, ts)

    # After the main query loop, analyze and output the statistics
    _print_query_statistics(all_query_stats, fd)

    if fd is not None:
        os.close(fd)
        print(filename)
    return filename


def _open_report_file(report_path: str | None, fqdn: str) -> tuple[int | None, str | None]:
    if not report_path:
        return (None, None)

    try:
        fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    except OSError as e:
        print(f"Error creating report file '{report_path}': {e}")
        return (None, None)

    ts = time.ctime()
    print(f"start={ts}")
    _write_report_line(fd, f"querying for {fqdn}")
    _write_report_line(fd, f"start={ts}")
    return (fd, report_path)


def _seed_root_hints(
        tcp: bool,
        socket_types: Sequence[socket.AddressFamily | int],
        verbose: bool,
        fd: int | None,
    ) -> list[dict] | None:
    try:
        response = dns.resolver.resolve(".", "NS", lifetime=10, tcp=tcp)
        if verbose:
            print(f"[VERBOSE] Successfully resolved root NS records: {response}")
    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        msg = f"Failed to resolve root nameservers: {e}"
        print(msg)
        _write_report_line(fd, msg)
        return None
    except (dns.exception.DNSException, OSError) as e:
        msg = f"Unexpected error resolving root nameservers: {e}"
        print(msg)
        _write_report_line(fd, msg)
        return None

    root_hints = []
    for var in response.response.answer:
        for i in var.items:
            str_name = str(i.to_text())
            for fam in socket_types:
                add_info = cached_getaddrinfo(str_name, None, fam)
                if verbose:
                    print(f"[VERBOSE] getaddrinfo for {str_name} (family {fam}): {add_info}")
                if add_info is None:
                    continue
                for a in add_info:
                    addr_list = a[4]
                    root_hints.append({'qname': str_name, 'af_type': a[0], 'addrinfo': addr_list[0]})
                    if verbose:
                        print(f"[VERBOSE] Added root hint: qname={str_name}, af_type={a[0]}, addrinfo={addr_list[0]}")

    if len(root_hints) == 0:
        print("No root hints found after processing root NS records!")
    return root_hints


def _run_query_chain(
        fqdn: str,
        root_hints: list[dict],
        cli_args: argparse.Namespace,
        fd: int | None,
        all_ips: dict,
        socket_types: Sequence[socket.AddressFamily | int],
    ) -> list[dict]:
    all_query_stats = []
    old_cache = root_hints
    af_to_qtype: dict[int, dns.rdatatype.RdataType] = {
        socket.AF_INET: dns.rdatatype.A,
        socket.AF_INET6: dns.rdatatype.AAAA,
    }

    while len(old_cache) > 0:
        qtype_list = [af_to_qtype[af] for af in socket_types]
        (reply_hints, new_domain, query_stats) = query_all(
            fqdn, old_cache, qtype_list, cli_args.tcp, fd, cli_args.gt, all_ips, socket_types)
        all_query_stats.extend(query_stats)
        old_cache = reply_hints
        if new_domain is not None:
            msg = f"(re)querying for {fqdn} due to CNAME to {new_domain}"
            print(msg)
            _write_report_line(fd, msg)
            fqdn = new_domain
            old_cache = root_hints
        print("===================")
        _write_report_line(fd, "===================")

    return all_query_stats


def _write_report_line(fd: int | None, line: str) -> None:
    if fd is None:
        return
    os.write(fd, str.encode(line + '\n'))


def _write_identity_queries(fd: int, all_ips: dict, ts: str) -> None:
    for ip in all_ips:
        _write_report_line(fd, f"# {ip}")
        _write_report_line(fd, f"dig +noall +answer +stats @{ip} identity.nameserver.id ch txt")
        identity = dns.message.make_query("identity.nameserver.id", dns.rdatatype.TXT, rdclass=dns.rdataclass.CHAOS)
        try:
            resp = dns.query.udp(identity, ip, timeout=10)
            for var in resp.answer:
                for i in var.items:
                    msg = f'"{ts}";"{ip}";{i}'
                    _write_report_line(fd, msg)
                    print(msg)
        except (dns.exception.DNSException, OSError) as e:
            msg = f"{e}:{ip}"
            print(msg)
            _write_report_line(fd, msg)
        _write_report_line(fd, f"mtr -bw {ip}")


def _print_query_statistics(all_query_stats: list[dict], fd: int | None) -> None:
    if not all_query_stats:
        return

    print("\nQuery Statistics Analysis:")
    print("=" * 50)

    # Group by TTL ranges
    ttl_ranges = {}
    for stat in all_query_stats:
        ttl_key = f"{stat['nameserver']}"
        if ttl_key not in ttl_ranges:
            ttl_ranges[ttl_key] = {
                'count': 0,
                'latencies': [],
                'nameservers': set(),
                'ttl': None,
            }
        ttl_ranges[ttl_key]['count'] += 1
        ttl_ranges[ttl_key]['latencies'].append(stat['latency'])
        ttl_ranges[ttl_key]['nameservers'].add(stat['nameserver'])
        ttl_ranges[ttl_key]['ttl'] = stat['ttl']

    avg_list = []
    min_list = []
    max_list = []
    stddev_list = []
    ttl_list = []
    count_list = []

    # Calculate and display statistics for each TTL range
    for delegation, data in ttl_ranges.items():
        avg_latency = statistics.mean(data['latencies'])
        min_latency = min(data['latencies'])
        max_latency = max(data['latencies'])
        stddev = statistics.stdev(data['latencies']) if len(data['latencies']) > 1 else 0

        # Find IP addresses and nameservers associated with min and max latencies
        min_ip = None
        max_ip = None
        min_ns = None
        max_ns = None
        for stat in all_query_stats:
            if stat['nameserver'] != delegation:
                continue
            if stat['latency'] == min_latency:
                min_ip = stat['ip']
                # Find the nameserver that maps to this IP
                for ns_stat in all_query_stats:
                    if ns_stat['ip'] == min_ip:
                        min_ns = ns_stat['nsname']
                        break
            if stat['latency'] == max_latency:
                max_ip = stat['ip']
                # Find the nameserver that maps to this IP
                for ns_stat in all_query_stats:
                    if ns_stat['ip'] == max_ip:
                        max_ns = ns_stat['nsname']
                        break

        print(f"\nDelegation: {delegation}")
        print(f"Number of queries: {data['count']}")
        print(f"TTL: {data['ttl']}")
        print("Latency statistics (ms):")
        print(f"  Average: {avg_latency:.2f}")
        print(f"  Min: {min_latency:.2f} (IP: {min_ip}, NS: {min_ns})")
        print(f"  Max: {max_latency:.2f} (IP: {max_ip}, NS: {max_ns})")
        print(f"  StdDev: {stddev:.2f}")

        avg_list.append(avg_latency)
        min_list.append(min_latency)
        max_list.append(max_latency)
        stddev_list.append(stddev)
        ttl_list.append(data['ttl'])
        count_list.append(data['count'])

        _write_report_line(fd, f"\nDelegation: {delegation}")
        _write_report_line(fd, f"Number of queries: {data['count']}")
        _write_report_line(fd, f"TTL: {data['ttl']}")
        _write_report_line(fd, "Latency statistics (ms):")
        _write_report_line(fd, f"  Average: {avg_latency:.2f}")
        _write_report_line(fd, f"  Min: {min_latency:.2f} (IP: {min_ip}, NS: {min_ns})")
        _write_report_line(fd, f"  Max: {max_latency:.2f} (IP: {max_ip}, NS: {max_ns})")
        _write_report_line(fd, f"  StdDev: {stddev:.2f}")

##     rtt_val = 0.0
##     ttl_pct = 0
##     #
##     with open('data.json', 'w') as f:
##         rtt_vals = []
##         for ttl_v in ttl_list:
##             ttl_pct = ttl_pct + (1/ttl_v)
## #            rtt_vals.append(list(numpy.random.uniform(min_v, max_v, 100000)))
##         data_dict = {'rtt_values': rtt_vals, 'ttl_odds': f"{ttl_pct:.8f}",
##             'avg_list': avg_list, 'min_list': min_list, 'max_list': max_list, 'stddev_list': stddev_list,
##             'ttl_list': ttl_list, 'count_list': count_list }
##         json.dump(data_dict, f, indent=2)
##
##     ttl_pct = ttl_pct * 100.0
##     # likelyhood that any given ttl might expire at any given second
##     print(f"ttl_pct={ttl_pct:.5f}")


def has_ipv6_connectivity() -> bool:
    """Test if IPv6 connectivity is available by attempting to connect to a root server.

    Returns:
        bool: True if IPv6 connectivity is available, False otherwise.
    """

    test_addr = "2001:503:ba3e::2:30"  # a.root-servers.net IPv6
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.connect((test_addr, 53))
    except OSError:
        return False
    else:
        return True


def upload_report_file(fn_path: Path, url: str) -> None:
    """Upload a report file and remove it after the upload attempt."""
    try:
        with fn_path.open("rb") as f:
            post_response = requests.post(
                url,
                data={'file': str(fn_path)},
                files={'file': f},
                timeout=10,
                verify=True,
            )
        if post_response.ok:
            print("Upload successful:", post_response.text)
        else:
            print(f"Upload failed with status code: {post_response.status_code}")

    except (requests.RequestException, OSError) as e:
        print(f"Error during upload: {e}")
    finally:
        with contextlib.suppress(OSError):
            fn_path.unlink()


def main() -> None:
    """ Parse command-line arguments, query each requested domain, and optionally save/upload reports. """

    # define a parser
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument('domains', nargs='+', help="one or more domain names to query")  # allow multiple domains

    ip_group = parser.add_mutually_exclusive_group()
    ip_group.add_argument('-4', '--ipv4', action='store_true', help="query ipv4-only")
    ip_group.add_argument('-6', '--ipv6', action='store_true', help="query ipv6-only")

    parser.add_argument('-t', '--tcp', action='store_true', help="send queries over TCP")  # use TCP
    parser.add_argument('-r', '--report', metavar='REPORT_FILE', type=str, help="Save results to specified file")
    parser.add_argument('-g', '--gt', action='store_true', help="greater than 100ms only")
    parser.add_argument('-u', '--upload', action='store_true', help="requires -r - uploads report to hardcoded url")
    parser.add_argument('-v', '--verbose', action='store_true', help="enable verbose debugging output")

    args = parser.parse_args()

    socket_af_types = (
        [socket.AF_INET] if args.ipv4 else
        [socket.AF_INET6] if args.ipv6 else
        [socket.AF_INET, socket.AF_INET6]
    )

    # Auto-detect and filter unavailable address families
    if socket.AF_INET6 in socket_af_types and not has_ipv6_connectivity():
        print("Note: IPv6 connectivity unavailable, using IPv4 only")
        socket_af_types = [socket.AF_INET]

    # XXX Replace me if you are going to use -u flag
    url = "https://www.example.com/upload/upload_file.php"

    # Iterate through all specified domains
    for domain in args.domains:
        print(f"\nProcessing domain: {domain}")
        print("=" * 50)

        fn = query_domain(domain, args, socket_af_types, verbose=args.verbose)
        if fn is None:
            print("=" * 50)
            continue

        print(f"fn={fn}")
        if args.upload:
            upload_report_file(Path(fn), url)
        print("=" * 50)

    # internal statistics
    # print(f"addrinfo_cache_hits={addrinfo_cache_hits} - cache size:", len(addrinfo_cache))


if __name__ == '__main__':
    main()
