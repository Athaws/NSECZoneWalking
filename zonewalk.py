#!/usr/bin/env python3
import argparse
import dns.zone
import dns.query
import dns.resolver
import dns.exception
from dns.rdatatype import *
from dns.rdata import _base64ify
from typing import Dict, List, Optional, Any

class ZoneWalker:
    def __init__(self, domain: str, nameserver: Optional[str] = None):
        self.domain = domain + "." if not domain.endswith(".") else domain
        self.nameserver = nameserver
        self.resolver = dns.resolver.Resolver()
        if nameserver:
            try:
                if not nameserver.replace('.', '').isdigit():
                    ns_ip = str(dns.resolver.resolve(nameserver, 'A')[0])
                    self.resolver.nameservers = [ns_ip]
                else:
                    self.resolver.nameservers = [nameserver]
            except dns.exception.DNSException:
                raise ValueError(f"Could not resolve nameserver {nameserver} to IP")

    def format_rdata(self, rdata: Any) -> str:
        match rdata.__class__.__name__:
            case 'A' | 'AAAA':
                return rdata.address
            case 'MX':
                return f"{rdata.preference} {rdata.exchange}"
            case 'NS':
                return str(rdata.target)
            case 'SOA':
                return (f"{rdata.mname} {rdata.rname} {rdata.serial} "
                       f"{rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}")
            case 'TXT':
                return ' '.join([s.decode() for s in rdata.strings])
            case 'CNAME':
                return str(rdata.target)
            case 'PTR':
                return str(rdata.target)
            case 'SRV':
                return f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
            case 'DNSKEY':
                return (f"flags:{rdata.flags} protocol:{rdata.protocol} "
                       f"algorithm:{rdata.algorithm} key:{_base64ify(rdata.key).replace(' ', '')}")
            case 'RRSIG':
                return (f"{rdata.type_covered} {rdata.algorithm} {rdata.labels} "
                       f"{rdata.original_ttl} {rdata.expiration} {rdata.inception} "
                       f"{rdata.key_tag} {rdata.signer} {rdata.signature}")
            case 'DS':
                return (f"{rdata.key_tag} {rdata.algorithm} {rdata.digest_type} "
                       f"{_base64ify(rdata.digest).replace(' ', '')}")
            case _:
                return str(rdata)
    
    def get_all_records(self, node: str) -> Dict[str, List[str]]:
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'DNAME', 'NS', 'SOA', 'PTR', 'SRV', 'CAA']
        records = {}
        seen_values = {rtype: set() for rtype in record_types}

        try:
            cname_answer = self.resolver.resolve(node, 'CNAME')
            for r in cname_answer:
                formatted = self.format_rdata(r)
                if formatted not in seen_values['CNAME']:
                    records.setdefault('CNAME', []).append(formatted)
                    seen_values['CNAME'].add(formatted)
            if 'CNAME' in records:
                return records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException as e:
            print(f"[-] Error in CNAME lookup: {e}")

        ns_data = self._get_ns_with_ips(node)
        if ns_data:
            records['NS'] = ns_data
        
        for rtype in record_types:
            if rtype in ['CNAME', 'NS']:
                continue
                
            try:
                answer = self.resolver.resolve(node, rtype)
                for r in answer:
                    formatted = self.format_rdata(r)
                    if formatted not in seen_values[rtype]:
                        records.setdefault(rtype, []).append(formatted)
                        seen_values[rtype].add(formatted)
            except dns.resolver.NoAnswer:
                if ns_data:
                    for result in self._query_via_ns(node, rtype, ns_data):
                        if result not in seen_values[rtype]:
                            records.setdefault(rtype, []).append(result)
                            seen_values[rtype].add(result)
                else:
                    pass
            except dns.exception.DNSException as e:
                print(f"[-] Error fetching {rtype}: {e}")

        return records

    def _get_ns_with_ips(self, node: str) -> Dict[str, List[str]]:
        ns_data = {}
        seen_ips = set()
        
        try:
            answer = self.resolver.resolve(node, 'NS', raise_on_no_answer=False)
            response = answer.response

            ns_names = set()
            for section in [response.answer, response.authority]:
                for rrset in section:
                    if rrset.rdtype == dns.rdatatype.NS:
                        ns_names.update(str(ns.target).rstrip('.') for ns in rrset)

            for rrset in response.additional:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    ns_name = str(rrset.name).rstrip('.')
                    if ns_name in ns_names:
                        ip = rrset[0].address
                        if ip not in seen_ips:
                            ns_data.setdefault(ns_name, []).append(ip)
                            seen_ips.add(ip)

            for ns_name in ns_names:
                if ns_name not in ns_data:
                    try:
                        a_answer = self.resolver.resolve(ns_name, 'A')
                        for r in a_answer:
                            ip = str(r.address)
                            if ip not in seen_ips:
                                ns_data.setdefault(ns_name, []).append(ip)
                                seen_ips.add(ip)
                        try:
                            aaaa_answer = self.resolver.resolve(ns_name, 'AAAA')
                            for r in aaaa_answer:
                                ip = str(r.address)
                                if ip not in seen_ips:
                                    ns_data.setdefault(ns_name, []).append(ip)
                                    seen_ips.add(ip)
                        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                            print(f"[-] Could not resolve IPv6 addresses for {ns_name}")
                    except dns.exception.DNSException as e:
                        print(f"[-] Error resolving {ns_name}: {e}")

            return ns_data
        except dns.exception.DNSException as e:
            print(f"[-] Error fetching NS records: {e}")
            return {}

    def _query_via_ns(self, node: str, rtype: str, ns_data: Dict[str, List[str]]) -> List[str]:
        results = []
        original_ns = self.resolver.nameservers.copy()
        seen_values = set()
        
        for ns_name, ips in ns_data.items():
            for ip in ips:
                try:
                    self.resolver.nameservers = [ip]
                    answer = self.resolver.resolve(node, rtype, raise_on_no_answer=False)
                    for r in answer:
                        formatted = self.format_rdata(r)
                        if formatted not in seen_values:
                            results.append(formatted)
                            seen_values.add(formatted)
                    break
                except dns.exception.DNSException as e:
                    print(f"  [-] Failed via {ns_name} ({ip}): {str(e)}")
                finally:
                    self.resolver.nameservers = original_ns
        
        return results
    
    def generate_zone_file(self, records: Dict[str, Dict[str, List[str]]]) -> str:
        soa_values = None
        for node_data in records.values():
            if 'SOA' in node_data and node_data['SOA']:
                soa_values = node_data['SOA'][0].split()
                break
        
        if not soa_values:
            return ""

        zone_header = f"""$ORIGIN {self.domain}
$TTL {soa_values[-1]}  ; minimum TTL from SOA
@       IN SOA  {soa_values[0]} {soa_values[1]} (
                {soa_values[2]} ; serial
                {soa_values[3]} ; refresh
                {soa_values[4]} ; retry
                {soa_values[5]} ; expire
                {soa_values[6]} ; minimum TTL
                )\n\n"""
        
        zone_records = []
        seen_lines = set()
        
        for node, node_data in records.items():
            node_name = node if node.endswith('.') else f"{node}.{self.domain}."
            
            for rtype, values in node_data.items():
                if rtype == 'SOA':
                    continue
                    
                if rtype == 'NS':
                    for ns_name, ips in values.items():
                        ns_name_fqdn = ns_name if ns_name.endswith('.') else f"{ns_name}."
                        record_line = f'{node_name.ljust(20)} IN NS    {ns_name_fqdn}'
                        if record_line not in seen_lines:
                            zone_records.append(record_line)
                            seen_lines.add(record_line)
                        
                        if ns_name.rstrip('.').endswith(self.domain.rstrip('.')):
                            for ip in ips:
                                ip_type = 'A' if ':' not in ip else 'AAAA'
                                glue_line = f'{ns_name_fqdn.ljust(20)} IN {ip_type.ljust(6)} {ip}'
                                if glue_line not in seen_lines:
                                    zone_records.append(glue_line)
                                    seen_lines.add(glue_line)
                elif rtype in ['A', 'AAAA', 'CNAME', 'PTR', 'DNAME']:
                    for value in values:
                        record_line = f'{node_name.ljust(20)} IN {rtype.ljust(6)} {value}'
                        if record_line not in seen_lines:
                            zone_records.append(record_line)
                            seen_lines.add(record_line)
                elif rtype == 'MX':
                    for value in values:
                        pref, exchange = value.split()
                        record_line = f'{node_name.ljust(20)} IN MX    {pref} {exchange}'
                        if record_line not in seen_lines:
                            zone_records.append(record_line)
                            seen_lines.add(record_line)
                elif rtype == 'TXT':
                    for value in values:
                        record_line = f'{node_name.ljust(20)} IN TXT   "{value}"'
                        if record_line not in seen_lines:
                            zone_records.append(record_line)
                            seen_lines.add(record_line)
        
        return zone_header + "\n".join(sorted(zone_records)) + "\n"

    def nsec_walk(self) -> Dict[str, Dict[str, List[str]]]:
        results = {}
        print(f"[*] Starting NSEC-walk for {self.domain}")
        
        try:
            current_node = self.domain
            seen_nodes = set()
            
            while current_node not in seen_nodes:
                seen_nodes.add(current_node)
                current_records = self.get_all_records(current_node)
                results[current_node] = current_records
                
                print(f"\n[+] Node: {current_node}")
                for rtype, values in current_records.items():
                    print(f"  {rtype}:")
                    for value in values:
                        print(f"    • {value}")
                
                try:
                    nsec_rrset = self.resolver.resolve(current_node, 'NSEC').rrset[0]
                    next_node = str(nsec_rrset.next)
                    
                    if next_node == self.domain or next_node in seen_nodes:
                        break
                        
                    current_node = next_node
                    
                except dns.exception.DNSException as e:
                    print(f"[-] Error getting NSEC for {current_node}: {e}")
                    break
            
            print(f"\n[+] NSEC-walk complete. Found {len(results)} nodes total")
            return results
            
        except dns.exception.DNSException as e:
            print(f"[-] NSEC-walk not possible: {e} (zone may not be DNSSEC-signed)")
            return {}

    def run(self):
        print(f"\n=== Zone Walking for {self.domain} ===\n")
        
        records = self.nsec_walk()
        zone_content = self.generate_zone_file(records)
        with open(self.domain.rstrip('.') + '.zone', 'w') as f:
            f.write(zone_content)
        exit()

def main():
    parser = argparse.ArgumentParser(
        description="Simple Zone Walking Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, help="Domain to investigate")
    parser.add_argument("-n", "--nameserver", help="Specific nameserver to use")
    args = parser.parse_args()

    try:
        walker = ZoneWalker(args.domain, args.nameserver)
        walker.run()
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nInterrupted by user")

if __name__ == "__main__":
    main()
