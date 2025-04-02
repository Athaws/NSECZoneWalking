# NSEC ZoneWalking tool
A tool in Python for performing Zone Walking using NSEC posts, developed as a fun side project for the course DVGC28 at Karlstad University

## Requirements
```bash
pip install dnspython
```

## Usage
```bash
python3 ./zonewalk.py -d <domain> -n <nameserver>
```
Works best if the nameserver is the authourative one for the starting domain;
The tool will figure out the rest of the nameservers needed for walking any nodes further down.

## Example output (to stdout): `./zonewalk.py -d inforing.se -n bill.ip.se` - for the file that is generated see file inforing.se.zone
```
=== Zone Walking for inforing.se. ===

[*] Starting NSEC-walk for inforing.se.

[+] Node: inforing.se.
  NS:
    • boll.ip.se
    • bill.ip.se
    • bull.ip.se
    • bell.ip.se
    • ball.ip.se
  A:
    • 46.21.96.58
  AAAA:
    • 2a02:750:12::80
  MX:
    • 10 mx1.egensajt.se.
    • 20 mx3.egensajt.se.
    • 10 mx2.egensajt.se.
    • 30 mx4.egensajt.se.
  TXT:
    • v=spf1 include:spf.egensajt.se ~all
  SOA:
    • boll.ip.se. msb.ip.se. 2023010728 21600 3600 604800 86400
  CAA:
    • 0 issue "letsencrypt.org"

[+] Node: _dmarc.inforing.se.
  TXT:
    • v=DMARC1; p=reject

[+] Node: dkim._domainkey.inforing.se.
  CNAME:
    • dkim.egensajt.se.

[+] Node: stenspade.inforing.se.
  A:
    • 1.2.3.4

[+] Node: www.inforing.se.
  CNAME:
    • inforing.se.

[+] NSEC-walk complete. Found 5 nodes total
```
