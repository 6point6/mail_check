# mail_check
Script for checking the DNS record of a domain.

Uses python library checkdmarc, which works when provided with a name server. See https://github.com/domainaware/checkdmarc/blob/master/checkdmarc.py.

# Example
```Shell
$ python3 mail_check/mail_check.py bbc.co.uk
Pure domain = bbc.co.uk

==== Hosts ====
Hostname: cluster1.eu.messagelabs.com, preference: 10, TLS: True, starttls: True.
Addresses: 46.226.52.106, 46.226.52.193, 46.226.52.202, 46.226.52.97, 85.158.142.106, 85.158.142.196, 85.158.142.202, 85.158.142.97, 

Hostname: cluster1a.eu.messagelabs.com, preference: 20, TLS: False, starttls: False.
Addresses: 35.157.65.66, 52.58.124.202, 52.58.21.128, 

Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 46.226.52.106 is mail270.messagelabs.com, but the A/AAAA DNS records for mail270.messagelabs.com do not resolve to 46.226.52.106
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 46.226.52.193 is mail281.messagelabs.com, but the A/AAAA DNS records for mail281.messagelabs.com do not resolve to 46.226.52.193
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 46.226.52.202 is mail290.messagelabs.com, but the A/AAAA DNS records for mail290.messagelabs.com do not resolve to 46.226.52.202
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 46.226.52.97 is mail261.messagelabs.com, but the A/AAAA DNS records for mail261.messagelabs.com do not resolve to 46.226.52.97
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 85.158.142.106 is mail231.messagelabs.com, but the A/AAAA DNS records for mail231.messagelabs.com do not resolve to 85.158.142.106
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 85.158.142.196 is mail241.messagelabs.com, but the A/AAAA DNS records for mail241.messagelabs.com do not resolve to 85.158.142.196
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 85.158.142.202 is mail247.messagelabs.com, but the A/AAAA DNS records for mail247.messagelabs.com do not resolve to 85.158.142.202
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 85.158.142.97 is mail222.messagelabs.com, but the A/AAAA DNS records for mail222.messagelabs.com do not resolve to 85.158.142.97
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 35.157.65.66 is ec2-35-157-65-66.eu-central-1.compute.amazonaws.com, but the A/AAAA DNS records for ec2-35-157-65-66.eu-central-1.compute.amazonaws.com do not resolve to 35.157.65.66
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 52.58.124.202 is ec2-52-58-124-202.eu-central-1.compute.amazonaws.com, but the A/AAAA DNS records for ec2-52-58-124-202.eu-central-1.compute.amazonaws.com do not resolve to 52.58.124.202
Warning: The DNS operation timed out after 2.0 seconds
Warning: The reverse DNS of 52.58.21.128 is ec2-52-58-21-128.eu-central-1.compute.amazonaws.com, but the A/AAAA DNS records for ec2-52-58-21-128.eu-central-1.compute.amazonaws.com do not resolve to 52.58.21.128
Warning: STARTTLS is not supported on cluster1a.eu.messagelabs.com
Warning: SSL/TLS is not supported on cluster1a.eu.messagelabs.com

==== DMARC ====
Location:       bbc.co.uk
Raw Record:     v=DMARC1;p=none;aspf=r;pct=100;fo=0;ri=86400;rua=mailto:bbcuk_rua@dmeu.easysol.net;ruf=mailto:bbcuk_ruf@dmeu.easysol.net;
Version:        DMARC1
Requested Mail Receiver Policy: True (none)
Explicit alignment mode for DKIM:       False
Explicit alignment mode for SPF:        True
SPF Value:      r
Aggregate Report Mailbox (RUA): True (Address: bbcuk_rua@dmeu.easysol.net, scheme: mailto)
Forensic Report Mailbox (RUF): True (Address: bbcuk_ruf@dmeu.easysol.net, scheme: mailto)
Percent of mail to apply rules to: True (100)
Sub-Policy: False (none)
Authentication and/or alignment vulnerabilities: True (['0'])
Report Format: False (['afrf'])
Seconds between agregating reports: True (86400)

==== Domains ====
[]


==== SPF ====
SPF Record: v=spf1 ip4:212.58.224.0/19 ip4:132.185.0.0/16 ip4:78.136.53.80/28 ip4:78.136.14.192/27 ip4:78.136.19.8/29 ip4:89.234.10.72/29 ip4:89.234.53.236 ip4:212.111.33.181 ip4:78.137.117.8 ip4:46.37.176.74 ip4:159.253.62.157 ip4:185.119.233.144/30 ip4:185.119.232.158 +include:sf.sis.bbc.co.uk +include:spf.messagelabs.com +include:servers.mcsv.net +include:amazonses.com ?all

Warning: ['SPF type DNS records found. Use of DNS Type SPF has been removed in the standards track version of SPF, RFC 7208. These records should be removed and replaced with TXT records: v=spf1 ip4:212.58.224.0/19 ip4:132.185.0.0/16 ip4:78.136.53.80/28 ip4:78.136.14.192/27 ip4:78.136.19.8/29 ip4:89.234.10.72/29 ip4:89.234.53.236 ip4:212.111.33.181 ip4:78.137.117.8 ip4:46.37.176.74 ip4:159.253.62.157  ip4:185.119.233.144/30 ip4:185.119.232.158 +include:sf.sis.bbc.co.uk +include:spf.messagelabs.com +include:servers.mcsv.net +include:amazonses.com ?all']
```
