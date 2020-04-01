# mail_check
Script for checking the DNS record of a domain.

Uses python library checkdmarc, which works when provided with a name server. See https://github.com/domainaware/checkdmarc/blob/master/checkdmarc.py.

First own the libs:
```
pip3 install checkdmarc; pip3 install tabulate
```
# Running
```shell
> python3 ./mail_check.py -h
usage: mail_check.py [-h] [-d D] [-f]

Mail record checking utility

optional arguments:
  -h, --help  show this help message and exit
  -d D        The domain record to test
  -f          Run all tests
```

## Example
Run with "-d" and the domain to do a DMARC check:
```Shell
> python3 ./mail_check.py -d 6point6.co.uk
Pure domain = "6point6.co.uk"

==== DMARC ====
Problem found: second entry should be 'p',currently set to "rua=mailto:55d7175f07@rep.dmarcanalyzer.com"

Problem found: DMARC record "p" tag is set to "none", which does not prevent abuse on your domain. If you are satisfied with the authentication success of your sending sources, move your policy to a 'p=quarantine' or 'p=reject'.

Field       Value
----------  -------------------------------------------------------------------------------------------------
Location    6point6.co.uk
Version     DMARC1
Raw Record  v=DMARC1; rua=mailto:55d7175f07@rep.dmarcanalyzer.com; p=none; pct=100; sp=none; adkim=r; aspf=r;

Fields:

Key    Set          Value                                       Comment
-----  -----------  ------------------------------------------  ----------------------------------------------------------
p      True         none                                        No specific action be taken on mail that fails
                                                                DMARC authentication and alignment.
adkim  True         r                                           Relaxed Mode allows Authenticated DKIM/SPF domains
                                                                that share a common Organizational Domain
                                                                with an email's "header-From:"
                                                                domain to pass the DMARC check.
aspf   True         r                                           Relaxed Mode allows Authenticated DKIM/SPF domains
                                                                that share a common Organizational Domain
                                                                with an email's "header-From:"
                                                                domain to pass the DMARC check.
rua    True         Address: 55d7175f07@rep.dmarcanalyzer.com,  Indicates where aggregate DMARC reports should be sent to.
                    scheme: mailto
ruf    Not Defined  Not Defined                                 Indicates where forensic DMARC reports should be sent to.
pc     True         100                                         Percentage of messages to which the
                                                                DMARC policy is to be applied.
                                                                This parameter provides a way to gradually
                                                                implement and test the impact of the policy.
sp     True         none                                        (Sub-Domains) No specific action be taken on mail
                                                                that fails DMARC authentication and alignment.
fo     False        0                                           Generate a DMARC failure report if all
                                                                underlying authentication mechanisms
                                                                fail to produce an aligned “pass” result. (Default)
rf     False        afrf                                        The reporting format for individual Forensic reports.
                                                                Authorized values: “afrf”, “iodef”.
ri     False        86400                                       The number of seconds elapsed between
                                                                sending aggregate reports to the sender.
                                                                The default value is 86,400 seconds or a day.
```

The "-f" option gives full results that include host and SPF records:
```shell
> python3 ./mail_check.py -d 6point6.co.uk -f
Pure domain = "6point6.co.uk"

==== DMARC ====
Problem found: second entry should be 'p',currently set to "rua=mailto:55d7175f07@rep.dmarcanalyzer.com"

Problem found: DMARC record "p" tag is set to "none", which does not prevent abuse on your domain. If you are satisfied with the authentication success of your sending sources, move your policy to a 'p=quarantine' or 'p=reject'.
Field       Value
----------  -------------------------------------------------------------------------------------------------
Location    6point6.co.uk
Version     DMARC1
Raw Record  v=DMARC1; rua=mailto:55d7175f07@rep.dmarcanalyzer.com; p=none; pct=100; sp=none; adkim=r; aspf=r;

Fields:

Key    Set          Value                                       Comment
-----  -----------  ------------------------------------------  ----------------------------------------------------------
p      True         none                                        No specific action be taken on mail that fails
                                                                DMARC authentication and alignment.
adkim  True         r                                           Relaxed Mode allows Authenticated DKIM/SPF domains
                                                                that share a common Organizational Domain
                                                                with an email's "header-From:"
                                                                domain to pass the DMARC check.
aspf   True         r                                           Relaxed Mode allows Authenticated DKIM/SPF domains
                                                                that share a common Organizational Domain
                                                                with an email's "header-From:"
                                                                domain to pass the DMARC check.
rua    True         Address: 55d7175f07@rep.dmarcanalyzer.com,  Indicates where aggregate DMARC reports should be sent to.
                    scheme: mailto
ruf    Not Defined  Not Defined                                 Indicates where forensic DMARC reports should be sent to.
pc     True         100                                         Percentage of messages to which the
                                                                DMARC policy is to be applied.
                                                                This parameter provides a way to gradually
                                                                implement and test the impact of the policy.
sp     True         none                                        (Sub-Domains) No specific action be taken on mail
                                                                that fails DMARC authentication and alignment.
fo     False        0                                           Generate a DMARC failure report if all
                                                                underlying authentication mechanisms
                                                                fail to produce an aligned “pass” result. (Default)
rf     False        afrf                                        The reporting format for individual Forensic reports.
                                                                Authorized values: “afrf”, “iodef”.
ri     False        86400                                       The number of seconds elapsed between
                                                                sending aggregate reports to the sender.
                                                                The default value is 86,400 seconds or a day.

==== Hosts ====
Hostname: aspmx.l.google.com, preference: 10, TLS: True, starttls: True.
Addresses: 2a00:1450:400c:c01::1a, 74.125.133.26, 

Hostname: alt1.aspmx.l.google.com, preference: 20, TLS: True, starttls: True.
Addresses: 209.85.233.27, 2a00:1450:4010:c03::1a, 

Hostname: alt2.aspmx.l.google.com, preference: 20, TLS: True, starttls: True.
Addresses: 142.250.4.27, 2404:6800:4003:c06::1a, 

Hostname: aspmx2.googlemail.com, preference: 30, TLS: True, starttls: True.
Addresses: 209.85.233.26, 2a00:1450:4010:c03::1b, 

Hostname: aspmx3.googlemail.com, preference: 40, TLS: True, starttls: True.
Addresses: 142.250.4.27, 2404:6800:4003:c06::1a, 

Warning: 142.250.4.27 does not have any reverse DNS (PTR) records
Warning: 2404:6800:4003:c06::1a does not have any reverse DNS (PTR) records
Warning: 142.250.4.27 does not have any reverse DNS (PTR) records
Warning: 2404:6800:4003:c06::1a does not have any reverse DNS (PTR) records

==== Domains ====
None found

==== SPF ====
SPF Record: v=spf1 include:servers.mcsv.net include:_spf.google.com ip4:78.137.112.53 include:_spf.salesforce.com ~all
```
