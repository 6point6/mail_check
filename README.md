# Overview
Script for checking the DMARC, SPF parts of a domain DNS record.

Uses python library [checkdmarc](https://github.com/domainaware/checkdmarc/blob/master/checkdmarc.py), which works when provided with a name server.

SPF breakdown text taken from [dmarcian.com](https://dmarcian.com/spf-syntax-table/).

## Pre-Reqs
First, own the libs:
```
pip3 install checkdmarc tabulate
```

# Running
```shell
usage: mail_check.py [-h] [-d D] [-l L] [-f]

Mail record checking utility

optional arguments:
  -h, --help  show this help message and exit
  -d D        The domain record to test
  -l L        File of domains to test, one domain per line
  -f          Run all tests
```

## Example
Run with "-d" and the domain to do a DMARC and SPF check:
```Shell
> python3 mail_check.py -d 6point6.co.uk
Pure domain = "6point6.co.uk"


==== DMARC ====
Field       Value
----------  -------------------------------------------------------------------------------------------------------
Location    6point6.co.uk
Version     DMARC1
Raw Record  v=DMARC1; p=quarantine; rua=mailto:55d7175f07@rep.dmarcanalyzer.com; pct=100; sp=none; adkim=r; aspf=r;

Fields:

+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| Key   | Set         | Value                                      | Comment                                                          |
+=======+=============+============================================+==================================================================+
| p     | True        | quarantine                                 | Mail failing the DMARC authentication and alignment              |
|       |             |                                            | checks be treated as suspicious by mail receivers.               |
|       |             |                                            | This can mean receivers place the email in the spam/junk folder, |
|       |             |                                            | flag as it suspicious                                            |
|       |             |                                            | or scrutinize this mail with extra intensity.                    |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| adkim | True        | r                                          | Relaxed Mode allows Authenticated DKIM/SPF domains               |
|       |             |                                            | that share a common Organizational Domain                        |
|       |             |                                            | with an email's "header-From:"                                   |
|       |             |                                            | domain to pass the DMARC check.                                  |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| aspf  | True        | r                                          | Relaxed Mode allows Authenticated DKIM/SPF domains               |
|       |             |                                            | that share a common Organizational Domain                        |
|       |             |                                            | with an email's "header-From:"                                   |
|       |             |                                            | domain to pass the DMARC check.                                  |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| rua   | True        | Address: 55d7175f07@rep.dmarcanalyzer.com, | Indicates where aggregate DMARC reports should be sent to.       |
|       |             | scheme: mailto                             |                                                                  |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| ruf   | Not Defined | Not Defined                                | Indicates where forensic DMARC reports should be sent to.        |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| pc    | True        | 100                                        | Percentage of messages to which the                              |
|       |             |                                            | DMARC policy is to be applied.                                   |
|       |             |                                            | This parameter provides a way to gradually                       |
|       |             |                                            | implement and test the impact of the policy.                     |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| sp    | True        | none                                       | (Sub-Domains) No specific action be taken on mail                |
|       |             |                                            | that fails DMARC authentication and alignment.                   |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| fo    | False       | 0                                          | Generate a DMARC failure report if all                           |
|       |             |                                            | underlying authentication mechanisms                             |
|       |             |                                            | fail to produce an aligned “pass” result. (Default)              |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| rf    | False       | afrf                                       | The reporting format for individual Forensic reports.            |
|       |             |                                            | Authorized values: “afrf”, “iodef”.                              |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| ri    | False       | 86400                                      | The number of seconds elapsed between                            |
|       |             |                                            | sending aggregate reports to the sender.                         |
|       |             |                                            | The default value is 86,400 seconds or a day.                    |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+

==== SPF ====
Raw SPF Record: v=spf1 include:servers.mcsv.net include:_spf.google.com include:servers.outfunnel.com ~all

Details:
Version: v=spf1
~all means soft fail mail that doesn't match a rule - accept but tag

Included senders: 
+-------------------+-----------------------+-------------+
| Type              | Value                 | Detail      |
+===================+=======================+=============+
| Known mail server | servers.mcsv.net      | Mailchimp   |
+-------------------+-----------------------+-------------+
| Known mail server | _spf.google.com       | Google Mail |
+-------------------+-----------------------+-------------+
| Known mail server | servers.outfunnel.com | OutFunnel   |
+-------------------+-----------------------+-------------+

Excluded senders:
None

```

The "-f" option gives full results, which include host records:
```shell
> python3 mail_check.py -d 6point6.co.uk
Pure domain = "6point6.co.uk"


==== DMARC ====
Field       Value
----------  -------------------------------------------------------------------------------------------------------
Location    6point6.co.uk
Version     DMARC1
Raw Record  v=DMARC1; p=quarantine; rua=mailto:55d7175f07@rep.dmarcanalyzer.com; pct=100; sp=none; adkim=r; aspf=r;

Fields:

+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| Key   | Set         | Value                                      | Comment                                                          |
+=======+=============+============================================+==================================================================+
| p     | True        | quarantine                                 | Mail failing the DMARC authentication and alignment              |
|       |             |                                            | checks be treated as suspicious by mail receivers.               |
|       |             |                                            | This can mean receivers place the email in the spam/junk folder, |
|       |             |                                            | flag as it suspicious                                            |
|       |             |                                            | or scrutinize this mail with extra intensity.                    |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| adkim | True        | r                                          | Relaxed Mode allows Authenticated DKIM/SPF domains               |
|       |             |                                            | that share a common Organizational Domain                        |
|       |             |                                            | with an email's "header-From:"                                   |
|       |             |                                            | domain to pass the DMARC check.                                  |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| aspf  | True        | r                                          | Relaxed Mode allows Authenticated DKIM/SPF domains               |
|       |             |                                            | that share a common Organizational Domain                        |
|       |             |                                            | with an email's "header-From:"                                   |
|       |             |                                            | domain to pass the DMARC check.                                  |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| rua   | True        | Address: 55d7175f07@rep.dmarcanalyzer.com, | Indicates where aggregate DMARC reports should be sent to.       |
|       |             | scheme: mailto                             |                                                                  |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| ruf   | Not Defined | Not Defined                                | Indicates where forensic DMARC reports should be sent to.        |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| pc    | True        | 100                                        | Percentage of messages to which the                              |
|       |             |                                            | DMARC policy is to be applied.                                   |
|       |             |                                            | This parameter provides a way to gradually                       |
|       |             |                                            | implement and test the impact of the policy.                     |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| sp    | True        | none                                       | (Sub-Domains) No specific action be taken on mail                |
|       |             |                                            | that fails DMARC authentication and alignment.                   |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| fo    | False       | 0                                          | Generate a DMARC failure report if all                           |
|       |             |                                            | underlying authentication mechanisms                             |
|       |             |                                            | fail to produce an aligned “pass” result. (Default)              |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| rf    | False       | afrf                                       | The reporting format for individual Forensic reports.            |
|       |             |                                            | Authorized values: “afrf”, “iodef”.                              |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+
| ri    | False       | 86400                                      | The number of seconds elapsed between                            |
|       |             |                                            | sending aggregate reports to the sender.                         |
|       |             |                                            | The default value is 86,400 seconds or a day.                    |
+-------+-------------+--------------------------------------------+------------------------------------------------------------------+

==== SPF ====
Raw SPF Record: v=spf1 include:servers.mcsv.net include:_spf.google.com include:servers.outfunnel.com ~all

Details:
Version: v=spf1
~all means soft fail mail that doesn't match a rule - accept but tag

Included senders: 
+-------------------+-----------------------+-------------+
| Type              | Value                 | Detail      |
+===================+=======================+=============+
| Known mail server | servers.mcsv.net      | Mailchimp   |
+-------------------+-----------------------+-------------+
| Known mail server | _spf.google.com       | Google Mail |
+-------------------+-----------------------+-------------+
| Known mail server | servers.outfunnel.com | OutFunnel   |
+-------------------+-----------------------+-------------+

Excluded senders:
None


==== Hosts ====
Hostname: aspmx.l.google.com, preference: 10, TLS: True, starttls: True.
Addresses: 2a00:1450:400c:c07::1b, 64.233.184.27, 

Hostname: alt1.aspmx.l.google.com, preference: 20, TLS: True, starttls: True.
Addresses: 209.85.233.26, 2a00:1450:4010:c03::1b, 

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
```
