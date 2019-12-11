# mail_check
Script for checking the DNS record of a domain.

Uses python library checkdmarc, which works when provided with a name server. See https://github.com/domainaware/checkdmarc/blob/master/checkdmarc.py.

# Example
```Shell
$ python3 mail_check.py bbc.co.uk
Checking "bbc.co.uk"
Pure domain = "bbc.co.uk"
Location: bbc.co.uk
Raw Record: v=DMARC1;p=none;aspf=r;pct=100;fo=0;ri=86400;rua=mailto:bbcuk_rua@dmeu.easysol.net;ruf=mailto:bbcuk_ruf@dmeu.easysol.net;
DKIM explicit: False
SPF explicit: True
SPF Value: r

All data:
v: OrderedDict([('value', 'DMARC1'), ('explicit', True)])
p: OrderedDict([('value', 'none'), ('explicit', True)])
aspf: OrderedDict([('value', 'r'), ('explicit', True)])
pct: OrderedDict([('value', 100), ('explicit', True)])
fo: OrderedDict([('value', ['0']), ('explicit', True)])
ri: OrderedDict([('value', 86400), ('explicit', True)])
rua: OrderedDict([('value', [OrderedDict([('scheme', 'mailto'), ('address', 'bbcuk_rua@dmeu.easysol.net'), ('size_limit', None)])]), ('explicit', True)])
ruf: OrderedDict([('value', [OrderedDict([('scheme', 'mailto'), ('address', 'bbcuk_ruf@dmeu.easysol.net'), ('size_limit', None)])]), ('explicit', True)])
adkim: OrderedDict([('value', 'r'), ('explicit', False)])
rf: OrderedDict([('value', ['afrf']), ('explicit', False)])
sp: OrderedDict([('value', 'none'), ('explicit', False)])
```
