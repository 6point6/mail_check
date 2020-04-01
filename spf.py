
# known sending servers
servers = {"servers.mcsv.net": "Mailchimp", "_spf.salesforce.com": "SalesForce", "_spf.google.com": "Google Mail", "amazonses.com": "Amazon Simple Email Service", "spf.messagelabs.com": "Symantec Message Labs", "_spf.sidetrade.net": "SideTrade", "eu._netblocks.mimecast.com": "EU Mimecast", "de._netblocks.mimecast.com": "DE Mimecast", "us._netblocks.mimecast.com": "US Mimecast", "za._netblocks.mimecast.com": "ZA Mimecast", "au._netblocks.mimecast.com": "AU Mimecast", "_netblocks.mimecast.com": "Global Mimecast", "_spf.createsend.com": "CreateSend Newsletter Software", "spf-a.hotmail.com": "Office 365", "spf-b.hotmail.com": "Office 365", "spf-a.outlook.com": "Office 365", "spf-b.outlook.com": "Office 365", "spfa.bigfish.com": "Office 365", "spfb.bigfish.com": "Office 365", "spfc.bigfish.com": "Office 365", "spf-a.hotmail.com": "Office 365", "_spf-ssg-b.microsoft.com": "Office 365", "_spf-ssg-c.microsoft.com": "Office 365", "spf.protection.outlook.com": "Office 365", "sendgrid.net": "SendGrid"}


# process an SPF record. See https://dmarcian.com/spf-syntax-table/
def parse_SPF(record, domain):
    fields = record.split(" ")

    # process includes
    print("Details:")

    # SPF fields
    for field in fields:
        if field[:2] == "v=":
            print("Version: %s" % field)
        elif field == "mx":
            print("Match domain from MX Record")
        elif field[1:] == "all":
            if field[:1] == "+":
                print("+all accept regardless of whether a rule is matched. Not recommended")
            elif field[:1] == "-":
                print("-all reject mail that doesn't match a rule")
            elif field[:1] == "~":
                print("~all means soft fail mail that doesn't match a rule - accept but tag")
            elif field[:1] == "?":
                print("~all means no rule for all")

    # print all includes
    print("\nIncluded senders: ")

    for field in fields:
        if field[0:1] != "-" and field[0:1] != "~" and field[0:1] != "?":
            # server fields
            if field[:8] == "include:":
                if domain in field:
                    print("Proprietary mail server: %s" % field[8:])
                else:
                    processInclude(field[8:])
            elif field[:9] == "+include:":
                if domain in field:
                    print("Proprietary mail server: %s" % field[9:])
                else:
                    processInclude(field[9:])
            elif field[:4] == "ip4:":
                if "/" in field:
                    print("IPv4 Address Range %s" % field[4:])
                else:
                    print("IPv4 Address %s" % field[4:])
            elif field[:4] == "ip6:":
                if "/" in field:
                    print("IPv6 Address Range %s" % field[4:])
                else:
                    print("IPv6 Address %s" % field[4:])

    # print all excludes
    print("\nExcluded:")

    for field in fields:
        if field[0:1] == "-":
            print("Reject: %s" % field[1:])
        elif field[0:1] == "~":
            print("Soft fail: %s" % field[1:])
        elif field[0:1] == "?":
            if field != "~all":
                print("No rule: %s" % field[1:])
    
    print("\n")


# Lookup mail server
def processInclude(field):
    if field in servers:
        print("Known mail server \"%s\": %s" % (field, servers[field]))
    else:
        print("Unknown mail server: %s" % field)
