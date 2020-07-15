
# https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/how-office-365-uses-spf-to-prevent-spoofing?view=o365-worldwide
# https://dmarcian.com/spf-syntax-table/

import checkdmarc
from tabulate import tabulate

# known sending servers
# TODO add from https://github.com/covert-labs/mx-intel?
servers = {"servers.mcsv.net": "Mailchimp", 
            "_spf.salesforce.com": "SalesForce",
            "_spf.google.com": "Google Mail",
            "amazonses.com": "Amazon Simple Email Service",
            "spf.messagelabs.com": "Symantec Message Labs",
            "_spf.sidetrade.net": "SideTrade",
            "eu._netblocks.mimecast.com": "EU Mimecast",
            "de._netblocks.mimecast.com": "DE Mimecast",
            "us._netblocks.mimecast.com": "US Mimecast",
            "za._netblocks.mimecast.com": "ZA Mimecast",
            "au._netblocks.mimecast.com": "AU Mimecast",
            "_netblocks.mimecast.com": "Global Mimecast",
            "_spf.createsend.com": "CreateSend Newsletter Software",
            "spf-a.hotmail.com": "Office 365",
            "spf-b.hotmail.com": "Office 365",
            "spf-c.hotmail.com": "Office 365",
            "spf-a.outlook.com": "Office 365",
            "spf-b.outlook.com": "Office 365",
            "spf-c.outlook.com": "Office 365",
            "spfa.bigfish.com": "Office 365",
            "spfb.bigfish.com": "Office 365",
            "spfc.bigfish.com": "Office 365",
            "_spf-ssg-b.microsoft.com": "Office 365",
            "_spf-ssg-c.microsoft.com": "Office 365",
            "spf.protection.outlook.com": "Office 365",
            "sendgrid.net": "SendGrid",
            "mailcontrol.com": "Forcepoint Security Cloud",
            "spf.mandrillapp.com": "MailChimp Transactional Email",
            "spf.sitel.com": "Sitel Customer Experience Platform",
            "kallidus-suite.com": "Kallidus Suite",
            "emailcc.com": "Concep B2B",
            "mh.blackboard.com": "BlackBoard email relay",
            "mktomail.com": "MarketTo Emailer",
            "spf.exclaimer.net": "Exclaimer Signatures",
            "mail.zohoanalytics.com": "Zoho Cloud Platform",
            "spf.smtp2go.com": "SMTP2GO Email sender",
            "_netblocks.eloqua.com": "Oracle Eloqua",
            "_spf.fireeyecloud.com": "FireEye",
            "servers.outfunnel.com": "OutFunnel"}

server_suffices = {"pphosted.com": "ProofPoint"}


# Get the SPF record 
def process_SPF(pure_domain):
    print("==== SPF ====")
    dmarc = {}
    
    try:
        dmarc = checkdmarc.query_spf_record(pure_domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        print("Raw SPF Record: %s\n" % dmarc["record"])

        parse_SPF(dmarc["record"], pure_domain)

        for warning in dmarc["warnings"]:
            print("Warning: \"%s\"" % warning)

        # TODO parse this
    except Exception as e:
            print('Error with processing record for %s: \"%s\"' % (pure_domain, e))
            

# process an SPF record. See https://dmarcian.com/spf-syntax-table/
def parse_SPF(record, domain):
    fields = record.split(" ")

    # process includes
    print("Details:")

    # look for redirect first, run against that
    for field in fields:
        if field[:9] == "redirect=":
            print("Following redirect to %s\n" % field[9:])
            process_SPF(field[9:])
            return

    # SPF fields
    for field in fields:
        # look for version
        if field[:2] == "v=":
            print("Version: %s" % field)
        # look for MX
        elif field == "mx":
            print("Match domain from MX Record")
        # process the "all" record
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
    rows = []

    for field in fields:
        # exclude all but include
        if field[0:1] != "-" and field[0:1] != "~" and field[0:1] != "?":
            # domain, implicit +
            if field[:8] == "include:":
                if domain in field:
                    rows.append(["Proprietary mail server", "{}".format(field[8:]), ""])
                else:
                    rows.append(processInclude(field[8:]))
                    
            # domain, explicit +
            elif field[:9] == "+include:":
                if domain in field:
                    rows.append(["Proprietary mail server", "{}".format(field[9:]), ""])
                else:
                    rows.append(processInclude(field[9:]))
            # IPv4
            elif field[:4] == "ip4:":
                # check for range
                if "/" in field:
                    rows.append(["IPv4 Address Range", "{}".format(field[4:]), ""])
                else:
                    rows.append(["IPv4 Address Range", "{}".format(field[4:]), ""])
            # IPv6
            elif field[:4] == "ip6:":
                # check for range
                if "/" in field:
                    rows.append(["IPv6 Address Range", "{}".format(field[4:]), ""])
                else:
                    rows.append(["IPv6 Address Range", "{}".format(field[4:]), ""])
    
    if len(rows) == 0:
        print("None")
    else:
        print(tabulate(rows, headers=["Type", "Value", "Detail"], colalign=("left",), tablefmt="grid"))

    # print all excludes
    print("\nExcluded senders:")
    rows = []

    for field in fields:
        if field[0:1] == "-":
            if field != "-all":
                rows.append(["Reject", "{}".format(field[1:])])
        elif field[0:1] == "~":
            if field != "~all":
                rows.append(["Soft fail", "{}".format(field[1:])])
        elif field[0:1] == "?":
            if field != "?all":
                rows.append(["No rule", "{}".format(field[1:])])
    
    if len(rows) == 0:
        print("None")
    else:
        print(tabulate(rows, headers=["Type", "Value"], colalign=("left",), tablefmt="grid"))
    
    print("\n")


# Lookup mail server
def processInclude(field):
    if field in servers:
        return ["Known mail server", "{}".format(field), "{}".format(servers[field])]
    else:
        for suffix in server_suffices:
            if suffix in field:
                return ["Known mail server", "{}".format(field), "{}".format(server_suffices[suffix])]
    
    return ["Unknown mail server", "{}".format(field), ""]
        
