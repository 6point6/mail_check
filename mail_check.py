#
# For more info see https://dmarc.org/overview/, https://tools.ietf.org/html/rfc4408, https://tools.ietf.org/html/rfc6376

import os, sys
import checkdmarc

def check_DMARC(domain):
    print("==== DMARC ====")

    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_dmarc_record(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        #print(dmarc)

        # location
        print("Location: \t%s" % dmarc["location"])

        # record
        print("Raw Record: \t%s" % dmarc["record"])

        # parsed
        parsed = dmarc["parsed"]

        # version
        print("Version: \t%s" % parsed["tags"]["v"]["value"])

        # p
        print("Requested Mail Receiver Policy: %s (%s)" % (parsed["tags"]["p"]["explicit"], parsed["tags"]["p"]["value"]))

        # get DKIM
        print("Explicit alignment mode for DKIM: \t%s" % parsed["tags"]["adkim"]["explicit"])
        
        # Get SPF
        print("Explicit alignment mode for SPF: \t%s" % parsed["tags"]["aspf"]["explicit"])
        if parsed["tags"]["aspf"]["explicit"] is True:
            print("SPF Value: \t%s" % parsed["tags"]["aspf"]["value"])

        # rua
        if parsed["tags"]["ruf"] is not None:
            print("Aggregate Report Mailbox (RUA): %s (" % parsed["tags"]["rua"]["explicit"], end="")

            for entry in parsed["tags"]["rua"]["value"]:
                print("Address: %s, scheme: %s" % (entry["address"], entry["scheme"]), end="")
            
            print(")")

        if parsed["tags"]["ruf"] is not None:
            print("Forensic Report Mailbox (RUF): %s (" % parsed["tags"]["ruf"]["explicit"], end="")

            for entry in parsed["tags"]["ruf"]["value"]:
                print("Address: %s, scheme: %s" % (entry["address"], entry["scheme"]), end="")
        
            print(")")

        # pct
        print("Percent of mail to apply rules to: %s (%s)" %(parsed["tags"]["pct"]["explicit"], parsed["tags"]["pct"]["value"]))

        # sp
        print("Sub-Policy: %s (%s)" %(parsed["tags"]["sp"]["explicit"], parsed["tags"]["sp"]["value"]))

        # fo
        # 0: Generate a DMARC failure report if all underlying authentication mechanisms fail to produce an aligned “pass” result. (Default)
        # 1: Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned “pass” result.
        # d: Generate a DKIM failure report if the message had a signature that failed evaluation, regardless of its alignment.
        # s: Generate an SPF failure report if the message failed SPF evaluation, regardless of its alignment.
        print("Authentication and/or alignment vulnerabilities: %s (%s)" %(parsed["tags"]["fo"]["explicit"], parsed["tags"]["fo"]["value"]))

        # rf
        print("Report Format: %s (%s)" %(parsed["tags"]["rf"]["explicit"], parsed["tags"]["rf"]["value"]))
        
        # ri
        print("Seconds between agregating reports: %s (%s)" %(parsed["tags"]["ri"]["explicit"], parsed["tags"]["ri"]["value"]))

        # print all the dicts anyway
        #print("\nAll data:")
        #for key in parsed["tags"]:
           #print("%s: %s" % (key, parsed["tags"][key]))
        
        print()

    except Exception as e:
        print('Error with ' + domain)
        print(e)


# TODO fix this
def check_domain(domain):
    print("==== Domains ====")
    dmarc = {}
    
    try:
        dmarc = checkdmarc.check_domains(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        print(dmarc)
    except Exception as e:
            print('Error with ' + domain)
            print(e)
    
    print("\n")


def get_hosts(domain):
    print("==== Hosts ====")
    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_mx_hosts(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        for host_record in dmarc["hosts"]:
            print("Hostname: %s, preference: %s, TLS: %s, starttls: %s." % (host_record["hostname"], host_record["preference"], host_record["tls"], host_record["starttls"]))
            print("Addresses: ", end="")

            for address in host_record["addresses"]:
                print("%s, " % address, end="")
            
            print("\n")

        for warning in dmarc["warnings"]:
            print("Warning: %s" % warning)
    except Exception as e:
            print('Error with ' + domain)
            print(e)

    print()


def check_SPF(pure_domain):
    print("==== SPF ====")
    dmarc = {}
    
    try:
        dmarc = checkdmarc.query_spf_record(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        print("SPF Record: %s\n" % dmarc["record"])

        print("Warning: %s" % dmarc["warnings"])

        # TODO parse this
    except Exception as e:
            print('Error with ' + domain)
            print(e)
    
    print("\n")


if __name__ == '__main__':
    if len(sys.argv) is not 2:
        print("Usage: python3 mail_check.py domain")
        sys.exit(-1)
    
    # check domain
    domain = sys.argv[1]
    pure_domain = checkdmarc.get_base_domain(domain)
    print("Pure domain = \"%s\"\n" % pure_domain)

    # run tests
    get_hosts(pure_domain)
    check_DMARC(pure_domain)
    check_domain(pure_domain)
    check_SPF(pure_domain)
    