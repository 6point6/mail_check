import os, sys
import checkdmarc

def check(domain):
    print("Checking \"%s\"" % domain)

    pure_domain = checkdmarc.get_base_domain(domain)
    print("Pure domain = \"%s\"" % pure_domain)

    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_dmarc_record(pure_domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        #print(dmarc)

        # location
        print("Location: %s" % dmarc["location"])

        # record
        print("Raw Record: %s" % dmarc["record"])

        # parsed
        parsed = dmarc["parsed"]

        # get DKIM
        print("DKIM explicit: %s" % parsed["tags"]["adkim"]["explicit"])
        
        # Get SPF
        print("SPF explicit: %s" % parsed["tags"]["aspf"]["explicit"])
        if parsed["tags"]["aspf"]["explicit"] is True:
            print("SPF Value: %s" % parsed["tags"]["aspf"]["value"])
        
        # print all the dicts anyway
        print("\nAll data:")
        for key in parsed["tags"]:
           print("%s: %s" % (key, parsed["tags"][key])) 

    except Exception as e:
        print('Error with ' + domain)
        print(e)

if __name__ == '__main__':
    if len(sys.argv) is not 2:
        print("Usage: python3 mail_check.py domain")
        sys.exit(-1)
    
    domain = sys.argv[1]
    check(domain)