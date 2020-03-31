import checkdmarc

VERSION_INDEX = 0
P_INDEX = 1

# explanations stolen from https://dmarcian.com/dmarc-inspector/
def process_DMARC(domain):
    print("==== DMARC ====")

    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_dmarc_record(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        #print(dmarc)

        check_DMARC_order(dmarc["record"])

        # print details
        print("\nDMARC Record:")

        # location
        print("Location: \t%s" % dmarc["location"])

        # record
        print("Raw Record: \t%s" % dmarc["record"])

        # parsed
        parsed = dmarc["parsed"]

        # version
        # The DMARC version should always be "DMARC1".
        # Note: A wrong, or absent DMARC version tag would cause the entire record to be ignored
        print("Version: \t%s" % parsed["tags"]["v"]["value"])

        # p
        # Policy applied to emails that fails the DMARC check. Authorized values: "none", "quarantine", or "reject". 
        # "none" is used to collect feedback and gain visibility into email streams without impacting existing flows. 
        # "quarantine" allows Mail Receivers to treat email that fails the DMARC check as suspicious. Most of the time, they will end up in your SPAM folder. 
        # "reject" outright rejects all emails that fail the DMARC check.
        print("Requested Mail Receiver Policy: %s (%s)" % (parsed["tags"]["p"]["explicit"], parsed["tags"]["p"]["value"]))

        # get DKIM
        print("Explicit alignment mode for DKIM: \t%s" % parsed["tags"]["adkim"]["explicit"])
        
        # Get ASPF
        # Specifies “Alignment Mode” for SPF.
        # Authorized values: “r”, “s”. “r”, or “Relaxed Mode” allows SPF Authenticated domains that share a common Organizational Domain with an email’s “header-From:” domain to pass the DMARC check. “s”, or “Strict Mode” requires exact matching between the SPF domain and an email’s “header-From:” domain.
        print("Explicit alignment mode for SPF: \t%s" % parsed["tags"]["aspf"]["explicit"])
        if parsed["tags"]["aspf"]["explicit"] is True:
            print("ASPF Value: \t%s" % parsed["tags"]["aspf"]["value"])

        # rua
        # The list of URIs for receivers to send XML feedback to.
        # Note: This is not a list of email addresses, as DMARC requires a list of URIs of the form “mailto:address@example.org”.
        if parsed["tags"]["rua"] is not None:
            print("Aggregate Report Mailbox (RUA): %s (" % parsed["tags"]["rua"]["explicit"], end="")

            for entry in parsed["tags"]["rua"]["value"]:
                print("Address: %s, scheme: %s" % (entry["address"], entry["scheme"]), end="")
            
            print(")")

        # ruf
        # The list of URIs for receivers to send Forensic reports to.
        # Note: This is not a list of email addresses, as DMARC requires a list of URIs of the form “mailto:address@example.org”.
        if parsed["tags"]["ruf"] is not None:
            print("Forensic Report Mailbox (RUF): %s (" % parsed["tags"]["ruf"]["explicit"], end="")

            for entry in parsed["tags"]["ruf"]["value"]:
                print("Address: %s, scheme: %s" % (entry["address"], entry["scheme"]), end="")
        
            print(")")

        # pct
        # The percentage tag tells receivers to only apply policy against email that fails the DMARC check x amount of the time. 
        # For example, "pct=25" tells receivers to apply the "p=" policy 25% of the time against email that fails the DMARC check. 
        # Note: The policy must be "quarantine" or "reject" for the percentage tag to be applied.
        print("Percent of mail to apply rules to: %s (%s)" %(parsed["tags"]["pct"]["explicit"], parsed["tags"]["pct"]["value"]))

        # sp
        # Policy to apply to email from a sub-domain of this DMARC record that fails the DMARC check.
        # Authorized values: "none", "quarantine", or "reject".
        # This tag allows domain owners to explicitly publish a "wildcard" sub-domain policy.
        print("Sub-Policy: %s (%s)" %(parsed["tags"]["sp"]["explicit"], parsed["tags"]["sp"]["value"]))

        # fo
        # 0: Generate a DMARC failure report if all underlying authentication mechanisms fail to produce an aligned “pass” result. (Default)
        # 1: Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned “pass” result.
        # d: Generate a DKIM failure report if the message had a signature that failed evaluation, regardless of its alignment.
        # s: Generate an SPF failure report if the message failed SPF evaluation, regardless of its alignment.
        print("Authentication and/or alignment vulnerabilities: %s (%s)" %(parsed["tags"]["fo"]["explicit"], parsed["tags"]["fo"]["value"][0]))

        # rf
        # The reporting format for individual Forensic reports. Authorized values: “afrf”, “iodef”.
        print("Report Format: %s (%s)" %(parsed["tags"]["rf"]["explicit"], parsed["tags"]["rf"]["value"][0]))
        
        # ri
        # The reporting interval for how often you’d like to receive aggregate XML reports.
        # You’ll most likely receive reports once a day regardless of this setting.
        print("Seconds between agregating reports: %s (%s)" %(parsed["tags"]["ri"]["explicit"], parsed["tags"]["ri"]["value"]))

        # print all the dicts anyway
        #print("\nAll data:")
        #for key in parsed["tags"]:
           #print("%s: %s" % (key, parsed["tags"][key]))
        
        print()

    except Exception as e:
        print('Error with ' + domain)
        print(e)


# check the order of the version and p fields
def check_DMARC_order(record):
    # v=DMARC1; rua=mailto:55d7175f07@rep.dmarcanalyzer.com; p=none; pct=100; sp=none; adkim=r; aspf=r;
    # trim spaces
    record = record.replace(" ", "")
    
    # split the entries
    entries = record.split(";")
    
    #print("DMARC record has %d entries" % len(entries))

    # version should be first
    if not entries[VERSION_INDEX][0:2] == "v=":
        print("Problem found: first entry should be version\n")
    else:
        # should be v1    
        if not entries[VERSION_INDEX] == "v=DMARC1":
            print("Problem found: unknown version \"%s\"\n" % entries[VERSION_INDEX][2:])

    # p should be second
    if not entries[P_INDEX][0:2] == "p=":
        print("Problem found: second entry should be 'p', currently set to \"%s\"\n" % entries[P_INDEX])

        # find p
        for entry in entries:
            if entry[0:2] == "p=":
                check_p_value(entry[2:])
    else:
        check_p_value(entries[P_INDEX][2:])


# check the policy value
def check_p_value(p_value):
    if p_value == "none":
        # stolen from https://dmarcian.com/dmarc-inspector/
        print("Problem found: DMARC record \"p\" tag is set to \"none\", which does not prevent abuse on your domain. If you are satisfied with the authentication success of your sending sources, move your policy to a 'p=quarantine' or 'p=reject'.")
    elif p_value != "quarantine" and p_value != "reject":
        print("Problem found: 'p' should be set to 'none', 'quarantine' or 'reject'")





