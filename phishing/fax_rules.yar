
rule fax_phish_1 : phishing
{
    meta:
        author = "Jan Goebel"
        description = "Detect DHL Fax Phishing eMail"
        created = "2021-06-09"
        modified = "2021-06-09"
    strings:
        $subject = "FAX" nocase
        $sender = "@xindacrop.com" nocase
        $body1 = "INCOMING FAX"
        $body2 = "Remote Drive:"
    condition:
        all of them
}
