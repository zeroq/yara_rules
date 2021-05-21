
rule invoice_phish_1 : phishing
{
    meta:
        author = "Jan Goebel"
        description = "Detect Invoice Phishing eMail"
        created = "2021-05-21"
        modified = "2021-05-21"
    strings:
        $subject = "Invoice from" nocase
        $sender = "invoiceofficer@"
        $body1 = "You have received an Invoice" nocase
        $body2 = "View Document" nocase
        $body3 = "see the attached invoice" nocase
    condition:
        all of them
