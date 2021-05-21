
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
}

rule invoice_phish_2: phishing
{
    meta:
        author = "Jan Goebel" 
        description = "Detect Invoice Phishing eMail (delivers BazarBackdoor)"
        created = "2021-05-21"
        modified = "2021-05-21"
    strings:
        $subject1 = "You have formed an order No" nocase
        $body1 = "Dear customer," nocase
        $body2 = "Your order" nocase
        $body3 = "shipment price is included in your invoice" nocase
        $body4 = "as soon as your order will be ready for delivery" nocase
    condition:
        all of them
}

rule invoice_phish_3: phishing
{
    meta:
        author = "Jan Goebel" 
        description = "Detect Invoice Phishing eMail"
        created = "2021-05-21"
        modified = "2021-05-21"
    strings:
        $subject1 = "Your free trial period" nocase
        $body1 = "Dear customer," nocase
        $body2 = "Your free trial period is coming to the end" nocase
        $body3 = "you have confirmed your payment method" nocase
        $body4 = "thank you for your business" nocase
    condition:
        all of them
}

rule office_phish_1: phishing
{
    meta:
        author = "Jan Goebel"
        description = "Detect Invoice Phishing eMail"
        created = "2021-05-21"
        modified = "2021-05-21"
    strings:
        $subject1 = "OfficeDoc" nocase
        $subject2 = "Important Business" nocase
        $filename = "Productivity Enhancing Guidance.htm" nocase
    condition:
        all of them
}

rule tax_phish_1: phishing
{
    meta:
        author = "Jan Goebel"
        description = "Detect Invoice Phishing eMail"
        created = "2021-05-21"
        modified = "2021-05-21"
    strings:
        $subject = "Recalculation of Your Tax Refund Payment" nocase
        $sender = "irs.service@" nocase
        $body1 = "Dear Applicant" nocase
        $body2 = "claim your refund now" nocase
        $body3 = "please submit the form" nocase
    condition:
        all of them
}
