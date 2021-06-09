
rule dhl_phish_1 : phishing
{
    meta:
        author = "Jan Goebel"
        description = "Detect DHL Invoice Phishing eMail"
        created = "2021-05-21"
        modified = "2021-05-21"
    strings:
        $subject = "update your information..." nocase
        $sender = "@skynet.bet" nocase
        $body1 = "Your package is waiting for delivery" nocase
        $body2 = "confirm your payment" nocase
    condition:
        all of them
}
