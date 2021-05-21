
rule windows_phish_1 : phishing
{
    meta:
        author = "Jan Goebel"
        description = "Detect Windows Update Phishing eMail"
        created = "2021-05-21"
        modified = "2021-05-21"
    strings:
        $subject = "Microsoft Windows Upgrade." nocase
        $body1 = "Your Office Windows Computer" nocase
        $body2 = "is outdated and an upgrade" nocase
        $body3 = "please open your browser" nocase
    condition:
        all of them
