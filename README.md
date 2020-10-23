# HIBPNotifer


This is fork of the core component of https://github.com/thewhiteh4t/pwnedOrNot .

It focuses on sending email and slack notifications of the breaches encountered.
P.S - Notifications only include breach info for now (exclude dumps).

Will also be integrating with Google Admin SDK to read users from GSuite.

[**haveibeenpwned**](https://haveibeenpwned.com/API/v3) offers a lot of information about the compromised email, some useful information is displayed by this script:
* Name of Breach
* Domain Name
* Date of Breach
* Fabrication status
* Verification Status
* Retirement status
* Spam Status

And with all this information **pwnedOrNot** can easily find passwords for compromised emails if the dump is accessible and it contains the password

## Installation

```bash
git clone https://github.com/masterlittle/HIBPNotifier.git
cd pwnedOrNot
pip3 install requests
```

## Usage
```bash
python3 checkemails.py -h

usage: checkemails.py [-h] [-e EMAIL] [-f FILE] [-d DOMAIN] [-n] [-l]
                     [-c CHECK] [-s] [-D DAYS]

optional arguments:
  -h, --help                  show this help message and exit
  -e EMAIL, --email EMAIL     Email Address You Want to Test
  -f FILE, --file FILE        Load a File with Multiple Email Addresses
  -d DOMAIN, --domain DOMAIN  Filter Results by Domain Name
  -n, --nodumps               Only Check Breach Info and Skip Password Dumps
  -l, --list                  Get List of all pwned Domains
  -c CHECK, --check CHECK     Check if your Domain is pwned
  -s, --send-email            Email the results to the email id being checked. Check at the bottom for the environment variables to be set
  -D, --days                  Number of days past to check the breaches for
  -S, --slack-channel         If this option is present, you can send breach notifications to slack. Check at the bottom for the environment variables to be set

# Examples

# Check Single Email
python3 pwnedornot.py -e <email>
#OR
python3 pwnedornot.py --email <email>

# Check Multiple Emails from File
python3 pwnedornot.py -f <file name>
#OR
python3 pwnedornot.py --file <file name>

# Filter Result for a Domain Name [Ex : adobe.com]
python3 pwnedornot.py -e <email> -d <domain name>
#OR
python3 pwnedornot.py -f <file name> --domain <domain name>

# Get only Breach Info, Skip Password Dumps
python3 pwnedornot.py -e <email> -n
#OR
python3 pwnedornot.py -f <file name> --nodumps

# Get List of all Breached Domains
python3 pwnedornot.py -l
#OR
python3 pwnedornot.py --list

# Send email of breaches and check breaches only for past 30 days
python3 checkemails.py -e <email> -s -D 30

# Send slack notifications
python3 checkemails.py -f <file> -S <slack channel>

# Check if a Domain is Pwned
python3 pwnedornot.py -c <domain name>
#OR
python3 pwnedornot.py --check <domain name>
```

#### ENV variables to set for sending emails. All variables are set in config.py -

- LEAK_ALERTER_EMAIL_HOST

- LEAK_ALERTER_EMAIL_PORT -> Default = 587

- LEAK_ALERTER_EMAIL_USERNAME -> Default = None

- LEAK_ALERTER_EMAIL_PASSWORD -> Default = None

- LEAK_ALERTER_EMAIL_SEND_TO -> Default = The email being checked

- LEAK_ALERTER_EMAIL_SEND_FROM

- LEAK_ALERTER_EMAIL_SUBJECT -> Default = Email found in security breach

#### ENV variable to set for Slack

- SLACK_API_TOKEN

