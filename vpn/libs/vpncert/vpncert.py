#!/usr/bin/env
import logging
import json
from os.path import basename, exists as file_exists
from glob import glob 
import subprocess
import time
import smtplib
from math import floor
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

VPN_CITIES = ["Helsinki", "Tampere", "Berlin", "Berliini"]
VPN_STATES = ["Uusimaa"]
VPN_COUNTRIES = ["FI", "DE"]
VPN_ORGANIZATIONS = ["Futurice Oy", "Futurice Gmbh", "Futurice", "Futurice Ltd"]
VPN_OU = ["OpenVPN Machines"]

class alert:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.vpncert = vpncert()

    def send_alert(self, certinfo):
        alert_msg = """Hi,
Your Futurice VPN certificate %s is going to expire in %s days.

If you still need VPN, please go to https://vpnmanagement.futurice.com/ and follow
instructions to renew it. If you don't need VPN, you can just ignore these mails.

You get this email 30 days and 14 days before certificate expires. Also, for last 5
days, you get this email every day.

Best regards,
IT Team
""" % (certinfo["filename"].replace(".crt", ""), certinfo["not_after_days"])
        if self.dry_run:
            print alert_msg
            return
        email = certinfo["filename"].split("-")
        email = "%s@futurice.com" % (email[0])
        msg = MIMEMultipart()
        msg['From'] = "admin@futurice.com"
        msg['To'] = email
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = "Futurice VPN cert is going to expire"
        msg.attach( MIMEText(alert_msg) )

        logging.debug("Sending email to %s with subject %s" % (msg["To"], msg["Subject"]))
        smtp = smtplib.SMTP("smtpgw.futurice.com")
        try:
            smtp.sendmail("admin@futurice.com", email, msg.as_string())
        except:
            print "Sending email to %s failed." % email
            return
        smtp.close()
        print "Sent warning email to %s" % email


    def run(self):
        for filename in glob("/home/vpn/futurice_certificates/futurice_openvpn_machine/keys/*-*.crt"):
             certinfo = self.vpncert.process_cert(filename)
             if certinfo is None:
                  continue
             if certinfo["not_after_days"] < 0:
                  continue
             if certinfo["not_after_days"] == 30:
                  self.send_alert(certinfo)
             if certinfo["not_after_days"] == 14:
                  self.send_alert(certinfo)
             if certinfo["not_after_days"] < 5:
                  self.send_alert(certinfo)


"""
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=FI, ST=Uusimaa, L=Helsinki, O=Futurice Oy, OU=OpenVPN Machines, CN=ojar-desktop/emailAddress=ojar@futurice.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
"""

class vpncert(object):
    def __init__(self, username = None):
        self.username = username

    def process_cert(self, filename):
            args = ["openssl", "x509", "-in",  filename, "-noout", "-text" ]
            pid = subprocess.Popen(args, stdout=subprocess.PIPE)
            (stdoutmsg, stderrmsg) = pid.communicate()
            if stdoutmsg is None:
                return None
            stdoutmsg = stdoutmsg.split("\n")
            atime = None
            ctime = None
            for line in stdoutmsg:
                if "Not After : " in line:
                    line = line.strip().replace("Not After : ", "")
                    atime = time.strptime(line, "%b %d %H:%M:%S %Y %Z")
                if "Not Before: " in line:
                    line = line.strip().replace("Not Before: ", "")
                    ctime = time.strptime(line, "%b %d %H:%M:%S %Y %Z")
            if atime is not None and ctime is not None:
                return {'not_after': atime, 
                              'not_after_printable': time.strftime('%Y-%m-%d', atime),
                              'not_after_days': int((time.mktime(atime) - time.time()) / 86400),
                              'not_before': ctime, 
                              'not_before_printable': time.strftime('%Y-%m-%d', ctime), 
                              'validity_length': int((time.mktime(atime) - time.mktime(ctime)) / 86400),
                              'filename': basename(filename)}

    def list_all_certs(self):
        certs = []
        for filename in glob("/home/vpn/futurice_certificates/futurice_openvpn_machine/keys/*-*.crt"):
             certinfo = self.process_cert(filename)
             if certinfo is not None:
                  certs.append(certinfo)
        return certs

    def listcerts(self):
        certs = []
        for filename in glob("/home/vpn/futurice_certificates/futurice_openvpn_machine/keys/"+self.username+"-*.crt"):
             certinfo = self.process_cert(filename)
             if certinfo is not None:
                  certs.append(certinfo)
        return certs

    def validatecert(self, filename):
        errors = []
        fields = {}
        if not file_exists(filename):
            errors.append("Internal error: no such file")
            return (False, errors, fields)

        args = ["openssl", "req", "-in", filename, "-noout", "-text" ]
        pid = subprocess.Popen(args, stdout=subprocess.PIPE)
        (stdoutmsg, stderrmsg) = pid.communicate()
        if stdoutmsg is None:
            errors.append("Internal error: can't communicate with openSSL process.")
            return (False, errors, fields)
        stdoutmsg = stdoutmsg.split("\n")
        for line in stdoutmsg:
            if "Subject: " in line:
                line = line.strip().replace("Subject: ", "")
                line = line.split(", ")
                for arg in line:
                    arg = arg.split("=")
                    if arg[0] == 'C': #country
                        fields['country'] = arg[1]
                        if arg[1] not in VPN_COUNTRIES:
                            errors.append("Please read country name rules. (was %s, expecting %s)" % (arg[1], VPN_COUNTRIES))
                    elif arg[0] == 'ST': # State
                        fields['state'] = arg[1]
                        if arg[1] not in VPN_STATES:
                            errors.append("Please read state name rules. (was %s, expecting %s)" % (arg[1], VPN_STATES))
                    elif arg[0] == 'L': # City
                        fields['city'] = arg[1]
                        if arg[1] not in VPN_CITIES:
                            errors.append("Please read city name rules. (was %s, expecting %s)" % (arg[1], VPN_CITIES))
                    elif arg[0] == 'O': # Organization
                        fields['organization'] = arg[1]
                        if arg[1] not in VPN_ORGANIZATIONS:
                            errors.append("Please read organization name rules. (was %s, expecting %s)" % (arg[1], VPN_ORGANIZATIONS))
                    elif arg[0] == 'OU': # Organization unit
                        fields['organizationunit'] = arg[1]
                        if arg[1] not in VPN_OU:
                            errors.append("Please read organization unit name rules. (was %s, expecting %s)" % (arg[1], VPN_OU))
                    elif arg[0] == 'CN': # CN
                        tmp = arg[1].split("/")
                        fields['common_name'] = tmp[0]
                        try:
                            fields['email'] = tmp[1]
                        except:
                            fields['email'] = "-"
                        commonname = tmp[0].split("-")
                        if len(commonname) < 2:
                            errors.append("Please read common name (CN) rules: correct format is username-{laptop/desktop/ext-laptop/ext-desktop/home-laptop/home-desktop}")
                            continue
                        if commonname[0] != self.username:
                            errors.append("Please read common name (CN) rules: first part must be your LDAP username (%s != %s)" % (commonname[0], self.username))

            if "Public Key Algorithm: " in line:
                line = line.strip().replace("Public Key Algorithm: ", "")
                fields['algorithm'] = line
                if line != 'rsaEncryption':
                    errors.append("Use RSA encryption for VPN keys.")
            if "RSA Public Key: " in line:
                line = line.strip().replace("RSA Public Key: ", "")
                line = line.replace("(", "").replace(" bit)", "")
                fields['bitlength'] = line
                try:
                    bits = int(line)
                    if bits < 2048:
                        errors.append("Minimum key length is 2048 bits.")
                except ValueError:
                    errors.append("Internal error: invalid key strength (%s)" % line)
        if not fields.get('bitlength'):
            errors.append("Can't determine bitlength from CSR.")
        if not fields.get('algorithm'):
            errors.append("Can't determine algorithm from CSR.")
        if not fields.get('common_name'):
            errors.append("Can't determine common name from CSR.")

        json.dump(errors, open("/tmp/a.txt", "w"))

        if len(errors) is not 0:
            return (False, errors, fields)
        return (True, errors, fields)



#        Subject: C=FI, ST=Uusimaa, L=Helsinki, O=Futurice Oy, OU=OpenVPN Machines, CN=ojar-laptop/emailAddress=olli.jarva@futurice.com
#        Subject Public Key Info:
#            Public Key Algorithm: rsaEncryption
#            RSA Public Key: (2048 bit)

