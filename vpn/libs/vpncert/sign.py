from password import Password
from vpncert import vpncert

import time
import smtplib
import os
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
from os.path import basename
from glob import glob
import zipfile
from tempfile import mkdtemp
import subprocess
import logging
import os.path
from shutil import move, copy, rmtree
KEYPATH="/home/vpn/futurice_certificates/futurice_openvpn_machine/keys"

class repository(object):
    def prepare_repository(self):
        logging.debug("Running hg pull")
        args = ["hg", "pull"]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()
        logging.debug("Running hg update")
        args = ["hg", "update"]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()

    def finish_repository(self, message):
        logging.debug("Running hg add")
        args = ["hg", "add"]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()
        logging.debug("Running hg commit -m %s" % message)
        args = ["hg", "commit", "-m", message]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()
        logging.debug("Running hg push")
        args = ["hg", "push"]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()
        


class sign(object):
    def __init__(self, csrfile, username):
        self.password = Password.PASSWORD
        self.certmanager = vpncert(username)
        self.csrfile = csrfile
        self.valid = True
        if not os.path.exists(csrfile):
            self.valid = False
            return
        status, errors, fields = self.certmanager.validatecert(csrfile)
        if not status:
            self.valid = False
            return
        self.fields = fields
        self.repository = repository()


    def get_cn(self):
        if not self.valid:
            return
        return self.fields["common_name"]

    def sign(self):
        if not self.valid:
            logging.error("Trying to run sign with invalid setup")
            return self.valid
        self.repository.prepare_repository()
        cn = self.fields['common_name']
        move(self.csrfile, "%s/%s.csr" % (KEYPATH, cn))
        args = ["openssl", "ca", "-batch", "-days", "365", "-out", "%s/%s.crt" % (KEYPATH, cn), "-in", "%s/%s.csr" % (KEYPATH, cn), "-md", "sha1", "-config", "/home/vpn/futurice_certificates/futurice_openvpn_machine/openssl.cnf", "-passin", "pass:%s" % self.password]
        env_list = {"KEY_DIR": KEYPATH,
            "KEY_SIZE": "2048",
            "PATH": "/bin:/usr/bin:/usr/sbin:/sbin",
            "KEY_COUNTRY": "FI",
            "KEY_PROVINCE": "Uusimaa",
            "KEY_CITY": "Helsinki",
            "KEY_ORG": "Futurice Oy",
            "PKCS11_MODULE_PATH": "/usr/lib",
            "PKCS11_PIN": "1298479823754987",
            "KEY_CN": "futurice-invalid",
            "KEY_EMAIL": "ssl@futurice.com",
            "KEY_OU": "OpenVPN Machines"}
        
        pid = subprocess.Popen(args, env=env_list)#, stdout=subprocess.PIPE)
        (stdoutmsg, stderrmsg) = pid.communicate()
        self.repository.finish_repository("Added certificate for %s" % cn)
        return (True, stdoutmsg)


    def revoke(self):
        if not self.valid:
            return self.valid
        self.repository.prepare_repository()
        cn = self.fields['common_name']
        if not os.path.exists("%s/%s.crt" % (KEYPATH, cn)):
            # No old crt available -> no reason to revoke
            return False
        args = ["openssl", "ca", "-revoke", "%s/%s.crt" % (KEYPATH, cn), "-config", "/home/vpn/futurice_certificates/futurice_openvpn_machine/openssl.cnf", "-passin", "pass:%s" % self.password]
        env_list = {"KEY_DIR": KEYPATH,
            "KEY_SIZE": "2048",
            "PATH": "/bin:/usr/bin:/usr/sbin:/sbin",
            "KEY_COUNTRY": "FI",
            "KEY_PROVINCE": "Uusimaa",
            "KEY_CITY": "Helsinki",
            "KEY_ORG": "Futurice Oy",
            "PKCS11_MODULE_PATH": "/usr/lib",
            "PKCS11_PIN": "1298479823754987",
            "KEY_CN": "futurice-invalid",
            "KEY_EMAIL": "ssl@futurice.com",
            "CRL": "%s/crl.pem" % KEYPATH,
            "KEY_OU": "OpenVPN Machines"}
        pid = subprocess.Popen(args, env=env_list)#, stdout=subprocess.PIPE)
        (stdoutmsg, stderrmsg) = pid.communicate()
        args = ["openssl", "ca", "-gencrl", "-out", "%s/crl.pem" % KEYPATH, "-config", "/home/vpn/futurice_certificates/futurice_openvpn_machine/openssl.cnf", "-passin", "pass:%s" % self.password]
        pid = subprocess.Popen(args, env=env_list)#, stdout=subprocess.PIPE)
        (stdoutmsg, stderrmsg) = pid.communicate()
        self.repository.finish_repository("Revoked certificate %s" % cn)


    def pack(self):
        if not self.valid:
            return self.valid
        cn = self.fields['common_name']
        MACCONF="""client
dev tap
proto udp
remote %s
resolv-retry infinite
nobind
persist-key
persist-tun

ca chain_futurice_openvpn_server_ca.pem
cert %s.crt
key %s.key

ns-cert-type server
cipher  AES-256-CBC
comp-lzo"""
        LINUXCONF="""client
dev tap
proto udp
remote %s
resolv-retry infinite
nobind
persist-key
persist-tun

ca /path/to/chain_futurice_openvpn_server_ca.pem
cert /path/to/%s.crt
key /path/to/%s.key

ns-cert-type server
cipher  AES-256-CBC
comp-lzo"""

        WINDOWSCONF="""client
dev tap
proto udp
remote %s
resolv-retry infinite
nobind
persist-key
persist-tun

ca chain_futurice_openvpn_server_ca.pem
cert %s.crt
key %s.key

ns-cert-type server
cipher  AES-256-CBC
comp-lzo""" 


        tempdir = mkdtemp()
        for endpoint, name in [ ( "hel-openvpn.futurice.com", "helsinki"), ( "ber-openvpn.futurice.com", "berlin" ), ( "tre-openvpn.futurice.com", "tampere" ) ]:
            f = open(tempdir+"/futurice-windows-%s.ovpn" % name, "w")
            f.write(WINDOWSCONF % (endpoint, cn, cn))
            f.close()
            f = open(tempdir+"/futurice-mac-%s.conf" % name, "w")
            f.write(MACCONF % (endpoint, cn, cn))
            f.close()
            f = open(tempdir+"/futurice-linux-%s.conf" % name, "w")
            f.write(LINUXCONF % (endpoint, cn, cn))
            f.close()
        
        copy("%s/%s.crt" % (KEYPATH, cn), tempdir+"/%s.crt" % cn)
        copy("%s/chain_futurice_openvpn_server_ca.pem" % KEYPATH, "%s/chain_futurice_openvpn_server_ca.pem" % tempdir)
        
        zip = zipfile.ZipFile("/home/vpn/vpn/vpn/static/zip/%s.zip" % cn, "w")
        for filename in glob("%s/*" % tempdir):
            zip.write(filename, basename(filename))
        zip.close()

        rmtree(tempdir)

    def send(self, email):
        if not self.valid:
            return self.valid

        cn = self.fields['common_name']

        text = """Hi,
Please see attached zip file. There is your certificate and sample configuration files for Mac, Linux and Windows.

If you have problems with configuring OpenVPN, please look at our OpenVPN instructions:
https://confluence.futurice.com/display/IT/OpenVPN
If you can't find answer to your problem, please come to see IT team, or send email (you can reply to this email).

Please remember that VPN certificates and keys are absolutely private. You may never share your VPN keys with anyone else.

--
IT team
"""

        msg = MIMEMultipart()
        msg['From'] = "admin@futurice.com"
        msg['To'] = email
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = "Your VPN certificate for %s" % cn
        msg.attach( MIMEText(text) )

        zip_filename = "/home/vpn/vpn/vpn/static/zip/%s.zip" % cn
        logging.debug("Adding mime attachment from %s" % zip_filename)
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(zip_filename, "rb").read() )
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s.zip"' % cn)
        msg.attach(part)

        logging.debug("Sending email to %s with subject %s" % (msg["To"], msg["Subject"]))
        smtp = smtplib.SMTP("smtpgw.futurice.com")
        smtp.sendmail("it@futurice.com", email, msg.as_string())
        smtp.close()

    def deploy(self):
        """ Deploys to VPN server (loads new certificates, adds firewall rules and DNS name) """
        if not self.valid:
            logging.error("Trying to run deploy with invalid certificate")
            return self.valid

        cn = self.fields['common_name']
        args = ["ssh", "vpnintegration@holmium.futurice.com", "-t", "sudo /root/vpnintegration.sh %s" % cn]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()
        time.sleep(5)

        logging.debug("Running vpn integration script in 10.4.0.3")
        args = ["ssh", "vpnintegration@10.4.0.3", "-t", "sudo /root/vpnintegration.sh %s" % cn]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()
        time.sleep(5)
        args = ["ssh", "vpnintegration@10.4.0.4", "-t", "sudo /root/vpnintegration.sh %s" % cn]
        pid = subprocess.Popen(args, cwd=KEYPATH)
        pid.wait()
