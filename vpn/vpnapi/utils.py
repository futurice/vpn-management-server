from ldap_auth.toolbox import get_user
import vpncert
from sign import sign
import subprocess
from django.conf import settings


def api_send_sms_all(user, message):
    def send_sms(number, message):
        try:
            number = number.replace("+", "00")
            args = ["wget", "--no-check-certificate", "-O-", "-o-",
                    settings.SMS_URL % (number, message)]
            pid = subprocess.Popen(args, stdout=subprocess.PIPE)
            (stdoutmsg, stderrmsg) = pid.communicate()
            return True
        except KeyError:
            return "keyerror"

    telephone = user.get("telephoneNumber")
    if telephone is None:
        return "Invalid phone number"
    valid_sms = send_sms(telephone[0], message)
    if valid_sms == True:
        return valid_sms
    return send_sms(user['mobile'][0], message)


def api_validate_csr(username, filename):
    certmanager = vpncert.vpncert(username)
    return certmanager.validatecert(filename)

def api_gen_and_send_password(username):
    # generate password
    args = ["pwgen", "9", "1"]
    pid = subprocess.Popen(args, stdout=subprocess.PIPE)
    (stdoutmsg, stderrmsg) = pid.communicate()
    if stdoutmsg is None:
        return {"success": False,
                "message": "Internal error: can't generate password"}
    stdoutmsg = stdoutmsg.split("\n")
    password = stdoutmsg[0]

    # send sms
    user = get_user(username)
    valid_sms = api_send_sms_all(user, password)
    if not valid_sms == True:
        return {"success": False, "valid_sms": False,
                "message": "Can't send SMS: %s" % valid_sms}
    return {"success": True, "password": password}


def api_sign_and_deploy(username, csrfilename, email = None):
    signing = sign(csrfilename, username)
    signing.revoke() # revoke old certificate
    signing.sign() # sign certificate
    signing.pack() # create certificate zip and configuration samples
    if email:
        signing.send(email) # send zip via email
    return signing
