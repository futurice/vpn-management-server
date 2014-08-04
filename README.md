VPN Management Server
=====================
Description
-----------
VPN Management is a self-service tool for users to handle their VPN certificates. The tool consists of two parts, the server and the installation wizard. VPN Management Server provides the interface and [VPN Configuration Wizard](https://github.com/futurice-oss/vpn-management-client) provides the native application for setting up your configurations. The server is integrated into LDAP for authentication and the keys are stored in a Mercurial repository. The application uses OpenVPN.

The user will create a .key file with the provided wizard or by manually at the web interface and send a certificate request to the server. The server will respond with a one time password. After validating the password, the server will sign the certificate request and send back the right configurations and a CRT.

After the creation of the certificates, users can use the VPN Management web tool to keep a track of their certificates or create new ones, for example for their computer at home. The certificates will last for a configurable amount of time and the server will remind you by email when your certificates are getting old.


Background
----------
This application was created as an internal support system at [Futurice](http://www.futurice.com).

> Futurice has been lucky enough to grow steadily every year. This has caused the positive problem that the legendary IT team at Futurice needs to be able to help more and more people. To fight this growing need, one aim is to automate and simplify as much as possible. Out of this also came the idea to allow employees to setup a VPN without the assistance of IT. The VPN Management wizard has helped a lot in reducing  help requests to the IT team. At the same time it has allowed employees to get access to the services they need immediately when the need has surfaced. Thus reducing the time wasted to wait for help. Everybody wins! What could be better?  -- Mats Malmsten, Former Head of IT Team @ Futurice

Installation
------------
**NOTE:**
You need a LDAP server and CA (Certificate Authority) for running this application.

#### Installing step by step:
Install requirements:  
`pip install -r requirements.txt`

Create local_settings:  
`cp local_settings.py.example local_settings.py`   

Modify local_settings to match your information.

Modify `inital_data.yaml` at `vpn/vpnconf/fixtures` to match your information.

Initialize the application:  
`python manage.py syncdb`

Run the application:  
`PYTHONPATH=../python:.. REMOTE_USER=<uid> python manage.py runserver`

About Futurice
--------------
[Futurice](http://www.futurice.com) is a lean service creation company with offices in Helsinki, Tampere, Berlin and London.

People who have contributed to VPN Management Server:
- [Olli Jarva](https://github.com/ojarva)
- [Henri Holopainen](https://github.com/henriholopainen)
- [Ville Tainio](https://github.com/Wisheri)

Support
-------
Pull requests and new issues are of course welcome. If you have any questions, comments or feedback you can contact us by email at sol@futurice.com. We will try to answer your questions, but we have limited manpower so please, be patient with us.
