"""
Evennia settings file.

The available options are found in the default settings file found
here:

/home/griatch/Devel/MUD/evennia/evennia-trunk/evennia/settings_default.py

Remember:

Don't copy more from the default file than you actually intend to
change; this will make sure that you don't overload upstream updates
unnecessarily.

When changing a setting requiring a file system path (like
path/to/actual/file.py), use GAME_DIR and EVENNIA_DIR to reference
your game folder and the Evennia library folders respectively. Python
paths (path.to.module) should be given relative to the game's root
folder (typeclasses.foo) whereas paths within the Evennia library
needs to be given explicitly (evennia.foo).

"""

# Use the defaults from Evennia unless explicitly overridden
from evennia.settings_default import *

######################################################################
# Evennia base server config
######################################################################

# This is the name of your game. Make it catchy!
SERVERNAME = "Evdemo"

# open to the internet: 4280, 4281, 4282
# closed to the internet (internal use): 4283, 4284
TELNET_PORTS = [4280]
WEBSERVER_PORTS = [(4281, 4283)]
WEBSOCKET_CLIENT_PORT = 4282
AMP_PORT = 4284
ALLOWED_HOSTS = [".silvren.com"]
# TELNET_INTERFACES = ['71.171.93.80']
# WEBSOCKET_CLIENT_INTERFACE = '71.171.93.80'

# other settings
IDLE_TIMEOUT = 3600 * 7
PERMISSION_PLAYER_DEFAULT = "Builders"
IRC_ENABLED = True

LOCKDOWN_MODE = False


GAME_DIRECTORY_LISTING = {
    'game_status': 'launched',
    'game_website': 'http://silvren.com:4281',
    'listing_contact': 'a@a.com',
    'telnet_hostname': 'silvren.com',
    'telnet_port': 4280,
    'short_description': "The Evennia demo server",
    'long_description':'The Evennia demo server shows off a standard install of Evennia. People can play around as builders and explore some of the functi    onality. You can chat to deveopers in the Evennia IRC channel directly from the demo. Max idle time is seven days and the demo may be reset without notice,     at which point you need to recreate your account.'
    }



######################################################################
# Django web features
######################################################################


# The secret key is randomly seeded upon creation. It is used to sign
# Django's cookies. Do not share this with anyone. Changing it will
# log out all active web browsing sessions. Game web client sessions
# may survive.
SECRET_KEY = 'H/,^%v)6+_7.~TiR;BK*]-u$"fEMZF(w`[2=j&nV'
