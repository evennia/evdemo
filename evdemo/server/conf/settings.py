"""
Evennia settings file.

The available options are found in the default settings file found
here:

$devel/evennia/evennia-trunk/evennia/settings_default.py

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
TELNET_PORTS = [4000]
WEBSERVER_PORTS = [(4001, 4005)]
# ALLOWED_HOSTS = ["demo.evennia.com", "128.199.48.138"]
TELNET_INTERFACES = ["128.199.48.138"]
AMP_PORT = 4003
WEBSERVER_INTERFACES = ["127.0.0.1"]
WEBSOCKET_CLIENT_INTERFACE = "127.0.0.1"
WEBSOCKET_CLIENT_PORT = 4002
WEBSOCKET_CLIENT_URL = "wss://demo.evennia.com:4002/"
# WEBSOCKET_CLIENT_INTERFACE = "128.199.48.138"
# TELNET_INTERFACES = ['71.171.93.80']
# WEBSOCKET_CLIENT_INTERFACE = '71.171.93.80'

# other settings
IDLE_TIMEOUT = 3600 * 24 * 7
PERMISSION_ACCOUNT_DEFAULT = "Builders"
IRC_ENABLED = True

# LOCKDOWN_MODE = True
# DEBUG=True

GLOBAL_SCRIPTS = {
    "Evscaperoom gc": {
        'typeclass': "evscaperoom.scripts.CleanupScript"
    }
}

######################################################################
# Django web features
######################################################################

try:
    from server.conf.secret_settings import *
except ImportError:
    print("secret_settings.py file not found or failed to import.")

try:
    # Created by the `evennia connections` wizard
    from .connection_settings import *
except ImportError:
    pass
