"""
Evennia settings file.

The full options are found in the default settings file found here:

/home/griatch/evdemo/evennia/evennia/settings_default.py

Note: Don't copy more from the default file than you actually intend to
change; this will make sure that you don't overload upstream updates
unnecessarily.

"""

# Use the defaults from Evennia unless explicitly overridden
import os
from evennia.settings_default import *

######################################################################
# Evennia base server config
######################################################################

# This is the name of your game. Make it catchy!
SERVERNAME = "Evdemo"

# Path to the game directory (use EVENNIA_DIR to refer to the
# core evennia library)
GAME_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Place to put log files
LOG_DIR = os.path.join(GAME_DIR, "server", "logs")
SERVER_LOG_FILE = os.path.join(LOG_DIR, 'server.log')
PORTAL_LOG_FILE = os.path.join(LOG_DIR, 'portal.log')
HTTP_LOG_FILE = os.path.join(LOG_DIR, 'http_requests.log')

######################################################################
# Evennia Database config
######################################################################

TELNET_PORTS = [4444]
#TELNET_INTERFACES = ['127.0.0.1'] # lockdown mode
TELNET_INTERFACES = ['162.208.48.93']
AMP_PORT = 4445
WEBSERVER_ENABLED = True
WEBCLIENT_ENABLED = True
WEBSERVER_PORTS = [(8000, 5001)]
WEBSOCKET_CLIENT_PORT = 8022
#WEBSOCKET_CLIENT_INTERFACE = '127.0.0.1' # lockdown mode
WEBSOCKET_CLIENT_INTERFACE = '176.58.89.89'
WEBSOCKET_CLIENT_URL = 'ws://162.208.48.93'
#DEBUG = True

WEBSERVER_INTERFACES = ['162.208.48.93']
IDLE_TIMEOUT = 3600 * 24 * 7 # a week
PERMISSION_PLAYER_DEFAULT = "Builders"

IRC_ENABLED = True
ALLOWED_HOSTS = ['.horizondark.com']

GAME_DIRECTORY_LISTING = {
    'game_status': 'launched',
    'game_website': 'http://horizondark.com:8000',
    'listing_contact': 'a@a.com',
    'telnet_hostname': 'horizondark.com',
    'telnet_port': 4444,
    }


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(GAME_DIR, "server", "evennia.db3"),
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': ''
        }}

######################################################################
# Django web features
######################################################################

# Absolute path to the directory that holds file uploads from web apps.
# Example: "/home/media/media.lawrence.com"
MEDIA_ROOT = os.path.join(GAME_DIR, "web", "media")

# The master urlconf file that contains all of the sub-branches to the
# applications. Change this to add your own URLs to the website.
ROOT_URLCONF = 'web.urls'

# URL prefix for admin media -- CSS, JavaScript and images. Make sure
# to use a trailing slash. Django1.4+ will look for admin files under
# STATIC_URL/admin.
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(GAME_DIR, "web", "static")

# Directories from which static files will be gathered from.
STATICFILES_DIRS = (
    os.path.join(GAME_DIR, "web", "static_overrides"),
    os.path.join(EVENNIA_DIR, "web", "static"),)

# We setup the location of the website template as well as the admin site.
TEMPLATE_DIRS = (
    os.path.join(GAME_DIR, "web", "template_overrides"),
    os.path.join(EVENNIA_DIR, "web", "templates", ACTIVE_TEMPLATE),
    os.path.join(EVENNIA_DIR, "web", "templates"),)

# The secret key is randomly seeded upon creation. It is used to sign
# Django's cookies. Do not share this with anyone. Changing it will
# log out all active web browsing sessions. Game web client sessions
# may survive.
SECRET_KEY = 'U&9fbRJ@ere3rMjrGPOex(p$nFc8gsdfsPRs1Ht`3"Sy!M);#}4rl"'  # changed on deployment
