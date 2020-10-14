# -*- coding: utf-8 -*-
"""
Connection screen

Texts in this module will be shown to the user at login-time.

Evennia will look at global string variables (variables defined
at the "outermost" scope of this module and use it as the
connection screen. If there are more than one, Evennia will
randomize which one it displays.

The commands available to the user when the connection screen is shown
are defined in commands.default_cmdsets.UnloggedinCmdSet and the
screen is read and displayed by the unlogged-in "look" command.

"""

from django.conf import settings
from evennia import utils

CONNECTION_SCREEN = \
"""|b==============================================================|n
 Welcome to the demo install of Evennia - |g%s|n,
 currently running version %s!

 This demo instance may reset without warning, in which case
 you will have to recreate your account.

 If you have an existing account, connect to it by typing:
      |wconnect <username> <password>|n
 If you need to create an account, type (without the <>'s):
      |wcreate <username> <password>|n

 Enter |whelp|n for more info. |wlook|n will re-show this screen.
|b==============================================================|n""" \
 % (settings.SERVERNAME, utils.get_evennia_version())
