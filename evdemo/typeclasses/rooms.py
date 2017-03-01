"""
Room

Rooms are simple containers that has no location of their own.

"""

from evennia import DefaultRoom


class Room(DefaultRoom):
    """
    Rooms are like any Object, except their location is None
    (which is default). They also use basetype_setup() to
    add locks so they cannot be puppeted or picked up.
    (to change that, use at_object_creation instead)

    See examples/object.py for a list of
    properties and methods available on all Objects.
    """
    pass

from evennia import default_cmds, CmdSet

class RestrictedCommand(default_cmds.MuxCommand):
    """
    This command is not available in this location.
    Please experiment in the Sandbox.
    """
    key = "restricted"
    aliases = ("@tel", "@alias", "@wipe", "@set", "@name", "@desc",
               "@cpattr", "@mvattr", "@copy", "@open", "@link", "@unlink",
               "@create", "@dig", "@tunnel", "@delete", "@typeclass",
               "@lock", "sethome", "@tag", "@spawn")

    def func(self):
        """Run the restriction """
        err = "|RThe command |r%s|R is not available in this location. Please experiment" \
                      " in the |ySandbox|n." % self.cmdstring
        self.caller.msg(err)

class RestrictedCmdSet(CmdSet):
    """Restricted cmdset"""
    key = "restricted_cmdset"
    priority = 2
    def at_cmdset_creation(self):
        self.add(RestrictedCommand())

class RestrictedRoom(Room):
    """
    A room type with limited builder commands.
    """
    def at_object_creation(self):
        self.locks.add("call:not perm(Wizards)")
        self.cmdset.add(RestrictedCmdSet, permanent=True)
