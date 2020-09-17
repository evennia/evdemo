"""
Commands

Commands describe the input the account can do to the game.

"""

from evennia import Command as BaseCommand
from evennia import default_cmds
from evennia.commands import cmdset

class Command(BaseCommand):
    """
    Inherit from this if you want to create your own command styles
    from scratch.  Note that Evennia's default commands inherits from
    MuxCommand instead.

    Note that the class's `__doc__` string (this text) is
    used by Evennia to create the automatic help entry for
    the command, so make sure to document consistently here.

    Each Command implements the following methods, called
    in this order (only func() is actually required):
        - at_pre_command(): If this returns True, execution is aborted.
        - parse(): Should perform any extra parsing needed on self.args
            and store the result on self.
        - func(): Performs the actual work.
        - at_post_command(): Extra actions, often things done after
            every command, like prompts.

    """
    pass

class CmdNoLimbo(default_cmds.MuxCommand):
    """
    This command is not available in Limbo. Go to the |ySandbox|n to experiment and get the full help text.

    """
    key = "build"
    locks = "cmd:perm(desc) or perm(Builders)"
    help_category = "Building"

    def func(self):
        self.caller.msg("Building is not available in Limbo. "
                        "Go to the |ySandbox| to experiment and get all build commands.")


class CmdTap(BaseCommand):
    """
    Inspect character actions for debug purposes.

    Usage:
        tap <object or #dbref>
        untap

    """
    key = "tap"
    aliases = ["untap"]
    locks = "cmd:superuser()"

    def parse(self):
        self.args = self.args.strip()

    def func(self):

        caller = self.caller

        if self.cmdname == "untap":
            if caller.ndb.tapped_data:
                targetsess, orig_data_in, orig_data_out = caller.ndb.tapped_data
                targetsess.data_in = orig_data_in
                targetsess.data_out = orig_data_out
                caller.msg(f"|rUntapped {targetsess.account.name}.|n")
                del caller.ndb.tapped_data
            else:
                caller.msg("No tap to untap.")
            return

        if not self.args:
            caller.msg("Usage: tap <object or #dbref> or untap")
            return

        if caller.ndb.tapped_data:
            targetsess, _, _ = caller.ndb.tapped_data
            caller.msg(f"|rYou are already tapping {targetsess.account.name}. Untap first.")
            return

        target = caller.search(self.args, global_search=True)
        if not target:
            return
        targetsess = target.sessions.get()[0]

        def _patched_data_in(*args, **kwargs):
            try:
                text = kwargs["text"][0][0].strip('\n')
            except (IndexError, KeyError, ValueError):
                text = kwargs
            taptxt = f"|wTAP|||g {targetsess.account.name} cmd:>|n '{text}'"
            if text != 'idle':
                caller.msg(taptxt)
            targetsess.sessionhandler.call_inputfuncs(targetsess, **kwargs)

        def _patched_data_out(*args, **kwargs):
            try:
                text = kwargs["text"]
                if not isinstance(text, str):
                    text = text[0]  # a tuple
                text = text.strip("\n")
                text = "|wTAP|||n " + "\n|wTAP|||n ".join(text.split("\n"))
            except (IndexError, KeyError, ValueError):
                text = kwargs
            taptxt = f"|wTAP|||y {targetsess.account.name} sees:|n\n{text}"
            caller.msg(taptxt)
            targetsess.sessionhandler.data_out(targetsess, **kwargs)

        # patch object with custom version
        caller.ndb.tapped_data = (targetsess, targetsess.data_in, targetsess.data_out)
        targetsess.data_in = _patched_data_in
        targetsess.data_out = _patched_data_out

        caller.msg(f"|gStart tapping {targetsess.account.name}...|n")

#------------------------------------------------------------
#
# The default commands inherit from
#
#   evennia.commands.default.muxcommand.MuxCommand.
#
# If you want to make sweeping changes to default commands you can
# uncomment this copy of the MuxCommand parent and add
#
#   COMMAND_DEFAULT_CLASS = "commands.command.MuxCommand"
#
# to your settings file. Be warned that the default commands expect
# the functionality implemented in the parse() method, so be
# careful with what you change.
#
#------------------------------------------------------------

#from evennia.utils import utils
#class MuxCommand(Command):
#    """
#    This sets up the basis for a MUX command. The idea
#    is that most other Mux-related commands should just
#    inherit from this and don't have to implement much
#    parsing of their own unless they do something particularly
#    advanced.
#
#    Note that the class's __doc__ string (this text) is
#    used by Evennia to create the automatic help entry for
#    the command, so make sure to document consistently here.
#    """
#    def has_perm(self, srcobj):
#        """
#        This is called by the cmdhandler to determine
#        if srcobj is allowed to execute this command.
#        We just show it here for completeness - we
#        are satisfied using the default check in Command.
#        """
#        return super(MuxCommand, self).has_perm(srcobj)
#
#    def at_pre_cmd(self):
#        """
#        This hook is called before self.parse() on all commands
#        """
#        pass
#
#    def at_post_cmd(self):
#        """
#        This hook is called after the command has finished executing
#        (after self.func()).
#        """
#        pass
#
#    def parse(self):
#        """
#        This method is called by the cmdhandler once the command name
#        has been identified. It creates a new set of member variables
#        that can be later accessed from self.func() (see below)
#
#        The following variables are available for our use when entering this
#        method (from the command definition, and assigned on the fly by the
#        cmdhandler):
#           self.key - the name of this command ('look')
#           self.aliases - the aliases of this cmd ('l')
#           self.permissions - permission string for this command
#           self.help_category - overall category of command
#
#           self.caller - the object calling this command
#           self.cmdstring - the actual command name used to call this
#                            (this allows you to know which alias was used,
#                             for example)
#           self.args - the raw input; everything following self.cmdstring.
#           self.cmdset - the cmdset from which this command was picked. Not
#                         often used (useful for commands like 'help' or to
#                         list all available commands etc)
#           self.obj - the object on which this command was defined. It is often
#                         the same as self.caller.
#
#        A MUX command has the following possible syntax:
#
#          name[ with several words][/switch[/switch..]] arg1[,arg2,...] [[=|,] arg[,..]]
#
#        The 'name[ with several words]' part is already dealt with by the
#        cmdhandler at this point, and stored in self.cmdname (we don't use
#        it here). The rest of the command is stored in self.args, which can
#        start with the switch indicator /.
#
#        This parser breaks self.args into its constituents and stores them in the
#        following variables:
#          self.switches = [list of /switches (without the /)]
#          self.raw = This is the raw argument input, including switches
#          self.args = This is re-defined to be everything *except* the switches
#          self.lhs = Everything to the left of = (lhs:'left-hand side'). If
#                     no = is found, this is identical to self.args.
#          self.rhs: Everything to the right of = (rhs:'right-hand side').
#                    If no '=' is found, this is None.
#          self.lhslist - [self.lhs split into a list by comma]
#          self.rhslist - [list of self.rhs split into a list by comma]
#          self.arglist = [list of space-separated args (stripped, including '=' if it exists)]
#
#          All args and list members are stripped of excess whitespace around the
#          strings, but case is preserved.
#        """
#        raw = self.args
#        args = raw.strip()
#
#        # split out switches
#        switches = []
#        if args and len(args) > 1 and args[0] == "/":
#            # we have a switch, or a set of switches. These end with a space.
#            switches = args[1:].split(None, 1)
#            if len(switches) > 1:
#                switches, args = switches
#                switches = switches.split('/')
#            else:
#                args = ""
#                switches = switches[0].split('/')
#        arglist = [arg.strip() for arg in args.split()]
#
#        # check for arg1, arg2, ... = argA, argB, ... constructs
#        lhs, rhs = args, None
#        lhslist, rhslist = [arg.strip() for arg in args.split(',')], []
#        if args and '=' in args:
#            lhs, rhs = [arg.strip() for arg in args.split('=', 1)]
#            lhslist = [arg.strip() for arg in lhs.split(',')]
#            rhslist = [arg.strip() for arg in rhs.split(',')]
#
#        # save to object properties:
#        self.raw = raw
#        self.switches = switches
#        self.args = args.strip()
#        self.arglist = arglist
#        self.lhs = lhs
#        self.lhslist = lhslist
#        self.rhs = rhs
#        self.rhslist = rhslist
#
#        # if the class has the account_caller property set on itself, we make
#        # sure that self.caller is always the account if possible. We also create
#        # a special property "character" for the puppeted object, if any. This
#        # is convenient for commands defined on the Account only.
#        if hasattr(self, "account_caller") and self.account_caller:
#            if utils.inherits_from(self.caller, "evennia.objects.objects.DefaultObject"):
#                # caller is an Object/Character
#                self.character = self.caller
#                self.caller = self.caller.account
#            elif utils.inherits_from(self.caller, "evennia.accounts.accounts.DefaultAccount"):
#                # caller was already an Account
#                self.character = self.caller.get_puppet(self.session)
#            else:
#                self.character = None
#
