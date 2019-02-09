#! /usr/bin/python
# Copyright (c) 2009 Steven Robertson.
#           (c) 2010-2019 Griatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or
# later, as published by the Free Software Foundation.

"""
Evennia codebot system and github webhook server

This is a central bot for relaying data about the Evennia development
(www.evennia.com). It's originally based on a part of Steven Robertson's
"googlecode-irc-bot" (https://github.com/jmhobbs/googlecode-irc-bot) which was
for the old google-code site. Since then it was heavily reworked and modified
for use with the Evennia project and updated to work with github.

- logs IRC channel to logfile (access to it by talking to the bot)
- parse github webhooks to get relevant events, echoes to IRC channel
- parse RSS feeds from blog/forum, echoes to IRC channel
- posts the IRC log regularly to Evennia mailing list (disabled, it was pretty spammy)

The bot uses threading to avoid lockups when loading very slow RSS urls (this
used to cause it to time out). It implements a subset of the github webhooks in
order to report them to IRC.

"""
__version__ = "0.6"

import time
import re
import os
import hmac
import json
import traceback
import feedparser
import inspect
from hashlib import sha1
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.words.protocols import irc
from twisted.mail.smtp import sendmail
from email.mime.text import MIMEText
from twisted.internet import reactor, protocol, task, threads
from twisted.python import log


# ------------------------------------------------------------
#  Print nice log messages
# ------------------------------------------------------------

def report(text):
    "Pretty-print the activity of the system"
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]", time.localtime(time.time()))
    print("%s: %s" % (timestamp, text))


# ------------------------------------------------------------
# IRC message formatting
# -----------------------------------------------------------

# IRC colors (mIRC)
CLR = {"bold": "\002",
       "color": "\003",
       "reset": "\017",
       "italic": "\026",
       "underline": "\037",
       "white": "00", "black": "01", "blue": "02", "green": "03", "red": "04", "brown": "05",
       "purple": "06", "orange": "07", "yellow": "08", "lime": "09", "teal": "10",
       "cyan": "11", "sky": "12", "pink": "13", "grey": "14", "silver": "15"}


def clr(txt, color=False, bold=False, italic=False, underline=False):
    return "{start}{color}{bold}{italic}{underline}{txt}{reset}" .format(
        start=CLR['color'],
        color=CLR.get(color, ""),
        bold=CLR['bold'] if bold else "",
        italic=CLR['italic'] if italic else "",
        underline=CLR['underline'] if underline else "",
        txt=txt,
        reset=CLR['reset'])


# helpers

def fmt_url(msg):
    return clr(msg, 'blue', underline=True)


def fmt_event(event):
    return clr("[{}]".format(event), 'yellow')


def fmt_repo(msg):
    return clr(msg, "cyan")


def fmt_branch(msg):
    return clr(msg, "red")


def fmt_path(msg):
    return clr(msg, "white")


def fmt_crop(text, length=60):
    "Crop text to given length and remove line breaks inside text"
    nlen = len(text)
    text = re.sub(r"\n\r|\r\n|\r|\n", r"\\", text.strip())
    diff = nlen - length
    if nlen > length:
        text = "{txt}{postfix}".format(
            txt=text[:length].strip("\ "),
            postfix=clr("[{} more]".format(diff) if diff > 10 else "[...]", 'grey'))
    return text


def fmt_sequence(seq, length=4):
    assert(length % 2 == 0)  # must be even
    if len(seq) > length:
        seq = seq[:length//2] + [None] + seq[-length//2:]
    return seq


# ------------------------------------------------------------
# Handle receiving Github webhooks
# ------------------------------------------------------------


class WebHookServer(Resource):
    """
    The webhook server sits on a port and listens for POST requests from a webhook
    set up on github to point to the server with this server. Supported events are
    parsed and passed to the ircbot. Each `_parse_*` method parses an event with that
    specific name.

    """
    isLeaf = True

    def __init__(self, ircbot, secret=None):
        """
        Args:
            ircbot_factory (ProtocolFactory): An IRC bot (factory) with a 'bot' property
                for the relaying parsed data to the connected IRC bot via bot.trysay().
            secret (str): Secret used to decrypt `X-Hub Signature` header
                sent from github when 'secret' is set

        """
        self.secret = secret
        self.ircbot = ircbot

        if secret:
            report("WebhookServer starting with GITHUB_WEBHOOK_SECRET='{}'.".format(secret))
        else:
            report("WebhookServer starting without GITHUB_WEBHOOK_SECRET set!")

        # Use all methods named _parse_* as parsers

        self.event_parsers = {parser[7:]: method for parser, method
                              in inspect.getmembers(self, predicate=inspect.ismethod)
                              if method.__name__.startswith("_parse_")}

    def _validate_signature(self, request):
        """
        Extract and validate the `X-Hub-Signature` header using the stored
        secret to make sure incoming data is ok. Guidelines here:
        http://pubsubhubbub.googlecode.com/svn/trunk/pubsubhubbub-core-0.3.html#authednotify

        Args:
            request (Request): Incoming POST request.

        Returns:
            content (JSON or None): The content or None if signature validation failed.

        """
        signature = request.getHeader("X-Hub-Signature")
        content = request.content.read()

        if self.secret is not None:
            hsh = hmac.new(self.secret, content, sha1)
            if hsh.digest().encode("hex") != signature[5:]:
                report("A request arrived with mismatching signature.")
                return None

        return content

    # event parsers

    def _parse_default(self, data):
        "Fallback for debugging"
        return str(data)

    def _parse_ping(self, data):
        zen = data['zen']
        name = data['hook']['name']
        repo = data['repository']['name']
        user = data['sender']['login']

        return "{event} {user} connected webhook '{name}' to {repo}: zen: {zen}".format(
            event=fmt_event("ping"),
            user=user,
            name=name,
            repo=fmt_repo(repo),
            zen=zen)

    def _parse_push(self, data):
        _show_number = 4  # how many commits to show per push. Must be even.

        repo = data['repository']['name']
        branch = data['ref'][11:] if data['ref'].startswith("refs/heads/") else data['ref']
        pusher = data['pusher']['name']
        compare_url = data['compare']
        raw_commits = data['commits']
        ncommits = len(raw_commits)

        if not ncommits:
            # this can happen on empty branch creation etc; ignore this event if so
            return

        raw_commits = fmt_sequence(raw_commits, _show_number)

        commits = []
        for commit in raw_commits:
            if commit is None:
                commits.append(" ... [{} more] ...".format(ncommits - _show_number))
            else:
                author = commit['author']['name']
                message = fmt_crop(commit['message'])
                url = commit['url'][:-33]  # cut away most of the sha
                commits.append(" [{author}]: {message}".format(
                    author=author,
                    message=message,
                    url=fmt_url(url)))  # don't show url to shorten it

        string = ("{event} {pusher} pushed {ncommits} commit{splural} to "
                  "{repo}/{branch}{compare_url}:{linebreak}{commits}".format(
                        event=fmt_event("push"),
                        pusher=pusher,
                        ncommits=ncommits,
                        splural="s" if ncommits > 1 else "",
                        repo=fmt_repo(repo),
                        branch=fmt_branch(branch),
                        compare_url=" ({})".format(fmt_url(compare_url)) if ncommits > 1 else "",
                        linebreak="\n" if ncommits > 1 else "",
                        commits="\n".join(commits)))
        return string

    def _parse_commit_comment(self, data):
        comment = data['comment']
        url = comment['html_url']
        path = comment['path']
        line = comment['line']
        repo = data['repository']['name']
        author = comment['user']['login']
        text = comment['body']

        return "{event} {author} commented on {path}, line {line} in {repo}: {text} ({url})".format(
            event=fmt_event("commit comment"),
            author=author,
            path=fmt_path(path),
            line=fmt_path(line),
            repo=fmt_repo(repo),
            text=fmt_crop(text),
            url=fmt_url(url))

    def _parse_gollum(self, data):  # wiki edits
        _show_number = 4  # must be even

        repo = data['repository']['name']
        author = data['sender']['login']
        raw_pages = data['pages']
        npages = len(raw_pages)
        raw_pages = fmt_sequence(raw_pages, _show_number)

        pages = []
        for page in raw_pages:
            if page is None:
                pages.append(" ... [[] more] ...".format(npages - _show_number))
            else:
                page_name = page['page_name']
                title = page['title']
                title = " ({})".format(fmt_crop(title)) if title != page_name else ""
                summary = ": {}".format(fmt_crop(page['summary'])) if page['summary'] else ""
                action = page['action']
                url = page['html_url']
                pages.append(" [{action}]: {page_name}{title}{summary} ({url})".format(
                    action=action,
                    page_name=fmt_path(page_name),
                    title=title,
                    summary=summary,
                    url=fmt_url(url)))

        string = ("{event} {author} updated {repo}/{wiki}:{linebreak}{pages}".format(
            event=fmt_event("wiki"),
            author=author,
            repo=fmt_repo(repo),
            wiki=fmt_branch("wiki"),
            linebreak="\n" if npages > 1 else "",
            pages="\n".join(pages)))

        return string

    def _parse_issues(self, data):
        action = data['action']
        if action in ('deleted', 'edited', 'transferred', 'pinned', 'unpinned',
                      'assigned', 'unassigned', 'labeled', 'unlabeled',
                      'milestoned', 'demilestoned'):
            # we don't want too much spam
            return None
        issue = data['issue']
        issue_num = issue['number']
        url = issue['html_url']
        title = issue['title']
        repo = data['repository']['name']
        user = data['sender']['login']

        return ("{event} {user} {action} issue #{number} in {repo}: {title} ({url})".format(
            event=fmt_event("issues"),
            user=user,
            action=fmt_path(action),
            number=fmt_path(issue_num),
            repo=fmt_repo(repo),
            title=fmt_repo(title),
            url=fmt_url(url)))

    def _parse_issue_comment(self, data):
        action = data['action']
        if action in ('edited', 'deleted'):
            # avoid spam when editing comments
            return None
        repo = data['repository']['name']
        issue = data['issue']
        issue_title = issue['title']
        issue_num = issue['number']
        comment = data['comment']
        url = comment['html_url']
        user = data['sender']['login']
        text = comment['body']

        return ("{event} {user} commented on issue "
                "#{number} ({title}) in {repo}: {text} ({url})".format(
                    event=fmt_event("issue comment"),
                    user=user,
                    action=action,
                    number=fmt_path(issue_num),
                    title=fmt_crop(issue_title),
                    repo=fmt_repo(repo),
                    text=fmt_crop(text),
                    url=fmt_url(url)))

    def _parse_create(self, data):  # create branch/tag
        ref = data['ref']
        ref_type = data['ref_type']
        repo = data['repository']['name']
        sender = data['sender']['login']

        if ref_type == 'branch':
            url = data['repository']['html_url'] + "/tree/" + ref  # github branch url
            return ("{event} {user} created new branch {repo}/{branch} {url}".format(
                    event=fmt_event("create"),
                    user=sender,
                    repo=fmt_repo(repo),
                    branch=fmt_branch(ref),
                    url=fmt_url(url)))
        elif ref_type == 'tag':
            url = data['repository']['html_url'] + "/releases"   # tags show on this page
            return ("{event} {user} added new tag {repo}/{ref} {url}".format(
                    event=fmt_event("create"),
                    user=sender,
                    repo=fmt_repo(repo),
                    ref=fmt_branch(ref),
                    url=fmt_url(url)))
        elif ref_type == 'repository':
            url = data['repository']['html_url']
            return ("{event} {user} created new repository {repo} {url}".format(
                    event=fmt_event("create"),
                    user=sender,
                    repo=fmt_repo(repo),
                    url=fmt_url(url)))

    def _parse_project(self, data):
        action = data['action']
        if action in ('edited',):
            # avoid spam from edits
            return None
        repo = data['repository']['name']
        project = data['project']
        url = project['html_url']
        name = project['name']
        text = fmt_crop(project['body'])
        user = data['sender']['login']

        return ("{event} {user} {action} project in {repo}: {name} - {text} {url}".format(
            event=fmt_event("project"),
            user=user,
            action=fmt_path(action),
            name=name,
            repo=fmt_repo(repo),
            text=text,
            url=fmt_url(url)))

    # TODO: Currently project_card API does not include http_urls nor a reference to
    # which project the card belongs to, making it useless for us at this time.

    def _parse_pull_request(self, data):
        action = data['action'].replace("_", "-")
        if action in ('synchronize',):
            # this would create a lot of spam
            return None

        number = data['number']
        pull_request = data['pull_request']
        url = pull_request['html_url']
        repo = data['repository']['name']
        head = pull_request['head']['ref']
        title = pull_request['title']
        merged = pull_request['merged_at']
        user = data['sender']['login']

        if action == 'closed':
            action = 'merged' if merged else 'closed (no merge)'

        return ("{event} {user} {action} PR #{num} ({title}) to {repo}/{head} {url}".format(
            event=fmt_event("pull request"),
            user=user,
            action=fmt_path(action),
            num=fmt_path(number),
            title=fmt_crop(title),
            repo=fmt_repo(repo),
            head=fmt_branch(head),
            url=fmt_url(url)))

    def _parse_pull_request_review(self, data):
        action = data['action']
        if action in ("edited", "dismissed"):
            return None
        review = data['review']
        url = review['html_url']
        text = review['body']
        user = data['sender']['login']
        pull_request = data['pull_request']
        pr_number = pull_request['number']
        pr_title = pull_request['title']

        return ("{event} {user} reviewed PR #{num} ({title}): {text} {url}".format(
            event=fmt_event("PR review"),
            user=user,
            num=fmt_path(pr_number),
            title=fmt_crop(pr_title),
            text=fmt_crop(text),
            url=fmt_url(url)))

    def _parse_pull_request_review_comment(self, data):
        action = data['action']
        if action in ('edited', 'deleted'):
            # avoid spam when editing comments
            return None
        repo = data['repository']['name']
        pull_request = data['pull_request']
        pr_title = pull_request['title']
        pr_number = pull_request['number']
        comment = data['comment']
        url = comment['html_url']
        user = data['sender']['login']
        text = comment['body']

        return ("{event} {user} {action} review comment on PR "
                "#{number} ({title}) for {repo}: {text} ({url})".format(
                    event=fmt_event("PR review"),
                    user=user,
                    action=action,
                    number=fmt_path(pr_number),
                    title=fmt_crop(pr_title),
                    repo=fmt_repo(repo),
                    text=fmt_crop(text),
                    url=fmt_url(url)))

    def _parse_fork(self, data):
        forkee = data['forkee']
        private = " (to private repo)" if forkee['private'] else ""
        name = forkee['name']
        user = data['sender']['login']
        url = forkee['html_url']

        return ("{event} {user} forked {name}{private} {url}".format(
            event=fmt_event("fork"),
            user=user,
            name=fmt_repo(name),
            private=private,
            url=fmt_url(url)))

    # entrypoints

    def handle_event(self, event, data):
        """
        Parse event using a suitable parser and relay the result to the IRC bot.

        """
        event_parser = self.event_parsers.get(event)  # , self._parse_default)

        if event_parser:
            try:
                result = event_parser(data)
                if result:
                    # we ignore certain sub-parts of events
                    self.ircbot.bot.trysay(result)
            except AttributeError:
                if self.ircbot.bot is None:
                    report("Note: Event '{}' received before bot "
                           "finished connecting.".format(event))
                else:
                    report(traceback.format_exc(30))
            except Exception:
                report(traceback.format_exc(30))
        else:
            # we log this to see if we missed something
            report("Webhook event '{}' lacks a parser.".format(event))

    def render_POST(self, request):
        """
        Handle the incoming POST request sent from github's webhook service
        when an event is triggered.

        """

        content = self._validate_signature(request)
        if content is None:
            return ""

        data = json.loads(content)
        event = request.getHeader("X-GitHub-Event")

        self.handle_event(event, data)

        return ""

    def start(self, port):
        "Start webhook server."
        webhook_site = Site(self)
        reactor.listenTCP(port, webhook_site)


# ------------------------------------------------------------
# Tail log files
# ------------------------------------------------------------

def tail_log_file(filename, offset, nlines):
    """
    Return the tail of a logfile without writing to it.

    Args:
        filename (str): The name of the log file, presumed to be in
            the Evennia log dir.
        offset (int): The line offset *from the end of the file* to start
            reading from. 0 means to start at the latest entry.
        nlines (int): How many lines to return, counting backwards
            from the offset. If file is shorter, will get all lines.
    Returns:
        lines (list): A list with the nline entries from the end of the file, or
            all if the file is shorter than nlines.

    """
    def seek_file(filehandle, offset, nlines):
        "step backwards in chunks and stop only when we have enough lines"
        lines_found = []
        buffer_size = 4098
        block_count = -1
        while len(lines_found) < (offset + nlines):
            try:
                # scan backwards in file, starting from the end
                filehandle.seek(block_count * buffer_size, os.SEEK_END)
            except IOError:
                # file too small for this seek, take what we've got
                filehandle.seek(0)
                lines_found = filehandle.readlines()
                break
            lines_found = filehandle.readlines()
            block_count -= 1
        # return the right number of lines
        lines_found = lines_found[-nlines-offset:-offset if offset else None]
        return lines_found

    with open(filename, 'r') as filehandle:
        return seek_file(filehandle, offset, nlines)


# ------------------------------------------------------------
# IRC logger
# ------------------------------------------------------------

class IRCLog(object):
    """
    Stores and retrieves an irc log for local storage. This log can then just
    be read or parts of it can be read out to be sent to a mailing list etc.
    The log also has the ability to be 'published', which will put a special
    marker into the log to avoid the same parts being published more than once.

    Log is stored as an integer number followed by the log line(s).

    """
    def __init__(self, filename):
        "Sets up the logger"
        self.filename = filename
        self.filehandle = open(self.filename, 'a', 0)
        self.pmarker = "<<<PUBLISHED>>>"

    def write_log(self, msg):
        """
        Access method. Writes an entry to log file.
        The message should already be clumped with the
        user at this point (so the display of 'actions'
        should already be handled at this point)
        """
        if msg.startswith('[off]'):
            # don't log lines beginning with "[off]".
            return
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]", time.localtime(time.time()))
        log_msg = "%s %s\n" % (timestamp, msg.strip())
        self.filehandle.write(log_msg)

    def read_unpublished_log(self):
        """
        Returns the log back to last <<<PUBLISHED>>> marker
        """
        self.filehandle.close()
        with open(self.filename, 'r') as f:
            lines = f.read().rsplit(self.pmarker, 1)
        lines = lines[-1].strip()
        # we want to keep the filehandle open henceforth.
        self.filehandle = open(self.filename, 'a', 0)
        return lines

    def tail_log(self, offset=0, nlines=20):
        """
        Return nlines lines of text from the end of the log,
        or starting nend lines from the end.
        """
        return "\n".join(tail_log_file(self.filename, offset, nlines))

    def close_logfile(self):
        "Cleanly close log file"
        try:
            self.filehandle.close()
        except IOError:
            pass

    def mark_log_as_published(self):
        """
        Put the <<<PUBLISHED>>> marker in the log. This should
        be called explicitly only once the publication actually
        successfully completed.
        """
        self.filehandle.write("%s\n" % self.pmarker)


# ------------------------------------------------------------
# The 'evenniacode' IRC bot
# ------------------------------------------------------------

class IRCBotInstance(irc.IRCClient):
    """
    An IRC bot protocol that tracks actitivity in a channel as well
    as sends text to it when prompted.

    """
    lineRate = 1

    # assigned by factory at creation
    nickname = None
    logger = None
    factory = None
    channel = None

    def signedOn(self):
        """
        Connected. We make sure to store ourself on factory here
        (this version only allows one bot instance, otherwise
         the factory would hold a list of bots)
        """
        self.join(self.channel)
        self.factory.bot = self

    def trysay(self, msg):
        """Attempts to send the given message to the channel."""
        self.msg(self.channel, msg)
        self.logger.write_log(msg)
        return True

    def privmsg(self, user, channel, msg):
        "A message was sent to channel or to us"
        user = user.split('!', 1)[0]
        if channel == self.nickname:
            # a private message to us - don't log it
            nlines = 20
            if msg.startswith("log"):
                # we accept a private message on the form log <nlines>
                arg = msg[3:]
                if not arg.strip():
                    arg = 0
                try:
                    offset = int(arg)
                except Exception:
                    self.msg(
                        user,
                        "You will always get a maximum of {nlines} logged lines from me. "
                        "But you can choose how far back those {nlines} lines begin. "
                        "Example: messaging me 'log 200' will give you {nlines} lines from "
                        "the log starting 200 lines from the latest entry.".format(nlines=nlines))
                    return
                logtxt = self.logger.tail_log(offset, nlines=nlines)
                if logtxt:
                    report("log requested by %s (position %i)" % (user, offset))
                    self.msg(user, logtxt)
                else:
                    self.msg(user, "No log found.")
            else:
                # any other input
                self.msg(user, "To view backlog, try 'log' or 'log help'.")

        elif not msg.startswith('***'):
            self.logger.write_log("%s: %s" % (user, msg))

    def action(self, user, channel, msg):
        "An action was done in channel"
        if not msg.startswith('**'):
            user = user.split('!', 1)[0]
            self.logger.write_log("* %s %s" % (user, msg))

    def connectionMade(self):
        "Called when client connects"
        irc.IRCClient.connectionMade(self)
        report("connected to %s" % self.channel)

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        report("disconnected from %s" % self.channel)


class IRCBot(protocol.ReconnectingClientFactory):
    """
    Creates instances of IRCBotInstance, connecting with
    a staggered increase in delay. To send data, access self.bot.

    """
    # scaling reconnect time
    initialDelay = 1
    factor = 1.5
    maxDelay = 60

    def __init__(self, nickname, channel, logger):
        "Storing some important protocol properties"
        self.nickname = nickname
        self.logger = logger
        self.channel = channel
        self.bot = None

    def buildProtocol(self, addr):
        "Build the protocol and assign it some properties"
        protocol = IRCBotInstance()
        protocol.factory = self
        protocol.nickname = self.nickname
        protocol.logger = self.logger
        protocol.channel = self.channel
        return protocol

    def startedConnecting(self, connector):
        "Tracks reconnections for debugging"
        report("%s (re)connecting to %s" % (self.nickname, self.channel))

    def start(self, network, port):
        reactor.connectTCP(network, port, self)


# ------------------------------------------------------------
# RSS feed reader
# ------------------------------------------------------------

class FeedReader(object):
    """
    A simple RSS reader using universal feedparser
    """
    def __init__(self, url):
        """
        Setup the feed reader and reset the data we
        already read since before.

        Args:
            url (str): Feed URL to read.

        """
        self.url = url
        self.old_entries = {}
        # we have to do this at startup to not
        # include all entries in the feed back to
        # its beginning
        report("initial fetch of feed %s ..." % self.url)
        self.get_new()

    def get_new(self):
        """
        Trigger a new data fetch from the feed URL.

        Returns:
            new_entries (list): Fetch new data from RSS feed, filtered
            against what we already had loaded from before.

        """
        # report("fetching feed from %s ..." % self.url)
        feed = feedparser.parse(self.url)
        new_entries = []
        for entry in feed['entries']:
            idval = entry['id'] + entry.get("updated", "")
            if idval not in self.old_entries:
                self.old_entries[idval] = entry
                new_entries.append(entry)
        # report("... found %i new entries." % len(new_entries))
        return new_entries


# ------------------------------------------------------------
# Polling/Repeating functions (called repeatedly)
# ------------------------------------------------------------

def report_blog_RSS_updates(feed, botfactory):
    """
    Check devblog RSS and use the evenniacode bot to report updates to IRC.

    Args:
        feed (FeedReader): A initialized feed to the dev blog.
        botfactory (EvenniaCodeBotFactory): The factory used for the active IRC bot.

    Note:
        We run this in a separate thread to avoid locking up the bot (and
        potentially timing out) for very slowly responding RSS urls.

    """
    def feed_return(feed_data, botfactory):
        "callback"
        for entry in reversed(feed_data):
            # announce all new entries
            msg = "[%s] '%s' %s" % (fmt_repo("devblog"),
                                    re.sub(r'<[^>]*?>', '', entry['title']),
                                    fmt_url(entry['link']))
            msg = msg.replace('\n', '').encode('utf-8')
            botfactory.bot.trysay(msg)

    def feed_error(fail):
        "errback"
        report("RSS feed error: %s" % fail.value)
    threads.deferToThread(feed.get_new).addCallback(feed_return, botfactory).addErrback(feed_error)


def report_wiki_RSS_updates(feed, botfactory):
    """
    This is for the github wiki RSS feed which is too verbose. It cuts away more from
    the message but otherwise works the same.
    """
    def feed_return(feed_data, botfactory):
        "callback"
        for entry in reversed(feed_data):
            # announce all new entries
            msg = "[%s] %s pushed to page '%s' %s" % (
                fmt_repo("evennia.wiki"),
                entry["author"],
                entry["link"].rsplit("/")[-1].replace("-", " "),
                fmt_url(entry["link"]))
            msg = msg.replace('\n', '').encode('utf-8')
            botfactory.bot.trysay(msg)

    def feed_error(fail):
        "errback"
        report("wiki RSS feed error: %s" % fail.value)
    threads.deferToThread(feed.get_new).addCallback(feed_return, botfactory).addErrback(feed_error)


def report_forum_RSS_updates(feed, botfactory):
    """
    This is for the google mailing list/forum RSS feed which is too verbose. This handler
    cuts away more from the message but otherwise it works the same as other rss feed handlers.

    """
    def feed_return(feed_data, botfactory):
        "callback"
        for entry in reversed(feed_data):
            # announce all new entries
            msg = "[%s] %s posted '%s' %s" % (fmt_repo("forum"),
                                              entry["author"],
                                              re.sub(r'<[^>]*?>', '', entry['title']),
                                              fmt_url(entry["link"]))
            msg = msg.replace('\n', '').encode('utf-8')
            botfactory.bot.trysay(msg)

    def feed_error(fail):
        "errback"
        report("wiki RSS feed error: %s" % fail.value)

    threads.deferToThread(feed.get_new).addCallback(feed_return, botfactory).addErrback(feed_error)


def mail_IRC_log(logger, channel, smtp, from_addr, to_addr):

    """
    Send latest IRC log to mailing list

    """
    minloglength = 20
    _log = logger.read_unpublished_log()
    lenlog = log.count('\n')
    if not lenlog >= minloglength:
        # skip publication
        report("skipping log publication due to small size (%i/%i lines)" % (lenlog, minloglength))
    else:
        # log long enough, format it
        date = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        string = "Log of IRC channel %s (log published %s)" % (channel, date)
        _log = "%s\n\n%s" % (string, _log)
        # convert log to email
        mail = MIMEText(log)
        mail['Subject'] = "[evennia] %s IRC log - %s" % (channel, date)
        mail['From'] = str(from_addr)
        mail['To'] = str(to_addr)
        # send mail to mailing list

        def errback(fail):
            report("... irc-log mail could not be published: %s" % fail.value)

        def callback(ret):
            logger.mark_log_as_published()
            report("... irc-log mail from %s to %s successfully published." % (from_addr, to_addr))

        report("publishing irc log (%i lines) ..." % lenlog)
        sendmail(smtp, from_addr, to_addr, mail.as_string()).addCallbacks(callback, errback)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def announce_err(fail, typ):
    "errback for reporing error on the commnd line"
    report("%s error: %s" % (typ, fail.value))


def handle_close(irc_logger):
    "callback for handling closing condition"
    irc_logger.close_logfile()
    report("Shutting down system and closing log (waiting for threads to finish)")


if __name__ == '__main__':

    # All per-project customizations should be done here

    # settings for Webhook server
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET", None)
    webhook_port = 7001

    # settings for EvenniaCode bot IRC bot
    bot_nickname = "evenniacode"
    irc_network = "irc.freenode.net"
    irc_port = 6667
    irc_channel = "#evennia"

    # RSS feeds
    rss_check_frequency = 10 * 60  # 10 minutes
    wikifeed = "https://github.com/evennia/evennia/wiki.atom"
    forumfeed = "https://groups.google.com/forum/feed/evennia/msgs/rss_v2_0.xml?num=20"
    blogfeed = "https://evennia.blogspot.com/feeds/posts/default?num=20"

    # settings for email publishing
    log_publish_frequency = 60 * 60 * 24 * 7  # every week
    logfile = "logfile.txt"
    smtp_server = "localhost"
    from_email = "evennia-irc-logs@evennia.com"
    to_email = "evennia-commits@googlegroups.com"

    # ------------------------------------------------------------

    # Start logger

    report("Opening IRC log ...")
    irc_logger = IRCLog(logfile)

    # Starting IRC bot

    report("Configure irc bot %s for %s:%s/%s ..." % (
        bot_nickname, irc_network, irc_port, irc_channel))

    ircbot = IRCBot(bot_nickname, irc_channel, irc_logger)
    ircbot.start(irc_network, irc_port)

    # Start WebhookServer

    report("Configuring webhook server on port %s ... " % webhook_port)

    webhook_server = WebHookServer(ircbot, secret=webhook_secret)
    webhook_server.start(webhook_port)

    # webhook_server.add_event("post", parse_all)

    # Setting up feeds

    # report("Initializing first fetch of wiki feed ... ")
    # wikifeed = FeedReader(wikifeed)

    report("Initializing feeds ... ")

    forumfeed = FeedReader(forumfeed)
    blogfeed = FeedReader(blogfeed)

    # Start tasks and set errbacks on them

    # wikifeed_task = task.LoopingCall(
    #     report_wiki_RSS_updates, wikifeed, ircbot)
    # wikifeed_task.start(
    #     rss_check_frequency, now=False).addErrback(announce_err, "rss 'wiki' feed")

    forumfeed_task = task.LoopingCall(
        report_forum_RSS_updates, forumfeed, ircbot)
    forumfeed_task.start(
        rss_check_frequency, now=False).addErrback(announce_err, "rss 'forum' feed")

    blogfeed_task = task.LoopingCall(
        report_blog_RSS_updates, blogfeed, ircbot)
    blogfeed_task.start(
        rss_check_frequency, now=False).addErrback(announce_err, "rss 'blog' feed")

    report("... all feeds initialized.")

    report("Starting system.")

    # publish_task = task.LoopingCall(
    #    mail_IRC_log, irc_logger, irc_channel, smtp_server, from_email, to_email)
    # publish_task.start(
    #    log_publish_frequency, now=False).addErrback(evenniacode_err, "irc log publishing")

    # catch shutdown signals and start service
    reactor.addSystemEventTrigger('before', 'shutdown', handle_close, irc_logger)
    reactor.run()
