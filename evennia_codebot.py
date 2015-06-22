#! /usr/bin/python
# Copyright (c) 2009 Steven Robertson.
#           (c) 2010-2013 Griatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or
# later, as published by the Free Software Foundation.

"""
Evennia codebot system

This is a central bot for relaying data about the Evennnia
development (www.evennia.com).

- logs #evennia IRC channel to logfile
- echoes RSS feed updates (code, blog, forum, issues) to #evennia
- posts the IRC log regularly to Evennia mailing list

The bot uses threading to avoid lockups when loading very
slow RSS urls (this used to cause it to time out)

"""
__version__ = "0.4"

import time, re
import feedparser
from twisted.words.protocols import irc
from twisted.mail.smtp import sendmail
from email.mime.text import MIMEText
from twisted.internet import reactor, protocol, task, threads
from twisted.python import log

#------------------------------------------------------------
# Print nice log messages
#------------------------------------------------------------

def make_iter(self, obj):
    "Make incoming object iterable"
    return obj if hasattr(obj, '__iter__') else [obj]

def report(text):
    "Pretty-print the activity of the system"
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]", time.localtime(time.time()))
    print "%s: %s" % (timestamp, text)

### IRC message formatting. For reference:
### \002 bold \003 color \017 reset \026 italic/reverse \037 underline
### 0 white 1 black 2 dark blue 3 dark green
### 4 dark red 5 brownish 6 dark purple 7 orange
### 8 yellow 9 light green 10 dark teal 11 light teal
### 12 light blue 13 light purple 14 dark gray 15 light gray

CL = {"bold":"\002", "color":"\003", "reset":"\017", "italic":"\026", "underline":"37",
      "white":"0", "black":"1", "dblue":"3", "dgreen":"4",
      "dred":"4", "brown":"5", "dpurpple":"6", "orange":"7",
      "yellow":"8", "green":"9","dteal":"10", "teal":"11",
      "blue":"12", "purple":"14","dgrey":"15", "gray":15}

def fmt_url(msg):
    return "\00302\037%s\017" % msg

def fmt_repo(msg):
    return "\00313%s\017" % msg



#------------------------------------------------------------
# IRC logger
#------------------------------------------------------------

class IRCLog(object):
    """
    Stores and retrieves an irc log.

    Log is stored as an integer number followed by the log line(s)

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


#------------------------------------------------------------
# IRC bot
#------------------------------------------------------------

class AnnounceBot(irc.IRCClient):
    """
    An IRC bot that tracks actitivity in a channel as well
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
        self.say(self.channel, msg)
        self.logger.write_log(msg)
        return True

    def privmsg(self, user, channel, msg):
        "A message was sent to channel"
        if not msg.startswith('***'):
            user = user.split('!', 1)[0]
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


class AnnounceBotFactory(protocol.ReconnectingClientFactory):
    """
    Creates instances of AnnounceBot, connecting with
    a staggered increase in delay
    """
    # scaling reconnect time
    initialDelay = 1
    factor = 1.5
    maxDelay = 60

    def __init__(self, nickname, logger, channel, manager):
        "Storing some important protocol properties"
        self.nickname = nickname
        self.logger = logger
        self.channel = channel
        self.manager = manager
        self.bot = None

    def buildProtocol(self, addr):
        "Build the protocol and assign it some properties"
        protocol = AnnounceBot()
        protocol.factory = self
        protocol.nickname = self.nickname
        protocol.logger = self.logger
        protocol.channel = self.channel
        protocol.manager = self.manager
        return protocol

    def startedConnecting(self, connector):
        "Tracks reconnections for debugging"
        report("%s (re)connecting to %s" % (self.nickname, self.channel))


class RelayBot(irc.IRCClient):
    """
    Sits in an external channel and echoes the text of
    a single user to another channel.
    """
    lineRate = 1

    # assigned by factory at creation
    nickname = None
    factory = None
    channel = None

    echousers = [] # which users should be echoed
    manager = None # through which manager to echo

    def signedOn(self):
        """
        Connected. We make sure to store ourself on factory here
        (this version only allows one bot instance, otherwise
         the factory would hold a list of bots)
        """
        self.join(self.channel)
        self.factory.bot = self

    def privmsg(self, user, channel, msg):
        "A message was sent to the channel. Relay to manager."
        user = user.split('!', 1)[0]
        if user in self.echousers and not msg.startswith('***'):
            self.manager.relay(msg)

    def connectionMade(self):
        "Called when client connects"
        irc.IRCClient.connectionMade(self)
        report("%s connected to %s" % (self.nickname, self.channel))

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        report("%s disconnected from %s" % (self.nickname, self.channel))


class RelayBotFactory(protocol.ReconnectingClientFactory):
    """
    Creates instances of AnnounceBot, connecting with
    a staggered increase in delay
    """
    # scaling reconnect time
    initialDelay = 1
    factor = 1.5
    maxDelay = 60

    def __init__(self, nickname, channel, echousers, manager):
        "Storing some important protocol properties"
        self.nickname = nickname
        self.channel = channel
        self.echousers = make_iter(echousers)
        self.manager = manager
        self.bot = None

    def buildProtocol(self, addr):
        "Build the protocol and assign it some properties"
        protocol = RelayBot()
        protocol.factory = self
        protocol.nickname = self.nickname
        protocol.channel = self.channel
        protocol.manager = self.manager
        protocol.echouser = self.echouser
        return protocol

    def startedConnecting(self, connector):
        "Tracks reconnections for debugging"
        report("%s (re)connecting to %s" % (self.nickname, self.channel))


class IRCRelayManager(object):
    """
    This manager handles two connected bots, one of which
    is an AnnounceBot and the other a RelayBot.
    """
    def __init__(self):
        self.announce_factory = None
        self.announce_irc_network = None
        self.announce_irc_port = None
        self.relay_factory = None
        self.relay_irc_network = None
        self.relay_irc_port = None

    def add_announcebot(self, nickname, logger, channel,
                        irc_network, irc_port):
        "Add factory, making sure to store ourselves"
        self.announce_factory = AnnounceBotFactory(nickname, logger, channel, self)
        self.announce_irc_network = irc_network
        self.announce_irc_port = irc_port

    def add_relaybot(self, nickname, channel, echouser, irc_network, irc_port):
        "Add factory, making sure to store ourselves"
        self.relay_factory = RelayBotFactory(nickname, channel, echouser, self)
        self.relay_irc_network = irc_network
        self.relay_irc_port = irc_port

    def relay(self, msg):
        "This is called by relay bot when a suitable message is to be echoed by the announce bot"
        self.announce_factory.bot.trysay(msg)

    def start(self):
        "Start the manager relay"
        reactor.connectTCP(self.relay_irc_network, self.relay_irc_port, self.relay_factory)
        reactor.connectTCP(self.announce_irc_network, self.announce_irc_port, self.announce_factory)




#------------------------------------------------------------
# IRC feed reader
#------------------------------------------------------------

class FeedReader(object):
    """
    A simple RSS reader using universal feedparser
    """
    def __init__(self, url):
        self.url = url
        self.old_entries = {}
        # we have to do this at startup to not
        # include all entries in the feed back to
        # its beginning
        report("initial fetch of feed %s ..." % self.url)
        self.get_new()

    def get_new(self):
        """Returns list of new items."""
        #report("fetching feed from %s ..." % self.url)
        feed = feedparser.parse(self.url)
        new_entries = []
        for entry in feed['entries']:
            idval = entry['id'] + entry.get("updated", "")
            if idval not in self.old_entries:
                self.old_entries[idval] = entry
                new_entries.append(entry)
        #report("... found %i new entries." % len(new_entries))
        return new_entries



#------------------------------------------------------------
# Callback functions
#------------------------------------------------------------

def report_blog_RSS_updates(feed, botfactory):
    """
    Check if An RSS feed has been updated and if so, use the
    AnnounceBot to report it to its IRC channel. We run this in a
    separate thread to avoid locking up the bot (and potentially
    timing out) for very slowly responding RSS urls.
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
            msg = "[%s] %s pushed to page '%s' %s" % (fmt_repo("evennia.wiki"),
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
    This is for the github wiki RSS feed which is too verbose. It cuts away more from
    the message but otherwise works the same.
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


def announce_err(fail, typ):
    "errback"
    report("%s error: %s" % (typ, fail.value))


def handle_close(irc_logger):
    "callback for handling closing condition"
    irc_logger.close_logfile()
    report("Shutting down system and closing log (waiting for threads to finish)")


if __name__ == '__main__':

    # All per-project customizations should be done here

    # settings for announce IRC bot
    announce_bot_nickname = "evenniacode"
    announce_irc_network = "irc.freenode.net"
    announce_irc_port = 6667
    announce_irc_channel = "#evennia"

    # settings for relay IRC bot
    relay_bot_nickname = "evenniarelay"
    relay_echousers = ("evennia-github", "ainneve-github")
    relay_irc_network = "irc.freenode.net"
    relay_irc_port = 6667
    relay_irc_channel = "#evennia-commits"

    # RSS feeds
    rss_check_frequency = 10 * 60 # 10 minutes
    wikifeed = "https://github.com/evennia/evennia/wiki.atom"
    forumfeed = "https://groups.google.com/forum/feed/evennia/msgs/rss_v2_0.xml?num=20"
    blogfeed = "https://evennia.blogspot.com/feeds/posts/default?num=20"

    # settings for email publishing
    log_publish_frequency = 60 * 60 * 24 * 7 # every week
    logfile = "logfile.txt"
    smtp_server = "localhost"
    from_email = "evennia-irc-logs@evennia.com"
    to_email = "evennia-commits@googlegroups.com"

    #------------------------------------------------------------

    # Start logger
    irc_logger = IRCLog(logfile)

    # Setting up feeds
    report("starting announce bot %s for %s:%s/%s - initalizing all feeds ..." % (announce_bot_nickname, announce_irc_network,
                                                                                  announce_irc_port, announce_irc_channel))
    report("starting relay bot %s (echoing %s) for %s:%s/%s - initalizing all feeds ..." % (relay_bot_nickname, relay_echousers,
                                                                                            relay_irc_network, relay_irc_port, relay_irc_channel))
    wikifeed = FeedReader(wikifeed)
    forumfeed = FeedReader(forumfeed)
    blogfeed = FeedReader(blogfeed)
    report("... all feeds initialized, starting system")

    # Starting IRC bots
    ircbots = IRCRelayManager()
    ircbots.add_announcebot(announce_bot_nickname, irc_logger, announce_irc_channel,
                            announce_irc_network, announce_irc_port)
    ircbots.add_relaybot(relay_bot_nickname, relay_irc_channel, relay_echousers,
                         relay_irc_network, relay_irc_port)
    ircbots.start()

    # Start tasks and set errbacks on them

    wikifeed_task = task.LoopingCall(report_wiki_RSS_updates, wikifeed, ircbots.announce_factory)
    wikifeed_task.start(rss_check_frequency, now=False).addErrback(announce_err, "rss 'wiki' feed")

    forumfeed_task = task.LoopingCall(report_forum_RSS_updates, forumfeed, ircbots.announce_factory)
    forumfeed_task.start(rss_check_frequency, now=False).addErrback(announce_err, "rss 'forum' feed")

    blogfeed_task = task.LoopingCall(report_blog_RSS_updates, blogfeed, ircbots.announce_factory)
    blogfeed_task.start(rss_check_frequency, now=False).addErrback(announce_err, "rss 'blog' feed")

    #publish_task = task.LoopingCall(mail_IRC_log, irc_logger, irc_channel, smtp_server, from_email, to_email)
    #publish_task.start(log_publish_frequency, now=False).addErrback(announce_err, "irc log publishing")

    reactor.addSystemEventTrigger('before', 'shutdown', handle_close, irc_logger)
    reactor.run()
