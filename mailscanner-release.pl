#!/usr/bin/perl
#
# mailscanner-release for MailScanner
# Copyright (C) 2010  Jeroen Koekkoek (jeroen@intuxicated.org)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

#
# Release a message from quarantine automatically detecting if file is
# in queue or rfc 822 format.
#


use strict;
use warnings;
use Data::Dumper;
use Email::MessageID;
use File::Temp qw (tempfile);
use FileHandle;
use Getopt::Long qw (:config no_ignore_case);
use IO::File;
use POSIX;
use Sys::Hostname::Long;

require 5.005;


#
# CONFIGURATION DEFAULTS
#

my $PROGRAM = 'mailscanner-release';
my $VERSION = '1.1';

my $config_file        = '/etc/MailScanner/MailScanner.conf';
my $sender             = '';
my $sendmail           = '';
my $temp_directory     = '';
my $temp_file          = ''; # Set by script to remove temporary file
my $rewrite_message_id = 0; # Very ugly, but necessary for Microsoft Exchange
my $use_syslog         = 0;
my $verbose            = 0;


# MailScanner

use lib qw (/usr/share/MailScanner);
use MailScanner;
use MailScanner::Config;
use MailScanner::Log;
use MailScanner::Message;

# Load Mail Transfer Agent (MTA) specific modules

my $mta = get_prm ('mta');
my $mod_mta;
my $mod_diskstore;

if ($mta =~ m/Exim/io) {
  $mod_mta       = 'Exim.pm';
  $mod_diskstore = 'EximDiskStore.pm';
} elsif ($mta =~ m/ZMailer/io) {
  $mod_mta       = 'ZMailer.pm';
  $mod_diskstore = 'ZMDiskStore.pm';
} elsif ($mta =~ m/Postfix/io) {
  $mod_mta       = 'Postfix.pm';
  $mod_diskstore = 'PFDiskStore.pm';
} elsif ($mta =~ m/qmail/io) {
  $mod_mta       = 'Qmail.pm';
  $mod_diskstore = 'QMDiskStore.pm';
} else {
  $mod_mta       = 'Sendmail.pm';
  $mod_diskstore = 'SMDiskStore.pm';
}

require "MailScanner/$mod_mta";
require "MailScanner/$mod_diskstore";


# main: main subroutine

sub main {

  my %opt = ();

  # parse command line parameters
  GetOptions (\%opt,
              'config_file|c|config-file=s',
              'date=s',
              'force_plain|force-plain',
              'force_queue|force-queue',
              'queue_id|queue-id=s',
              'recipient|r=s@',
              'rewrite_message_id|rewrite-message-id',
              'sender|s=s',
              'syslog',
              'temp_directory|t|temp-directory=s',
              'usage|help|u|h',
              'verbose|v',
              'version|V');

  version () if     ($opt{version});
  usage   () if     ($opt{usage});
  usage   () if     ($opt{force_plain} && $opt{force_queue});
  usage   () unless ($opt{queue_id});
  usage   () unless ($opt{sender});

  my $id = $opt{queue_id};

  $config_file        = $opt{config_file}    if ($opt{config_file});
  $sender             = $opt{sender};
  $temp_directory     = $opt{temp_directory} if ($opt{temp_directory});
  $rewrite_message_id = $opt{rewrite_message_id} ? 1 : 0;
  $use_syslog         = $opt{syslog}             ? 1 : 0;
  $verbose            = $opt{verbose}            ? 1 : 0;


  # initialize logging
  MailScanner::Log::Configure ('', 'stderr');

  if ($use_syslog) {
    my $facility  = get_prm ('syslogfacility');
    my $sock_type = get_prm ('syslogsockettype');

    error ('syslog facility undefined')
      if (! $facility);

    MailScanner::Log::Configure ('', 'syslog');
    MailScanner::Log::Start ($PROGRAM, $facility, $sock_type ? $sock_type : '');

  } elsif (! $verbose) {
    MailScanner::Log::WarningsOnly ();
  }

  info ('releasing message with id %s from quarantine', $id);


  # validate given recipients (optional)
  my @rcpts = ();
  my $nrcpts = 0;

  foreach my $rcpt (@{$opt{recipient}}) {
    next unless ($rcpt);
    $rcpt =~ s/^\s*//o;
    $rcpt =~ s/\s*$//o;
    $rcpt = lc ($rcpt);

    if ($rcpt =~ m/^[\.\+\-\_0-9a-zA-Z]+\@[\.\-0-9a-z]+$/o) {
      push (@rcpts, $rcpt);
      $nrcpts++;
    } else {
      error ('invalid recipient %s', $rcpt);
    }
  }

  if ($nrcpts) {
    notice ('replacing original recipients of message with id %s', $id);
  } else {
    notice ('using original recipients of message with id %s', $id);
  }

  # require root privileges
  error ("must be root")
    if ($>);

  my $sendmail   = get_prm ('sendmail');
  my $quarantine = get_prm ('quarantinedir');
  my $entire     = get_prm ('quarantinewholemessage');
  my $plain      = get_prm ('storeentireasdfqf');


  $entire = ($entire && $entire =~ m/[yY1]/ ? 1 : 0);
  $plain  = ($plain  && $plain  !~ m/[nN0]/ ? 0 : 1);

  if    ($opt{force_plain}) { $plain = 1; }
  elsif ($opt{force_queue}) { $plain = 0; }

  error ('sendmail binary is undefined')
    if (! $sendmail );
  error ('sendmail binary is not executable')
    if (! -x $sendmail );
  error ('quarantine directory is undefined')
    if (! $quarantine);
  error ('quarantine directory %s does not exist', $quarantine)
    if (! -d $quarantine);
  error ('quarantine does not store whole messages')
    if (! $entire);

  my $source;
  my $path = lookup_message ($quarantine, '', $id);

  error ('no quarantined message with id %s', $id)
    if (! $path);


  if ($plain) {
    $source = $path;

  } else {
    # create temporary file to store converted message
    my $fh;

    if ($temp_directory) {
      ($fh, $source) = tempfile (UNLINK => 0, DIR => $temp_directory);
    } else {
      ($fh, $source) = tempfile (UNLINK => 0);
    }

    $temp_file = $source;

    # create dummy instances to convert message
    my $mta;
    my $message;

    $mta = new MailScanner::Sendmail;
    $global::MS = new MailScanner ('WorkArea'   => '',
                                   'InQueue'    => '',
                                   'MTA'        => $mta,
                                   'Quarantine' => '');

    $path =~ m#^(.*)/([^/]+)$#o;
    $message = new MailScanner::Message ($2, $1, 0);

    # convert quarantined message into rfc 822 format
    eval
    {
      $message->{store}->WriteEntireMessage ($message, $fh);
    };

    error ('could not convert quarantined message with id %s', $id)
      if ($@);

    # INFO: here for furture reference
    # MailScanner:1029: $batch = new MailScanner::MessageBatch('normal', $IDToScan);
    # MessageBatch:91:  $global::MS->{mta}->CreateBatch($this, $OnlyID);
    # Postfix.pm:1779:  $newmessage = MailScanner::Message->new($id, $queuedirname, $getipfromheader);
    # Message.pm:235:   if ($global::MS->{mta}->ReadQf($this, $getipfromheader) != 1)
  }


  # NOTE: here for future reference
  # Quarantine.pm:201:  $message->{store}->CopyEntireMessage($message, $msgdir, 'message', $uid, $gid, $changeowner);
  # PFDiskStore.pm:631: $this->WriteEntireMessage($message, $target);
  # Message.pm:220: $this->{store} = new MailScanner::SMDiskStore($id, $queuedirname);


  my @sendmail_prms;
  if (scalar @rcpts) {
    @sendmail_prms = ('-i', '-r', $sender, @rcpts);
  } else {
    # extract recipients from message headers
    @sendmail_prms = ('-t', '-i', '-r', $sender);
  }

  # execute sendmail
  open (SENDMAIL, '|-', $sendmail, @sendmail_prms)
    || error ('open sendmail: %s', $!);
  open (MESSAGE, '<', $source)
    || error ('open %s: %s', $source, $!);
  binmode (MESSAGE)
    || error ('binmode %s: %s', $source, $!);

  if ($rewrite_message_id) {

    my $done = 0;
    my $line;
    while ($line = <MESSAGE>) {

      if (! $done && $line =~ m/(^\s*Message\-ID:\s*)(\S.*\S)(\s*$)/io) {
        $done = 1;

        my $mid = new Email::MessageID (host => hostname_long ());
        if ($mid) {
          print SENDMAIL $1 . $mid . $3;
        } else {
          print SENDMAIL $line;
        }
      } else {
        print SENDMAIL $line;
      }
    }
  } else {
    
    my $line;
    while ($line = <MESSAGE>) {
      print SENDMAIL $line;
    }
  }

  close (MESSAGE)
    || error ('close %s: %s', $source, $!);
  close (SENDMAIL)
    || error ('close sendmail: %s', $!);

  info ('released message with id %s from quarantine', $id);

  return EXIT_SUCCESS;
}

exit main;


# notice: smart MailScanner::Log::InfoLog wrapper

sub notice {
  return unless ($verbose);
  MailScanner::Log::InfoLog (@_);
}


# info: MailScanner::Log::InfoLog wrapper

sub info  {
  MailScanner::Log::InfoLog (@_);
}


# error: MailScanner::Log::DieLog wrapper

sub error {
  MailScanner::Log::DieLog  (@_);
}


# END: remove temporary file if set

END {
  unlink ($temp_file) if ($temp_file && -f $temp_file);
}


# usage: print usage information and exit

sub usage {
  printf STDERR "Usage: %s [OPTIONS] --sender SENDER --queue-id ID\n", $PROGRAM;
  printf STDERR "  -c, --config-file      specify alternate MailScanner.conf location\n";
  printf STDERR "      --date             specify date message was quarantined (YYYYMMDD)\n";
  printf STDERR "      --force-plain      force quarantined message to be treated as RFC822\n";
  printf STDERR "                           message\n";
  printf STDERR "      --force-queue      force quarantined message to be treated as valid queue\n";
  printf STDERR "                           file\n";
  printf STDERR "  -h, --help             show usage information and exit\n";
  printf STDERR "      --queue-id         specify queue identifier of quarantined message\n";
  printf STDERR "  -r, --recipient        specify one or more recipients (discards existing\n";
  printf STDERR "                           recipients)\n";
  printf STDERR "  -s, --sender           specify envelope sender address\n";
  printf STDERR "      --syslog           use syslog instead of stderr for logging\n";
  printf STDERR "  -t, --temp-directory   use directory instead of global temporary directory\n";
  printf STDERR "  -u, --usage            show usage information and exit\n";
  printf STDERR "  -v, --verbose          show extra information during operation\n";
  printf STDERR "  -V, --version          show version information and exit\n";
  exit EXIT_FAILURE;
}


# version: print version information and exit

sub version {
  printf STDERR "%s %s\n", $PROGRAM, $VERSION;
  exit EXIT_FAILURE;
}


# get_uid: get id by user

sub get_uid {

  my $uid;
  my $user = $_[0];
     $user =~ s/^\s*//o;
     $user =~ s/\s*$//o;

  if ($user =~ m/^[0-9]+$/o) {
    $uid = $user + 0;
  } elsif ($user =~ m/^[0-9a-zA-Z]+$/o) {
    $uid = getpwnam ($user);
  }

  return defined ($uid) ? $uid : -1;
}


# get_gid: get id by group

sub get_gid {

  my $gid;
  my $group = $_[0];
     $group =~ s/^\s*//o;
     $group =~ s/\s*$//o;

  if ($group =~ m/^[0-9]+$/o) {
    $gid = $group + 0;
  } elsif ($group =~ m/^[0-9a-zA-Z]+$/o) {
    $gid = getgrnam ($group);
  }

  return defined ($gid) ? $gid : -1;
}


# get_prm: lookup given variable in MailScanner config file

sub get_prm {

  return unless ($_[0]);
  return MailScanner::Config::QuickPeek ($config_file, $_[0]);
}


# lookup_message: traverse base/date directory or all base subdirectories if
#                 date is omitted

sub lookup_message {

  my ($dir, $date, $id) = @_;

  my @paths = ();
  my $npaths;

  # walk only quarantine/date
  if ($date) {
    my $path = walk_dir ("$dir/$date", $id, 1);
    push (@paths, $path) if ($path);

  # walk entire quarantine
  } else {
    my $handle;

    opendir ($handle, $dir)
      || error ("opendir %s: %s", $dir, $!);

    while (my $subdir = readdir ($handle)) {
      next if ($subdir eq '.' || $subdir eq '..');

      if (-d "$dir/$subdir") {
        my $path = walk_dir ("$dir/$subdir", $id, 1);
        push (@paths, $path) if ($path);
      }
    }

    closedir ($handle)
      || error ("closedir %s: %s", $dir, $!);
  }

  $npaths = scalar @paths;

  return if ($npaths < 1);

  if ($npaths > 1) {
    error ("multiple messages with id %s in quarantine", $id)
  }

  if (-f $paths[0]) {
    return $paths[0];
  } elsif (-f $paths[0].'/message') {
    return $paths[0].'/message';
  }

  return;
}


# walk_dir: walk directory given by lookup_message in search of given id

sub walk_dir {

  my ($dir, $id, $spam) = @_;

  my $handle;
  my $path;

  opendir ($handle, $dir)
    || error ("opendir %s: %s", $dir, $!);

  while (my $subdir = readdir ($handle)) {
    next if ($subdir eq '.' || $subdir eq '..');

    # ignore plain files
    if (-e "$dir/$subdir") {

      if ($subdir eq $id) {
        $path = "$dir/$subdir";
        last;

      } elsif ($spam && $subdir eq 'spam') {
        $path = walk_dir ("$dir/$subdir", $id, 0);
        last if ($path);
      }
    }
  }

  closedir ($handle)
    || error ("closedir %s: %s", $dir, $!);

  return $path;
}

