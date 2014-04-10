heartleech
==========

Demonstrates the "heartbleed" problem using full OpenSSL stack, and how simple
pattern-matching isn't sufficient to detect this attack. It evades the pattern
matching in IDS (Snort and EmergingThreat rules), it doesn't send the pattern
in packets that everyone is looking for, and it doesn't generate logfile error
messages.


*Description*


A lot of people are confused by the widely circulated test scripts that send the
following pattern in a packet:

  `18 03 02 00 03 01 40 00`
  
This is the basis for Snort/EmergingThreats signatures. It's the basis for wild
speculation that nefarious actors were exploiting this vulnerability before
it was disclosed on the Monday. An example is this article from EFF:
  
  https://www.eff.org/deeplinks/2014/04/wild-heart-were-intelligence-agencies-using-heartbleed-november-2013
  
Likewise, a lot of people are confused by error messages in their server logs
about SSL sessions being aborted during handshake. This is an artifact of lots
of tools. For example, my `masscan` port scanner causes that during a normal
SSL banner check.


Had anybody been exploiting the bug early, before Monday's public announcement,
it's unlikely they would have been doing things this way. A far easier way is the
method demonstrated in this program, which doesn't generate the above pattern
or log file entries.

The technique is to grab the OpenSSL library and do a custom build. Go into the
file `t1_lib.c` and change line# 2671 like the following:

  `- 	s2n(payload, p);`
  
  `+  s2n(0x4444, p);`

In this example, `0x4444` is the number I've chosen arbitrarily as the number
of bytes I want to get back, which is about 16kilobytes.

Once you've made that change to the OpenSSL build, then link the attached C
program. All this program does is establish a normal session, then send a heartbeat,
then dump the hex of the heartbeat message.

The thing with this program is that it does the heartbeat AFTER the handshake has
completed, so it won't produce those log messages. Also, while the fact this is 
a hearbeat is still exposed view SSL's "record" header, the contents are encrypted,
giving fewer bytes for an IDS to trigger on.

If you look at the bytes sent, you'll now see something like the following on the
request, where the bytes afterwards are encrypted and therefore meaningless:

  `18 03 03 00 3d`
  
On the response side, you'll see something like the following:

  `18 03 03 44 5C`
  
The problem here is that there aren't really enough bytes here for an IDS to pattern-match
on. The final two bytes are "length" field and can be arbitrarly chosen by a hacker, especially
if they want to evade an IDS. That leaves only the first three bytes being meaningful,
and they'll false positive in about one in 4-million SSL packets -- which on a busy network
would be quite often.

The only way to properly detect this for an IDS is to do a stateful protocol-analysis instead
of a pattern-match. A demonstration of this is in `masscan` which does a full SSL decode in
order to detect this issue (albeit with a truncated SSL stack). The `masscan` state-machine
decoders can easily be copied into an IDS.

As for conspiracy theories about early exploitation, this is the sort of program I would have
written, and I assume it's the sort of program that any competent organization (e.g. the NSA)
would have writtent to exploit this bug. Therefore, if you are seeing things that look like
current patterns that happened months ago, I'm betting it's false positives and not real
exploitation.


