===========
varnishmap
===========

---------------------------------------------------------
Calculate varnish node map for shortest path
---------------------------------------------------------

:Author: Weongyo Jeong
:Date:   2011-05-25
:Version: 1.0
:Manual section: 1


SYNOPSIS
========

varnishmap [-a] [-b] [-C] [-c] [-D] [-d] [-f] [-I regex] 
[-i tag] [-n varnish_name] [-P file] [-r file] [-V] 
[-w file] [-X regex] [-x tag]

DESCRIPTION
===========

The varnishmap utility reads varnishd(1) shared memory logs and
calculates them to draw varnish node map.

The following options are available:

-a          When writing to a file, append to it rather than overwrite it.

-b          Include log entries which result from communication with a 
	    backend server.  If neither -b nor -c is
	    specified, varnishmap acts as if they both were.

-C          Ignore case when matching regular expressions.

-c          Include log entries which result from communication 
	    with a client.  If neither -b nor -c is specified, 
	    varnishmap acts as if they both were.

-D          Daemonize.

-d          Process old log entries on startup.  Normally, varnishmap 
	    will only process entries which are written to the log 
	    after it starts.

-f          Prefer the X-Forwarded-For HTTP header over client.ip in 
	    the log output.

-I regex    Include log entries which match the specified regular 
   	    expression.  If neither -I nor -i is specified, 
	    all log entries are included.

-i tag      Include log entries with the specified tag.  If neither -I nor 
   	    -i is specified, all log entries are included.

-n          Specifies the name of the varnishd instance to get logs 
	    from.  If -n is not specified, the host name is used.

-P file     Write the process's PID to the specified file.

-r file     Read log entries from file instead of shared memory.

-V          Display the version number and exit.

-w file     Write log entries to file instead of displaying them.  
   	    The file will be overwritten unless the -a
	    option was specified.
	    
	    If varnishmap receives a SIGHUP while writing to a file, 
	    it will reopen the file, allowing the old one to be 
	    rotated away.

-X regex    Exclude log entries which match the specified 
   	    regular expression.

-x tag      Exclude log entries with the specified tag.

SEE ALSO
========

* varnishd(1)
* varnishhist(1)
* varnishlog(1)
* varnishstat(1)
* varnishtop(1)

HISTORY
=======

The varnishmap utility was developed by Weongyo Jeong.


COPYRIGHT
=========

This document is licensed under the same licence as Varnish
itself. See LICENCE for details.

* Copyright (c) 2006 Verdens Gang AS
* Copyright (c) 2006-2008 Linpro AS
* Copyright (c) 2008-2010 Redpill Linpro AS
* Copyright (c) 2010 Varnish Software AS
* Copyright (c) 2011 Weongyo Jeong
