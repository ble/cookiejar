# Copyright 2012 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include ../../../../Make.inc

TARG=net/http/cookiejar
GOFILES=\
	jar.go\
	cookie.go\
	url.go\
	publicsuffixes.go\
	table.go\

include ../../../../Make.pkg

table:
	./maketables.sh