SUBDIRS = doc src
EXTRA_DIST = GPL.txt Stanford.txt
dist_sysconf_DATA = igmpproxy.conf

ChangeLog:
	git --git-dir=$(srcdir)/.git log > $@

AUTHORS: ChangeLog
	( echo "Authors and contributors, in alphabetical order: "; echo; \
	sed -r "s/^Author: (.*)/\1/;t;d" $< | sort -u ) > $@

if HAVE_CLANG_FORMAT

.PHONY: reformat

reformat:
	@echo "Reformatting header files..."
	@CLANG_FORMAT@ -style=file -i `find . -name "*.h"`
	@echo "Reformatting C files..."
	@CLANG_FORMAT@ -style=file -i `find . -name "*.c"`

endif
