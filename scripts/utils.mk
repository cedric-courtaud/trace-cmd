# SPDX-License-Identifier: GPL-2.0

# Utils

ifeq ($(BUILDGUI), 1)
  GUI		= 'GUI '
  GSPACE	=
else
  GUI		=
  GSPACE	= "    "
endif

 GOBJ		= $(GSPACE)$(notdir $(strip $@))


ifeq ($(VERBOSE),1)
  Q =
  S =
else
  Q = @
  S = -s
endif

# Use empty print_* macros if either SILENT or VERBOSE.
ifeq ($(findstring 1,$(SILENT)$(VERBOSE)),1)
  print_compile =
  print_app_build =
  print_fpic_compile =
  print_shared_lib_compile =
  print_plugin_obj_compile =
  print_plugin_build =
  print_install =
  print_uninstall =
  print_update =
  print_asciidoc =
  print_xsltproc =
  print_install =
  hide_xsltproc_output =
else
  print_compile =		echo '  $(GUI)COMPILE            '$(GOBJ);
  print_app_build =		echo '  $(GUI)BUILD              '$(GOBJ);
  print_fpic_compile =		echo '  $(GUI)COMPILE FPIC       '$(GOBJ);
  print_shared_lib_compile =	echo '  $(GUI)COMPILE SHARED LIB '$(GOBJ);
  print_plugin_obj_compile =	echo '  $(GUI)COMPILE PLUGIN OBJ '$(GOBJ);
  print_plugin_build =		echo '  $(GUI)BUILD PLUGIN       '$(GOBJ);
  print_static_lib_build =	echo '  $(GUI)BUILD STATIC LIB   '$(GOBJ);
  print_install =		echo '  $(GUI)INSTALL     '$(GSPACE)$1'	to	$(DESTDIR_SQ)$2';
  print_update =		echo '  $(GUI)UPDATE             '$(GOBJ);
  print_uninstall =		echo '  $(GUI)UNINSTALLING $(DESTDIR_SQ)$1';
  print_asciidoc =		echo '  ASCIIDOC            '`basename $@`;
  print_xsltproc =		echo '  XSLTPROC            '`basename $@`;
  print_install =		echo '  INSTALL             '`basename $1`'	to	$(DESTDIR_SQ)'$2;
  hide_xsltproc_output = 2> /dev/null
endif

do_fpic_compile =					\
	($(print_fpic_compile)				\
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(EXT) -fPIC $< -o $@)

do_compile =							\
	($(if $(GENERATE_PIC), $(do_fpic_compile),		\
	 $(print_compile)					\
	 $(CC) -c $(CPPFLAGS) $(CFLAGS) $(EXT) $< -o $@))

do_app_build =						\
	($(print_app_build)				\
	$(CC) $^ -rdynamic -Wl,-rpath=$(libdir) -o $@ $(LDFLAGS) $(CONFIG_LIBS) $(LIBS))

do_build_static_lib =				\
	($(print_static_lib_build)		\
	$(RM) $@;  $(AR) rcs $@ $^)

do_compile_shared_library =			\
	($(print_shared_lib_compile)		\
	$(CC) --shared $^ '-Wl,-soname,$(@F),-rpath=$$ORIGIN' -o $@ $(LIBS))

do_compile_plugin_obj =				\
	($(print_plugin_obj_compile)		\
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -fPIC -o $@ $<)

do_plugin_build =				\
	($(print_plugin_build)			\
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -nostartfiles -o $@ $<)

do_compile_python_plugin_obj =			\
	($(print_plugin_obj_compile)		\
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(PYTHON_DIR_SQ) $(PYTHON_INCLUDES) -fPIC -o $@ $<)

do_python_plugin_build =			\
	($(print_plugin_build)			\
	$(CC) $< -shared $(LDFLAGS) $(PYTHON_LDFLAGS) -o $@)

define make_version.h
	(echo '/* This file is automatically generated. Do not modify. */';		\
	echo \#define VERSION_CODE $(shell						\
	expr $(VERSION) \* 256 + $(PATCHLEVEL));					\
	echo '#define EXTRAVERSION ' $(EXTRAVERSION);					\
	echo '#define VERSION_STRING "'$(VERSION).$(PATCHLEVEL).$(EXTRAVERSION)'"';	\
	echo '#define FILE_VERSION '$(FILE_VERSION);					\
	if [ -d $(src)/.git ]; then							\
	  d=`git diff`;									\
	  x="";										\
	  if [ ! -z "$$d" ]; then x="+"; fi;						\
	  echo '#define VERSION_GIT "'$(shell 						\
		git log -1 --pretty=format:"%H" 2>/dev/null)$$x'"';			\
	else										\
	  echo '#define VERSION_GIT "not-a-git-repo"';					\
	fi										\
	) > $1
endef

define update_version.h
	($(call make_version.h, $@.tmp);				\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then				\
		rm -f $@.tmp;						\
	else								\
		$(print_update)						\
		mv -f $@.tmp $@;					\
	fi);
endef

define update_dir
	(echo $1 > $@.tmp;	\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then				\
		rm -f $@.tmp;						\
	else								\
		$(print_update)						\
		mv -f $@.tmp $@;					\
	fi);
endef

define build_prefix
	(echo $1 > $@.tmp;	\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then				\
		rm -f $@.tmp;						\
	else								\
		$(print_update)						\
		mv -f $@.tmp $@;					\
	fi);
endef

define do_install
	$(print_install)				\
	if [ ! -d '$(DESTDIR_SQ)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$2';	\
	fi;						\
	$(INSTALL) $(if $3,-m $3,) $1 '$(DESTDIR_SQ)$2'
endef

define do_install_data
	$(print_install)				\
	if [ ! -d '$(DESTDIR_SQ)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$2';	\
	fi;						\
	$(INSTALL) -m 644 $1 '$(DESTDIR_SQ)$2'
endef

define do_install_pkgconfig_file
	if [ -n "${pkgconfig_dir}" ]; then 					\
		$(call do_install,$(PKG_CONFIG_FILE),$(pkgconfig_dir),644); 	\
	else 									\
		(echo Failed to locate pkg-config directory) 1>&2;		\
	fi
endef

define do_make_pkgconfig_file
	$(print_app_build)
	$(Q)cp -f $(srctree)/${PKG_CONFIG_SOURCE_FILE}.template ${PKG_CONFIG_FILE};	\
	sed -i "s|INSTALL_PREFIX|${1}|g" ${PKG_CONFIG_FILE}; 		\
	sed -i "s|LIB_VERSION|${LIBTRACECMD_VERSION}|g" ${PKG_CONFIG_FILE}; \
	sed -i "s|LIB_DIR|$(libdir)|g" ${PKG_CONFIG_FILE}; \
	sed -i "s|LIBTRACEFS_MIN_VERSION|$(LIBTRACEFS_MIN_VERSION)|g" ${PKG_CONFIG_FILE}; \
	sed -i "s|HEADER_DIR|$(includedir)/trace-cmd|g" ${PKG_CONFIG_FILE};
endef

do_asciidoc_build =				\
	($(print_asciidoc)			\
	 asciidoc -d manpage -b docbook -o $@ $<)

do_xsltproc_build =				\
	($(print_xsltproc)			\
	 xsltproc --nonet -o $@ ${MANPAGE_DOCBOOK_XSL} $< $(hide_xsltproc_output))

#
# asciidoc requires a synopsis, but file format man pages (5) do
# not require them. This removes it from the file in the final step.
define remove_synopsis
	(sed -e '/^\.SH "SYNOPSIS"/,/ignore/d' $1 > $1.tmp;\
	 mv $1.tmp $1)
endef

define do_install_docs
	$(print_install)				\
	if [ ! -d '$(DESTDIR_SQ)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$2';	\
	fi;						\
	$(INSTALL) -m 644 $1 '$(DESTDIR_SQ)$2'
endef

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifneq ($(V),1)
	QUIET_ASCIIDOC	= @echo '  ASCIIDOC  '$@;
	QUIET_XMLTO	= @echo '  XMLTO    '$@;
	QUIET_SUBDIR0	= +@subdir=
	QUIET_SUBDIR1	= ;$(NO_SUBDIR) \
			   echo '  SUBDIR   ' $$subdir; \
			  $(MAKE) $(PRINT_DIR) -C $$subdir
	export V
endif
endif
