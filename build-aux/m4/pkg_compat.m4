# pkg.m4 - Macros to locate and use pkg-config.   -*- Autoconf -*-
# serial 12 (pkg-config-0.29.2)

# Copyright © 2004 Scott James Remnant <scott@netsplit.com>.
# Copyright © 2012-2015 Dan Nicholson <dbn.lists@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# As a special exception to the GNU General Public License, if you
# distribute this file as part of a program that contains a
# configuration script generated by Autoconf, you may include it under
# the same distribution terms that you use for the rest of that
# program.

# PKG_PROG_PKG_CONFIG_COMPAT([MIN-VERSION], [ACTION-IF-NOT-FOUND])
# ---------------------------------------------------------
# Backported from pkg-config 0.29.2.
#
# Search for the pkg-config tool and set the PKG_CONFIG variable to
# first found in the path. Checks that the version of pkg-config found
# is at least MIN-VERSION. If MIN-VERSION is not specified, 0.9.0 is
# used since that's the first version where most current features of
# pkg-config existed.
#
# If pkg-config is not found or older than specified, it will result
# in an empty PKG_CONFIG variable. To avoid widespread issues with
# scripts not checking it, ACTION-IF-NOT-FOUND defaults to aborting.
# You can specify [PKG_CONFIG=false] as an action instead, which would
# result in pkg-config tests failing, but no bogus error messages.
AC_DEFUN([PKG_PROG_PKG_CONFIG_COMPAT],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_SYSTEM_(CFLAGS|LIBS)))?$])
m4_pattern_allow([^PKG_CONFIG_(DISABLE_UNINSTALLED|TOP_BUILD_DIR|DEBUG_SPEW)$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])
AC_ARG_VAR([PKG_CONFIG_PATH], [directories to add to pkg-config's search path])
AC_ARG_VAR([PKG_CONFIG_LIBDIR], [path overriding pkg-config's built-in search path])

if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
	_pkg_min_version=m4_default([$1], [0.9.0])
	AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
	if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		PKG_CONFIG=""
	fi
fi
if test -z "$PKG_CONFIG"; then
	m4_default([$2], [AC_MSG_ERROR([pkg-config not found])])
fi[]
])

# PKG_INSTALLDIR_COMPAT([DIRECTORY])
# -------------------------
# Backported from pkg-config 0.27.
#
# Substitutes the variable pkgconfigdir as the location where a module
# should install pkg-config .pc files. By default the directory is
# $libdir/pkgconfig, but the default can be changed by passing
# DIRECTORY. The user can override through the --with-pkgconfigdir
# parameter.
AC_DEFUN([PKG_INSTALLDIR_COMPAT],
[m4_pushdef([pkg_default], [m4_default([$1], ['${libdir}/pkgconfig'])])
m4_pushdef([pkg_description],
    [pkg-config installation directory @<:@]pkg_default[@:>@])
AC_ARG_WITH([pkgconfigdir],
    [AS_HELP_STRING([--with-pkgconfigdir], pkg_description)],,
    [with_pkgconfigdir=]pkg_default)
AC_SUBST([pkgconfigdir], [$with_pkgconfigdir])
m4_popdef([pkg_default])
m4_popdef([pkg_description])
])
