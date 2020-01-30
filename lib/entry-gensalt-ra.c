/* High-level libcrypt interfaces.

   Copyright 2007-2020 Thorsten Kukuk, Zack Weinberg, Björn Esser

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include "crypt-port.h"
#include "crypt-symver.h"

#if INCLUDE_crypt_gensalt_ra

#include "crypt.h"
#include "crypt-internal.h"

#include <stdlib.h>

char *
crypt_gensalt_ra (const char *prefix, unsigned long count,
                  const char *rbytes, int nrbytes)
{
  char *output = malloc (CRYPT_GENSALT_OUTPUT_SIZE);
  if (!output)
    return 0;

  char *result = crypt_gensalt_internal
    (prefix, count, rbytes, nrbytes, output, CRYPT_GENSALT_OUTPUT_SIZE);
  if (result == 0)
    free (output);
  return result;
}
SYMVER_crypt_gensalt_ra;
#endif