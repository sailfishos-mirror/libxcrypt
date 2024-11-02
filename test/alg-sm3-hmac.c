/* Copyright (C) 2018 Björn Esser besser82@fedoraproject.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "crypt-port.h"

/* #if INCLUDE_sm3_yescrypt */
#if INCLUDE_sm3crypt

#include "alg-sm3-hmac.h"

#include <stdio.h>

struct testcase
{
  const char *subject;
  const char *k;
  size_t ksize;
  const char *t;
  size_t tlen;
  const char *match;
};

/* Test vectors as published in GM/T 0042-2015 Appendix D.3 */
static const struct testcase testcases[] =
{
  {
    "First",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcde"
    "cdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",                  112,
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20",   32,
    "\xca\x05\xe1\x44\xed\x05\xd1\x85\x78\x40\xd1\xf3\x18\xa4\xa8\x66"
    "\x9e\x55\x9f\xc8\x39\x1f\x41\x44\x85\xbf\xdf\x7b\xb4\x08\x96\x3a"
  },
  {
    "Second",
    "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
    "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
    "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
    "\xcd\xcd",                                                           50,
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    "\x21\x22\x23\x24\x25",                                               37,
    "\x22\x0b\xf5\x79\xde\xd5\x55\x39\x3f\x01\x59\xf6\x6c\x99\x87\x78"
    "\x22\xa3\xec\xf6\x10\xd1\x55\x21\x54\xb4\x1d\x44\xb9\x4d\xb3\xae"
  },
  {
    "Third",
    "Hi There",                                                            8,
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",   32,
    "\xc0\xba\x18\xc6\x8b\x90\xc8\x8b\xc0\x7d\xe7\x94\xbf\xc7\xd2\xc8"
    "\xd1\x9e\xc3\x1e\xd8\x77\x3b\xc2\xb3\x90\xc9\x60\x4e\x0b\xe1\x1e"
  },
  {
    "Fourth",
    "what do ya want for nothing?",                                       28,
    "Jefe",                                                                4,
    "\x2e\x87\xf1\xd1\x68\x62\xe6\xd9\x64\xb5\x0a\x52\x00\xbf\x2b\x10"
    "\xb7\x64\xfa\xa9\x68\x0a\x29\x6a\x24\x05\xf2\x4b\xec\x39\xf8\x82"
  },
};

static void
dumphex(const void *ptr, size_t size)
{
  size_t i;

  for (i = 0; i < size; i++)
    printf("%02x", ((const unsigned char *)ptr)[i]);
  printf("\n");
}

static int
test_sm3_hmac(const struct testcase *tc)
{
  uint8_t digest[SM3_HMAC_MAC_SIZE];
  const char *omsg = "test vector for HMAC-SM3 from "
                     "GM/T 0042-2015 Appendix D.3";

  sm3_hmac_buf((const uint8_t *)tc->k, tc->ksize,
               (const uint8_t *)tc->t, tc->tlen, digest);

  if (memcmp(digest, tc->match, SM3_HMAC_MAC_SIZE))
    {
      fprintf(stderr, "ERROR: %s %s\n", tc->subject, omsg);
      printf("   key: ");
      dumphex(tc->k, tc->ksize);
      printf("   t:   ");
      dumphex(tc->t, tc->tlen);
      printf("   hmac=");
      dumphex(digest, SM3_HMAC_MAC_SIZE);
      printf(" expect=");
      dumphex(tc->match, SM3_HMAC_MAC_SIZE);
      return 1;
    }
  else
    fprintf(stderr, "   ok: %s %s\n", tc->subject, omsg);

  return 0;
}

int
main (void)
{
  int result = 0;

  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
    result |= test_sm3_hmac(&testcases[i]);

  return result;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_sm3_yescrypt */