/*
   Copyright (c) 2005  Morettoni Luca <luca@morettoni.net>
   All rights reserved.
   
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   
   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.

   $Id: tinystats.c,v 1.3 2005/08/17 15:06:29 luca Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#define ERR 111
#define MAX_PATH 1024
#define BUF_SIZE 1024
#define START "starting tinydns"
#define START_LEN (strlen(START))

#ifdef WITH_IPV6
#define DELTA 24
#else
#define DELTA 0
#endif

#define PARSE_PORT    9+DELTA
#define PARSE_ID      14+DELTA
#define PARSE_RR      21+DELTA
#define PARSE_RES     19+DELTA
#define PARSE_DOMAIN  26+DELTA

#define LOBYTE(x) (x & 0xff)
#define HIBYTE(x) ((x >> 8) & 0xff)

char *slave_prg = NULL;
char *dir = NULL;
char human = 0;
pid_t child_pid = 0;

unsigned long total, other, na, ni, bc, nq;
unsigned long a, ns, cname, soa, ptr, hinfo, mx, txt, rp, sig, key, aaaa, axfr, any;

void parse_ip (char *buf, char *out)
{
  int j;
  char res[5];

#ifdef WITH_IPV6
  long oct[8];

  for (j = 0; j < 8; j++) {
    bzero (res, sizeof res);
    memcpy (res, buf+j*4, 4);
    oct[j] = strtol (res, NULL, 16);
  }

  if (!oct[0] && !oct[1] && !oct[2] && !oct[3] && !oct[4] && oct[5] == 0xffff)
    snprintf (out, 16, "%d.%d.%d.%d", 
      (int) HIBYTE(oct[6]), (int) LOBYTE(oct[6]), (int) HIBYTE(oct[7]), (int) LOBYTE(oct[7]));
  else
    snprintf (out, 40, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", 
      (int) oct[0], (int) oct[1], (int) oct[2], (int) oct[3],
      (int) oct[4], (int) oct[5], (int) oct[6], (int) oct[7]);
#else
  long oct[4];

  for (j = 0; j < 4; j++) {
    bzero (res, sizeof res);
    memcpy (res, buf+j*2, 2);
    oct[j] = strtol (res, NULL, 16);
  }
  snprintf (out, 16, "%d.%d.%d.%d", 
    (int) oct[0], (int) oct[1], (int) oct[2], (int) oct[3]);
#endif
}

void do_slave (char *line)
{
  char ip[16];
  pid_t ext_pid;
  char *arg[4];

  parse_ip (line, ip);

  arg[0] = slave_prg;
  arg[1] = ip;
  arg[2] = line+PARSE_DOMAIN;
  arg[3] = NULL;

  switch ((ext_pid = fork ())) {
    case -1:
      /* error */
      exit (ERR);
      break;
    case 0:
      execvp (slave_prg, arg);
      fprintf (stderr, "tinystats: unable to run %s\n", slave_prg);
      exit (ERR);
 
      break;
  }
}

void reset (void)
{
  a = ns = cname = soa = ptr = hinfo = mx = txt = rp = sig = key = aaaa = axfr = any = 0UL;
  total = other = na = ni = bc = nq = 0UL;
}

int load ()
{
  char in[MAX_PATH];
  FILE *i;

  snprintf (in, MAX_PATH, "%s/tinystats.out", dir);
  i = fopen (in, "r");

  reset ();
  if (!i) 
    return 1;

  fscanf (i, "%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu",
      &a, &ns, &cname, &soa, &ptr, &hinfo, &mx, &txt, &rp, &sig, &key, &aaaa, &axfr, &any, 
      &total, &other, &na, &ni, &bc, &nq);

  fclose (i);
  return 0;
}

int store ()
{
  char out[MAX_PATH];
  FILE *o;

  snprintf (out, MAX_PATH, "%s/tinystats.out", dir);
  o = fopen (out, "w");

  if (!o) 
    return 1;

  fprintf (o, "%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu:%lu\n", 
      a, ns, cname, soa, ptr, hinfo, mx, txt, rp, sig, key, aaaa, axfr, any, 
      total, other, na, ni, bc, nq);
  fprintf (o, "a:ns:cname:soa:ptr:hinfo:mx:txt:rp:sig:key:aaaa:axfr:any:total:other:notauth:notimpl:badclass:noquery\n");

  fclose (o);
  return 0;
}

char *get_rr (char *type)
{
  switch (strtol (type, NULL, 16)) {
    case 1: return "A"; break;
    case 2: return "NS"; break;
    case 5: return "CNAME"; break;
    case 6: return "SOA"; break;
    case 12: return "PTR"; break;
    case 13: return "HINFO"; break;
    case 15: return "MX"; break;
    case 16: return "TXT"; break;
    case 17: return "RP"; break;
    case 24: return "SIG"; break;
    case 25: return "KEY"; break;
    case 28: return "AAAA"; break;
    case 252: return "AXFR"; break;
    case 255: return "ANY"; break;
    default: return type; break;
  }
}

void parse (void)
{
  char buff[BUF_SIZE];
  char buff_pretty[BUF_SIZE];
  char line[BUF_SIZE];
  int lpos = 0;
  int i, n;
  char res[5];
  long RR;
  long port;
  long id;
#ifdef WITH_IPV6
  char ip[40];
#else
  char ip[16];
#endif

  bzero (line, sizeof line);

  while ((n = read (0, buff, sizeof (buff))) > 0) {
    for (i = 0; i < n && buff[i]; i++) {
      if (buff[i] != '\n')
        line[lpos++] = buff[i];
      else {
        if (human && lpos > START_LEN) {
          parse_ip (line, ip);

          bzero (res, sizeof res);
          memcpy (res, line+PARSE_PORT, 4);
          port = strtol (res, NULL, 16);

          bzero (res, sizeof res);
          memcpy (res, line+PARSE_ID, 4);
          id = strtol (res, NULL, 16);

          bzero (res, sizeof res);
          memcpy (res, line+PARSE_RR, 4);

#ifdef WITH_IPV6
          snprintf (buff_pretty, BUF_SIZE, "%-39s %05d [%05d] %c %-4s ",
              ip, (int) port, (int) id, line[PARSE_RES], get_rr (res));
#else
          snprintf (buff_pretty, BUF_SIZE, "%-15s %05d [%05d] %c %-4s ",
              ip, (int) port, (int) id, line[PARSE_RES], get_rr (res));
#endif
          write (1, buff_pretty, strlen (buff_pretty));
          write (1, line+PARSE_DOMAIN, lpos-PARSE_DOMAIN);
        } else
          write (1, line, lpos);
        write (1, "\n", 1);

        /* line parsing */
        if (strncmp (line, START, START_LEN) == 0) reset ();

        if (lpos > START_LEN) {
          total++;
          switch (line[PARSE_RES]) {
            case '-': na++; break;
            case 'C': bc++; break;
            case '/': nq++; break;
            case 'I': 
              ni++; 
              if (slave_prg && strncmp (line+PARSE_RR, "0006", 4) == 0)
                do_slave (line);
              break;
          }

          if (line[PARSE_RES] == '+') {
            bzero (res, sizeof res);
            memcpy (res, line+PARSE_RR, 4);
            RR = strtol (res, NULL, 16);
            switch (RR) {
              case 1: a++; break;
              case 2: ns++; break;
              case 5: cname++; break;
              case 6: soa++; break;
              case 12: ptr++; break;
              case 13: hinfo++; break;
              case 15: mx++; break;
              case 16: txt++; break;
              case 17: rp++; break;
              case 24: sig++; break;
              case 25: key++; break;
              case 28: aaaa++; break;
              case 252: axfr++; break;
              case 255: any++; break;
              default: other++; break;
            }
          }
        }

        /* store results */
        store ();
        
        bzero (line, sizeof line);
        lpos = 0;
      }
    }
  }
}

void usage (void)
{
  fprintf (stderr, "usage: tinystats [-h] [-s program] dir program [ arg ... ]\n\n");
  fprintf (stderr, "options:\n");
  fprintf (stderr, " -h          enable ``human-readable'' output\n");
  fprintf (stderr, " -s program  run ``program IP ZONE'' when tinystats see I and SOA into logs;\n");
  fprintf (stderr, "             usually this mean that tinydns receive a slave update notify\n");
#ifdef WITH_IPV6
  fprintf (stderr, "\nIPv6 log format enabled!\n");
#endif

  exit (ERR);
}

void sig_alrm (int s)
{
  reset (); store ();
  if (child_pid) kill (child_pid, SIGALRM);
}

void sig_term (int s)
{
  store ();
  if (child_pid) kill (child_pid, SIGTERM);
  exit (0);
}

void sig_hup (int s)
{
  reset (); store ();
}

int main (int argc, char* argv[])
{
  int to_chil[2];

  while (argc > 1 && argv[1][0] == '-') {
    switch (argv[1][1]) {
      case 'h':
        human = 1;
        argc--; argv++;
        break;
      case 's':
        slave_prg = argv[2];
        argc -= 2; argv += 2;
        break;
      default:
        usage ();
    }
  }

  if (argc < 3) usage ();

  dir = argv[1];

  pipe (to_chil);

  switch ((child_pid = fork ())) {
    case -1:
      /* error */
      exit (ERR);
      break;
    case 0:
      close (0); dup (to_chil[0]);
  
      close (to_chil[0]);
      close (to_chil[1]);

      execvp (argv[2], argv + 2);
      fprintf (stderr, "tinystats: unable to run %s\n", argv[2]);
      exit (ERR);
 
      break;
  }

  load ();

  signal (SIGTERM, sig_term);
  signal (SIGALRM, sig_alrm);
  signal (SIGHUP, sig_hup);

  close (1); dup (to_chil[1]);
      
  close (to_chil[1]);
  close (to_chil[0]);

  parse ();

  exit (0);
}
