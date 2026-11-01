/* tg_pipe.h - the Telegram app's byte pipe to a PC relay (relay/tg_relay.py), shared memory in the
 * app heap. The f286dbg agent's memory read/write is the wire, so no agent change and no reflash:
 * the PC finds the block through the crumb file D:\F286_76_<address>.TXT, polls the header, moves
 * TCP bytes between the rings and a real socket, and writes the time and entropy. The agent runs in
 * the same MMI task as the app, so there is no concurrency: every field is either the phone's or the
 * PC's to write. Ring positions are free-running counters; the size of each ring is a power of 2.
 * The PC sees only MTProto ciphertext; it does supply entropy and time (see tg.c).
 * Layout is fixed (the relay parses it): keep fields 4-byte aligned and append only. */
#ifndef TG_PIPE_H
#define TG_PIPE_H

#include <stdint.h>

#define TG_PIPE_MAGIC   0x31504754u     /* "TGP1" */
#define TG_PIPE_UP      8192u           /* phone -> PC */
#define TG_PIPE_DN      32768u          /* PC -> phone */

enum { TG_PIPE_REQ_NONE, TG_PIPE_REQ_CONNECT, TG_PIPE_REQ_CLOSE };

typedef struct {
    uint32_t magic, size;               /* +0x00 */
    uint32_t up_cap, dn_cap;            /* +0x08 */
    uint32_t up_wr;                     /* +0x10 phone writes */
    uint32_t up_rd;                     /* +0x14 PC writes */
    uint32_t dn_wr;                     /* +0x18 PC writes */
    uint32_t dn_rd;                     /* +0x1c phone writes */
    uint32_t req, req_seq;              /* +0x20 phone: request (TG_PIPE_REQ_*), bumped seq per request */
    uint32_t ip, port;                  /* +0x28 phone: connect target (IPv4 host order) */
    uint32_t ack_seq;                   /* +0x30 PC: last req_seq handled */
    uint32_t conn;                      /* +0x34 PC: 1 socket open, 0 closed / failed */
    uint32_t pc_time;                   /* +0x38 PC: unix time, written on every poll (0 = never) */
    uint32_t pc_polls;                  /* +0x3c PC: bumped on every poll */
    uint32_t entropy_seq;               /* +0x40 PC: bumped when entropy[] is new */
    uint32_t phone_ticks;               /* +0x44 phone: timer ticks (liveness) */
    uint8_t entropy[32];                /* +0x48 PC */
    uint32_t api_id;                    /* +0x68 PC: from the PC's keyring, never stored on the phone */
    char api_hash[36];                  /* +0x6c PC: 32 hex chars + 0 */
    uint8_t up[TG_PIPE_UP];             /* +0x90 */
    uint8_t dn[TG_PIPE_DN];             /* +0x2090 */
} tg_pipe_t;
#define TG_PIPE_CRUMB   0x76u           /* api->crumb(0x76, pipe) -> D:\F286_76_<address>.TXT */

#endif
