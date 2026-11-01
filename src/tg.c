/* tg.c - Telegram for the Ruio F286: the MMI app around tinymtproto's tg_client.c.
 *
 * Screens (stock controls only): chat list (main window, a list; the sub-title tab shows the link
 * state), phone / code / name entry (edit boxes), a chat's history (text box) and compose (edit box).
 * The main window's one-shot timer drives everything: it moves bytes through the PC pipe
 * (tg_pipe.h, relay/tg_relay.py), polls the client with small budgets and handles its events.
 *
 * Until the phone has its own sockets the network is the PC relay over the USB debug agent. The
 * relay also provides the time (the app has no RTC API yet) and entropy (mixed with key timing; the
 * phone has no known TRNG yet), and the api_id/api_hash, which therefore never touch the phone's
 * storage. The saved session (D:\F286_TG.BIN) holds the account's auth key in the clear: D: has no
 * protection, so anyone with the phone has the account.
 *
 * Build: python build.py (see README.md); run: f286.py run out/tg.bin (f286dbg), then relay/tg_relay.py. */
#include "f286_ui.h"
#include "tg_pipe.h"
#include "tg_client.h"

F286_APP_HEADER(f286_main);

#define WIN_MAIN     0x00f28700u
#define WIN_PHONE    0x00f28701u
#define WIN_CODE     0x00f28702u
#define WIN_NAME     0x00f28703u
#define WIN_HIST     0x00f28704u
#define WIN_COMPOSE  0x00f28705u
#define C_MAIN       0x00f28710u
#define C_PHONE      0x00f28711u
#define C_CODE       0x00f28712u
#define C_NAME       0x00f28713u
#define C_HIST       0x00f28714u
#define C_COMPOSE    0x00f28715u

#define TICK_BUSY    30u
#define TICK_IDLE    150u
#define POLLS        24                 /* client polls per tick at most */
#define BUSY_POLLS   4                  /* heavy steps per tick at most */
#define BUDGET       64u                /* per heavy step: Montgomery products (~25 us each on the A7, est.), rho steps, inflate units */
#define ACK_TIMEOUT  15000u             /* ms without a relay answer to a connect request */
#define HIST_CHARS   6000
#define DLG_GAP_MS   5000u              /* the chat list refreshes at most this often */
#define SAVE_MAGIC   0x46534754u        /* "TGSF" */

typedef struct {
    uint32_t magic, version, unix_time, pad;
    tg_persist_t ps;
} save_t;

typedef struct {
    tg_client_t c;
    tg_pipe_t *pipe;
    uint8_t timer;
    int started, connected, sending, ack_wait;
    uint32_t ms, clock_base, ack_ms, sent_off, ent_seq, status, last_key_ms;
    int hist_dlg;                       /* open history: -1 Saved Messages, else a dialog; -2 none */
    int want_dialogs, want_hist;
    tg_dlg_t hist_peer;                 /* the open chat by identity (the list reorders); type NONE = Saved Messages */
    tg_dlg_t send_peer;                 /* where the queued message goes */
    int send_pending;                   /* send_txt waits for the client to be free */
    char send_txt[1200];
    int hist_loaded;                    /* w holds the open chat's history (hist_len chars) */
    uint32_t hist_len, dlg_ms;          /* dlg_ms: when the chat list was last asked for */
    uint16_t line[400];                 /* one message being added on top */
    int main_top, tab_dirty;            /* the main window is on top; its status tab needs redrawing */
    char confirm[24];                   /* the number shown for confirmation; a second OK sends it */
    save_t save;
    uint16_t w[HIST_CHARS];
    char u8[1200];
} app_t;

typedef struct { const f286_api_t *api; app_t *app; } state_t;
APP_STATE(state_t);
#define API (STATE()->api)
#define APP (STATE()->app)

static uint32_t main_win(uint32_t win, uint32_t msg, void *param);

/* ---- small helpers ---- */
static void copy(void *d, const void *s, uint32_t n)
{
    uint8_t *a = d;
    const uint8_t *b = s;
    while (n--) *a++ = *b++;
}

/* UTF-8 -> UCS-2 (characters beyond the BMP become '?'); returns the length, out is 0-terminated */
static uint32_t to_w(const char *s, uint16_t *out, uint32_t cap)
{
    const uint8_t *p = (const uint8_t *)s;
    uint32_t n = 0;
    while (*p && n + 1 < cap) {
        uint32_t c = *p++, more = 0;
        if (c >= 0xf0) { c &= 7; more = 3; }
        else if (c >= 0xe0) { c &= 15; more = 2; }
        else if (c >= 0xc0) { c &= 31; more = 1; }
        else if (c >= 0x80) { c = '?'; }
        while (more && (*p & 0xc0) == 0x80) { c = c << 6 | (*p++ & 63); more--; }
        if (more || c > 0xffff) c = '?';
        out[n++] = (uint16_t)(c == '\n' || c == '\r' ? ' ' : c);
    }
    out[n] = 0;
    return n;
}

/* appends UTF-8 s to out (UCS-2, length *n, capacity cap), keeping newlines */
static void cat_w(uint16_t *out, uint32_t *n, uint32_t cap, const char *s)
{
    const uint8_t *p = (const uint8_t *)s;
    while (*p && *n + 1 < cap) {
        uint32_t c = *p++, more = 0;
        if (c >= 0xf0) { c &= 7; more = 3; }
        else if (c >= 0xe0) { c &= 15; more = 2; }
        else if (c >= 0xc0) { c &= 31; more = 1; }
        else if (c >= 0x80) { c = '?'; }
        while (more && (*p & 0xc0) == 0x80) { c = c << 6 | (*p++ & 63); more--; }
        out[(*n)++] = (uint16_t)(more || c > 0xffff ? '?' : c);
    }
    out[*n] = 0;
}

/* "name: text" for one message */
static void cat_msg(uint16_t *out, uint32_t *n, uint32_t cap, const char *name, const char *text, uint32_t media)
{
    cat_w(out, n, cap, *name ? name : "?");
    cat_w(out, n, cap, ": ");
    cat_w(out, n, cap, media == 2 ? "[service message]" : *text ? text : media ? "[media]" : "");
}

/* UCS-2 -> UTF-8, 0-terminated */
static void to_u8(const uint16_t *w, uint32_t len, char *out, uint32_t cap)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < len; i++) {
        uint32_t c = w[i];
        if (c < 0x80) {
            if (n + 2 > cap) break;
            out[n++] = (char)c;
        } else if (c < 0x800) {
            if (n + 3 > cap) break;
            out[n++] = (char)(0xc0 | c >> 6);
            out[n++] = (char)(0x80 | (c & 63));
        } else {
            if (n + 4 > cap) break;
            out[n++] = (char)(0xe0 | c >> 12);
            out[n++] = (char)(0x80 | ((c >> 6) & 63));
            out[n++] = (char)(0x80 | (c & 63));
        }
    }
    out[n] = 0;
}

static uint32_t now_unix(app_t *a)
{
    return a->clock_base + a->ms / 1000u;
}

static void alert_u8(const uint16_t *line1, const char *line2)
{
    app_t *a = APP;
    static const uint32_t ms = 4000;    /* long enough to read a number or an error */
    to_w(line2, a->w, 64);
    ui_alert_ms(API, &ms, line1, a->w);
}

/* ---- saved session: D:\F286_TG.BIN ---- */
static void save_session(app_t *a)
{
    uint32_t h, done;
    a->save.magic = SAVE_MAGIC;
    a->save.version = 1;
    a->save.unix_time = now_unix(a);
    a->save.ps = a->c.ps;
    h = API->SFS_CreateFile(u"D:\\F286_TG.BIN", SFS_MODE_CREATE_ALWAYS_WRITE, 0, 0);
    if (h) {
        API->SFS_WriteFile(h, &a->save, sizeof a->save, &done, 0);
        API->SFS_CloseFile(h);
    }
    tg_wipe(&a->save.ps, sizeof a->save.ps);
}

static int load_session(app_t *a)
{
    uint32_t h, done = 0;
    h = API->SFS_CreateFile(u"D:\\F286_TG.BIN", SFS_MODE_READ_EXISTING, 0, 0);
    if (!h)
        return 0;
    API->SFS_ReadFile(h, &a->save, sizeof a->save, &done, 0);
    API->SFS_CloseFile(h);
    return done == sizeof a->save && a->save.magic == SAVE_MAGIC && a->save.version == 1;
}

/* ---- main list ---- */
static void status_tab(app_t *a)
{
    const uint16_t *t;
    a->tab_dirty = !a->main_top;
    if (!a->main_top)
        return;
    if (!a->pipe->pc_polls)
        t = u"no PC";
    else switch (a->status) {
        case TG_CLS_CONNECTING: t = u"connect"; break;
        case TG_CLS_KEY: t = u"key..."; break;
        case TG_CLS_ONLINE: t = u"online"; break;
        default: t = u"offline"; break;
    }
    API->GUIWIN_SetSubTitleText(WIN_MAIN, 1, t, wlen(t), 1);
}

static void fill_main(app_t *a)
{
    tg_client_t *c = &a->c;
    API->GUILIST_RemoveAllItems(C_MAIN);
    ui_list_begin(API, C_MAIN, (uint32_t)c->n_dlg + 3);
    if (!c->ps.logged_in) {
        ui_list_add(API, C_MAIN, u"Log in", F286_TXT_SELECT, 0, F286_TXT_EXIT);
        ui_list_add(API, C_MAIN, u"About", F286_TXT_SELECT, 0, F286_TXT_EXIT);
    } else {
        ui_list_add(API, C_MAIN, u"Saved Messages", F286_TXT_SELECT, 0, F286_TXT_EXIT);
        for (int i = 0; i < c->n_dlg; i++) {
            tg_dlg_t *d = &c->dlg[i];
            uint32_t n = 0;
            const char *pre = tg_cl_str(c, d->preview);
            if (d->unread) {
                char num[12];
                int k = 0;
                uint32_t u = (uint32_t)d->unread;
                char rev[11];
                int r = 0;
                do { rev[r++] = (char)('0' + u % 10u); u /= 10u; } while (u && r < 10);
                num[k++] = '(';
                while (r) num[k++] = rev[--r];
                num[k++] = ')';
                num[k++] = ' ';
                num[k] = 0;
                cat_w(a->w, &n, 120, num);
            }
            cat_w(a->w, &n, 120, tg_cl_str(c, d->title));
            cat_w(a->w, &n, 120, ": ");
            cat_w(a->w, &n, 120, *pre ? pre : d->media ? "[media]" : "");
            for (uint32_t k = 0; k < n; k++)
                if (a->w[k] == '\n' || a->w[k] == '\r') a->w[k] = ' ';
            ui_list_add(API, C_MAIN, a->w, F286_TXT_SELECT, 0, F286_TXT_EXIT);
        }
        ui_list_add(API, C_MAIN, u"Refresh", F286_TXT_SELECT, 0, F286_TXT_EXIT);
    }
    ui_list_end(API, WIN_MAIN, C_MAIN);
}

/* ---- history ---- */
static void fill_history(app_t *a)
{
    tg_client_t *c = &a->c;
    uint32_t n = 0;
    if (!API->MMK_IsOpenWin(WIN_HIST))
        return;
    if (!c->n_msg)
        cat_w(a->w, &n, HIST_CHARS, "(no messages)");
    for (int i = 0; i < c->n_msg; i++) {             /* newest first */
        tg_msg_t *m = &c->msg[i];
        cat_msg(a->w, &n, HIST_CHARS, m->out ? "Me" : tg_cl_str(c, m->from_name), tg_cl_str(c, m->text), m->media);
        cat_w(a->w, &n, HIST_CHARS, i + 1 < c->n_msg ? "\n\n" : "");
    }
    a->hist_len = c->n_msg ? n : 0;
    a->hist_loaded = 1;
    API->GUITEXT_SetString(C_HIST, a->w, n, 1);
}

/* the open chat, by identity; Saved Messages is the chat with ourselves */
static int is_open_chat_peer(app_t *a, int type, uint64_t id)
{
    if (a->hist_peer.type == TG_PEER_NONE)
        return type == TG_PEER_USER && id == a->c.ps.user_id;
    return type == a->hist_peer.type && id == a->hist_peer.id;
}

/* a message pushed while its chat is open goes on top of the shown history (no refetch) */
static void add_on_top(app_t *a, const char *name, const char *text, uint32_t media)
{
    uint32_t n = 0, keep;
    if (!API->MMK_IsOpenWin(WIN_HIST) || !a->hist_loaded)
        return;
    cat_msg(a->line, &n, sizeof a->line / 2 - 3, name, text, media);
    if (a->hist_len)
        cat_w(a->line, &n, sizeof a->line / 2, "\n\n");
    keep = a->hist_len;
    if (keep > HIST_CHARS - 1 - n)
        keep = HIST_CHARS - 1 - n;                  /* the oldest text falls off the end */
    for (uint32_t i = keep; i-- > 0;)
        a->w[n + i] = a->w[i];
    copy(a->w, a->line, n * 2);
    a->hist_len = n + keep;
    a->w[a->hist_len] = 0;
    API->GUITEXT_SetString(C_HIST, a->w, a->hist_len, 1);
}

static uint32_t hist_win(uint32_t win, uint32_t msg, void *param);
static uint32_t compose_win(uint32_t win, uint32_t msg, void *param);
static uint32_t entry_win(uint32_t win, uint32_t msg, void *param);

static void open_entry(uint32_t win_id, uint32_t ctrl, uint32_t max_len)
{
    ui_t t;
    ui_begin(&t, entry_win, win_id);
    ui_softkey(&t, F286_TXT_OK, F286_TXT_NULL, F286_TXT_BACK);
    ui_title(&t, F286_TXT_EDIT);
    /* the number and the code are keypad digits; only the name takes text */
    ui_edit_kind(&t, win_id == WIN_PHONE ? F286_WT_EDIT_PHONENUM : win_id == WIN_CODE ? F286_WT_EDIT_DIGITAL
                 : F286_WT_EDIT_TEXT, max_len, ctrl);
    ui_open(API, &t);
}

static void open_history(app_t *a, int dlg)
{
    ui_t t;
    a->hist_dlg = dlg;
    a->hist_loaded = 0;
    zero(&a->hist_peer, sizeof a->hist_peer);
    if (dlg >= 0)
        a->hist_peer = a->c.dlg[dlg];
    a->want_hist = 1;
    ui_begin(&t, hist_win, WIN_HIST);
    ui_softkey(&t, F286_TXT_EDIT, F286_TXT_NULL, F286_TXT_BACK);
    ui_title(&t, F286_TXT_VIEW);
    ui_text(&t, C_HIST);
    ui_open(API, &t);
}

static uint32_t hist_win(uint32_t win, uint32_t msg, void *param)
{
    app_t *a = APP;
    (void)param;
    switch (msg) {
    case MSG_OPEN_WINDOW: {
        uint32_t n = 0;
        cat_w(a->w, &n, 64, "Loading...");
        API->GUITEXT_SetString(C_HIST, a->w, n, 0);
        API->MMK_SetAtvCtrl(win, C_HIST);
        return 1;
    }
    case MSG_APP_OK: {                               /* reply */
        ui_t t;
        ui_begin(&t, compose_win, WIN_COMPOSE);
        ui_softkey(&t, F286_TXT_OK, F286_TXT_NULL, F286_TXT_BACK);
        ui_title(&t, F286_TXT_EDIT);
        ui_edit(&t, 500, C_COMPOSE);
        ui_open(API, &t);
        return 1;
    }
    case MSG_APP_CANCEL:
        API->MMK_CloseWin(win);
        return 1;
    case MSG_CLOSE_WINDOW:
        a->hist_dlg = -2;
        return 0;
    default:
        return 0;
    }
}

static uint32_t compose_win(uint32_t win, uint32_t msg, void *param)
{
    app_t *a = APP;
    (void)param;
    switch (msg) {
    case MSG_OPEN_WINDOW:
        API->MMK_SetAtvCtrl(win, C_COMPOSE);
        return 1;
    case MSG_APP_OK:
    case MSG_APP_WEB: {
        MMI_STRING_T s;
        API->GUIEDIT_GetString(C_COMPOSE, &s);
        if (s.wstr_len && a->send_pending) {
            ui_alert(API, u"Still sending", u"the last message");
            return 1;                               /* keep the text */
        }
        if (s.wstr_len) {                           /* queued: the client may be busy with a fetch */
            to_u8(s.wstr_ptr, s.wstr_len, a->send_txt, sizeof a->send_txt);
            a->send_peer = a->hist_peer;
            a->send_pending = 1;
        }
        API->MMK_CloseWin(win);
        return 1;
    }
    case MSG_APP_CANCEL:
        API->MMK_CloseWin(win);
        return 1;
    default:
        return 0;
    }
}

/* phone, code and name entry */
static uint32_t entry_win(uint32_t win, uint32_t msg, void *param)
{
    app_t *a = APP;
    uint32_t ctrl = win == WIN_PHONE ? C_PHONE : win == WIN_CODE ? C_CODE : C_NAME;
    (void)param;
    switch (msg) {
    case MSG_OPEN_WINDOW:
        if (win == WIN_PHONE)
            API->GUIEDIT_SetString(C_PHONE, u"+", 1);
        API->MMK_SetAtvCtrl(win, ctrl);
        return 1;
    case MSG_APP_OK:
    case MSG_APP_WEB: {
        MMI_STRING_T s;
        API->GUIEDIT_GetString(ctrl, &s);
        to_u8(s.wstr_ptr, s.wstr_len, a->u8, sizeof a->u8);
        if (win == WIN_PHONE) {
            char digits[24];
            uint32_t k = 0;
            for (const char *p = a->u8; *p && k < sizeof digits - 1; p++)
                if (*p >= '0' && *p <= '9') digits[k++] = *p;
            digits[k] = 0;
            if (k < 8) {
                ui_alert(API, u"Enter the number", u"with country code");
                return 1;
            }
            int same = 1;
            for (uint32_t j = 0; j <= k; j++)
                if (a->confirm[j + 1] != digits[j]) same = 0;
            if (!same) {                            /* first OK: show what will be sent */
                a->confirm[0] = '+';
                copy(a->confirm + 1, digits, k + 1);
                alert_u8(u"OK again to send to", a->confirm);
                return 1;
            }
            zero(a->confirm, sizeof a->confirm);
            tg_cl_send_code(&a->c, digits);
        } else if (win == WIN_CODE) {
            tg_cl_sign_in(&a->c, a->u8);
        } else {
            tg_cl_sign_up(&a->c, a->u8, "");
        }
        API->MMK_CloseWin(win);
        return 1;
    }
    case MSG_APP_CANCEL:
        API->MMK_CloseWin(win);
        return 1;
    default:
        return 0;
    }
}

/* ---- client events ---- */
static void on_event(app_t *a)
{
    tg_client_t *c = &a->c;
    tg_clev_t *e = &c->ev;
    switch (e->type) {
    case TG_CLE_STATUS:
        a->status = e->a;
        status_tab(a);
        break;
    case TG_CLE_PERSIST:
        save_session(a);
        break;
    case TG_CLE_CODE_SENT:
        open_entry(WIN_CODE, C_CODE, 12);
        break;
    case TG_CLE_SIGNUP_REQUIRED:
        ui_alert(API, u"New account:", u"enter your name");
        open_entry(WIN_NAME, C_NAME, 40);
        break;
    case TG_CLE_PASSWORD:
        ui_alert(API, u"Two-step password", u"is not supported yet");
        break;
    case TG_CLE_LOGGED_IN:
        fill_main(a);
        a->want_dialogs = 1;
        break;
    case TG_CLE_DIALOGS:
        fill_main(a);
        break;
    case TG_CLE_HISTORY:
        fill_history(a);
        break;
    case TG_CLE_SENT:
        if (a->hist_dlg != -2 && (a->send_peer.type == TG_PEER_NONE ? a->hist_peer.type == TG_PEER_NONE
                                  : is_open_chat_peer(a, a->send_peer.type, a->send_peer.id)))
            add_on_top(a, "Me", a->send_txt, 0);
        a->want_dialogs = 1;
        break;
    case TG_CLE_NEW_MESSAGE: {
        const tg_msg_t *m = &c->inbox[e->a];
        if (a->hist_dlg != -2 && is_open_chat_peer(a, m->peer_type, m->peer_id))
            add_on_top(a, m->out ? "Me" : tg_cl_peer_name(c, m->from_type, m->from_id), c->inbox_text[e->a], m->media);
        a->want_dialogs = 1;                        /* fetched once the list is on screen again */
        break;
    }
    case TG_CLE_ERROR:
        if (e->code != -1)
            alert_u8(u"Telegram:", c->err_text);
        break;
    default:
        break;
    }
}

/* ---- pipe ---- */
static void pipe_in(app_t *a)
{
    tg_pipe_t *p = a->pipe;
    while (p->dn_wr != p->dn_rd) {
        uint32_t room, idx = p->dn_rd & (TG_PIPE_DN - 1), n = p->dn_wr - p->dn_rd;
        uint8_t *dst = tg_cl_rx_space(&a->c, &room);
        if (n > TG_PIPE_DN - idx) n = TG_PIPE_DN - idx;
        if (n > room) n = room;
        if (!n) break;
        copy(dst, p->dn + idx, n);
        tg_cl_rx_commit(&a->c, n);
        p->dn_rd += n;
    }
}

/* returns 1 when all of c->out is in the ring */
static int pipe_out(app_t *a)
{
    tg_pipe_t *p = a->pipe;
    while (a->sent_off < a->c.out_len) {
        uint32_t idx = p->up_wr & (TG_PIPE_UP - 1), free = TG_PIPE_UP - (p->up_wr - p->up_rd);
        uint32_t n = a->c.out_len - a->sent_off;
        if (n > TG_PIPE_UP - idx) n = TG_PIPE_UP - idx;
        if (n > free) n = free;
        if (!n) return 0;
        copy(p->up + idx, a->c.out + a->sent_off, n);
        p->up_wr += n;
        a->sent_off += n;
    }
    return 1;
}

static void pipe_request(app_t *a, uint32_t req)
{
    tg_pipe_t *p = a->pipe;
    p->ip = a->c.ip;
    p->port = a->c.port;
    p->req = req;
    p->req_seq++;
}

/* the client may start once the relay has given the api_id (and time and entropy) */
static void maybe_start(app_t *a)
{
    tg_pipe_t *p = a->pipe;
    if (a->started || !p->api_id || !p->pc_time || !p->entropy_seq)
        return;
    a->c.cfg.api_id = (int32_t)p->api_id;
    copy(a->c.cfg.api_hash, p->api_hash, 32);
    a->c.cfg.api_hash[32] = 0;
    a->started = 1;
    tg_cl_online(&a->c, 1);
    if (a->c.ps.logged_in)
        a->want_dialogs = 1;
}

static int tick(app_t *a, uint32_t step_ms)
{
    tg_pipe_t *p = a->pipe;
    tg_client_t *c = &a->c;
    int busy = 0, heavy = 0;
    a->ms += step_ms;
    p->phone_ticks++;
    if (p->pc_time)
        a->clock_base = p->pc_time - a->ms / 1000u;
    if (p->entropy_seq != a->ent_seq) {
        tg_rng_add(&c->rng, p->entropy, 32);
        a->ent_seq = p->entropy_seq;
    }
    maybe_start(a);
    if (a->ack_wait) {
        if (p->ack_seq == p->req_seq) {
            a->ack_wait = 0;
            a->connected = p->conn != 0;
            if (a->connected) {
                p->dn_rd = p->dn_wr;                /* a fresh stream */
                tg_cl_connected(c);
            } else {
                tg_cl_disconnected(c);
            }
        } else if (a->ms - a->ack_ms > ACK_TIMEOUT) {
            a->ack_wait = 0;
            tg_cl_disconnected(c);
        }
    } else if (a->connected && !p->conn) {
        a->connected = 0;
        tg_cl_disconnected(c);
    }
    if (a->connected)
        pipe_in(a);
    if (a->sending) {
        if (!a->connected || pipe_out(a)) {
            a->sending = 0;
            tg_cl_sent(c);
        }
    }
    for (int i = 0; i < POLLS && !a->sending && !a->ack_wait && a->started; i++) {
        int r = tg_cl_poll(c, now_unix(a), BUDGET);
        if (r == TG_CL_IDLE)
            break;
        if (r == TG_CL_BUSY) {
            busy = 1;
            if (++heavy >= BUSY_POLLS)
                break;
        } else if (r == TG_CL_EVENT) {
            on_event(a);
        } else if (r == TG_CL_CONNECT) {
            pipe_request(a, TG_PIPE_REQ_CONNECT);
            a->ack_wait = 1;
            a->ack_ms = a->ms;
        } else if (r == TG_CL_SEND) {
            a->sent_off = 0;
            a->sending = 1;
            if (!a->connected || pipe_out(a)) {
                a->sending = 0;
                tg_cl_sent(c);
            }
        } else if (r == TG_CL_CLOSE) {
            pipe_request(a, TG_PIPE_REQ_CLOSE);
            a->connected = 0;
            tg_cl_disconnected(c);
        }
    }
    if (a->started && c->req_kind == 0 && c->ps.logged_in) {
        if (a->send_pending) {
            a->send_pending = 0;
            tg_cl_send_text_peer(c, a->send_peer.type == TG_PEER_NONE ? 0 : &a->send_peer, a->send_txt);
        } else if (a->want_hist && a->hist_dlg != -2) {
            a->want_hist = 0;
            tg_cl_get_history_peer(c, a->hist_peer.type == TG_PEER_NONE ? 0 : &a->hist_peer);
        } else if (a->want_dialogs && a->main_top && (!a->dlg_ms || a->ms - a->dlg_ms >= DLG_GAP_MS)) {
            a->want_dialogs = 0;
            a->dlg_ms = a->ms | 1;
            tg_cl_get_dialogs(c);
        }
    }
    if (!(p->phone_ticks & 15) || (a->tab_dirty && a->main_top))
        status_tab(a);
    return busy || a->sending || a->ack_wait;
}

/* ---- main window ---- */
static void *c_alloc(void *ctx, uint32_t n) { return ((const f286_api_t *)ctx)->alloc(n); }
static void c_free(void *ctx, void *p) { ((const f286_api_t *)ctx)->free(p); }

static void app_close(app_t *a)
{
    if (a->timer)
        API->MMK_StopTimer(a->timer);
    a->timer = 0;
    if (a->pipe) {
        a->pipe->magic = 0;
        if (a->connected)
            pipe_request(a, TG_PIPE_REQ_CLOSE);
    }
    tg_cl_free(&a->c);
    if (a->pipe)
        API->free(a->pipe);
    tg_wipe(a, sizeof *a);
    API->free(a);
    STATE()->app = 0;
}

static uint32_t main_win(uint32_t win, uint32_t msg, void *param)
{
    app_t *a = APP;
    if (!a)
        return 0;
    switch (msg) {
    case MSG_OPEN_WINDOW:
        a->main_top = 1;
        fill_main(a);
        status_tab(a);
        a->timer = API->MMK_CreateWinTimer(win, TICK_IDLE, 0, 0, 0);
        return 1;
    case MSG_TIMER:
        if (param && *(uint8_t *)param == a->timer) {
            int busy = tick(a, a->sending || a->ack_wait ? TICK_BUSY : TICK_IDLE);
            a->timer = API->MMK_CreateWinTimer(win, busy ? TICK_BUSY : TICK_IDLE, 0, 0, 0);
            return 1;
        }
        return 0;
    case MSG_APP_OK:
    case MSG_APP_WEB: {
        uint32_t i = API->GUILIST_GetCurItemIndex(C_MAIN);
        uint8_t mix[8];
        tg_wr32(mix, a->ms);
        tg_wr32(mix + 4, i ^ (a->ms - a->last_key_ms));
        tg_rng_add(&a->c.rng, mix, 8);              /* key timing as a little extra entropy */
        a->last_key_ms = a->ms;
        if (!a->c.ps.logged_in) {
            if (i == 0) {
                if (!a->started)
                    ui_alert(API, u"Start the PC relay:", u"tg_relay.py");
                else
                    open_entry(WIN_PHONE, C_PHONE, 20);
            } else {
                ui_alert(API, u"Telegram for F286", u"native MTProto 2.0");
            }
        } else if (i == 0) {
            open_history(a, -1);
        } else if ((int)i <= a->c.n_dlg) {
            open_history(a, (int)i - 1);
        } else {
            a->want_dialogs = 1;
        }
        return 1;
    }
    case MSG_APP_CANCEL:
        API->MMK_CloseWin(win);
        return 1;
    case MSG_LOSE_FOCUS:
        a->main_top = 0;
        return 0;
    case MSG_FULL_PAINT:
        a->main_top = 1;                            /* back on top: the next tick redraws the tab */
        return 0;
    case MSG_CLOSE_WINDOW:
        app_close(a);
        return 0;
    default:
        return 0;
    }
}

void f286_main(const f286_api_t *api, void *base, uint32_t size)
{
    app_t *a;
    tg_clcfg_t cfg;
    tg_persist_t *ps = 0;
    ui_t t;
    (void)base;
    (void)size;
    if (api->version < 3 || api->MMK_IsOpenWin(WIN_MAIN))
        return;
    STATE()->api = api;
    a = api->alloc(sizeof *a);
    if (!a)
        return;
    zero(a, sizeof *a);
    a->pipe = api->alloc(sizeof *a->pipe);
    if (!a->pipe) {
        api->free(a);
        return;
    }
    zero(a->pipe, sizeof *a->pipe);
    a->pipe->size = sizeof *a->pipe;
    a->pipe->up_cap = TG_PIPE_UP;
    a->pipe->dn_cap = TG_PIPE_DN;
    a->pipe->magic = TG_PIPE_MAGIC;
    a->hist_dlg = -2;
    STATE()->app = a;

    zero(&cfg, sizeof cfg);
    cfg.alloc = c_alloc;
    cfg.free = c_free;
    cfg.ctx = (void *)api;
    cfg.dc = 2;
    cfg.device_model = "Ruio F286";                  /* shown in the account's active sessions */
    cfg.system_version = "MocorOS";
    cfg.app_version = "0.1";
    tg_wr32(cfg.seed, (uint32_t)a);                  /* real entropy comes from the relay */
    tg_wr32(cfg.seed + 4, (uint32_t)a->pipe);
    if (load_session(a)) {
        ps = &a->save.ps;
        a->clock_base = a->save.unix_time;
    }
    if (tg_cl_init(&a->c, &cfg, ps)) {
        api->free(a->pipe);
        api->free(a);
        STATE()->app = 0;
        ui_alert(api, u"Out of memory", 0);
        return;
    }
    tg_wipe(&a->save.ps, sizeof a->save.ps);
    api->crumb(TG_PIPE_CRUMB, (uint32_t)a->pipe);    /* D:\F286_76_<pipe>.TXT: the relay finds it */

    ui_begin(&t, main_win, WIN_MAIN);
    ui_softkey(&t, F286_TXT_SELECT, F286_TXT_NULL, F286_TXT_EXIT);
    ui_title(&t, F286_TXT_MENU);
    ui_list(&t, C_MAIN);
    ui_open(api, &t);
}
