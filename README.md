# f286-telegram

A native Telegram client for the Ruio F286 feature phone (MocorOS, ARM Cortex-A7). It runs as an
SD app under the stock firmware, next to the normal phone, SMS and call stack, and speaks MTProto
2.0 on the phone itself through [tinymtproto](https://github.com/openfeaturephone/tinymtproto).
There is no bridge server: the auth key never leaves the phone.

For now the TCP connection goes through a PC over USB (`relay/tg_relay.py`), because the phone's
own sockets aren't reverse-engineered yet. The PC only moves ciphertext.

## What works

On my F286, through the relay: login with phone number and code (including the move to the
account's home DC), the chat list, a chat's last 20 messages (newest on top), new messages arriving
while the app is open, and sending text. That is one phone and one account, so expect rough edges.

Accounts with two-step verification (a cloud password) can't log in yet: the app says so and stops.
Media shows as `[media]`. Characters outside the BMP (most emoji) show as `?`, and what the stock
fonts can draw beyond that I haven't checked properly.

The key exchange takes about 10 s on the phone, most of it factoring pq (about 7 s), with the
work spread over 30 ms timer ticks so the UI keeps responding.

## Building

Clone the repositories next to each other (f286dbg is only needed to run it):

```
git clone https://github.com/openfeaturephone/f286-telegram
git clone https://github.com/openfeaturephone/tinymtproto
git clone https://github.com/openfeaturephone/mocor-sdk
git clone https://github.com/openfeaturephone/f286dbg
pip install ziglang pyelftools
cd f286-telegram
python build.py
```

That writes `out/tg.bin`. `build.py` takes the SD-app headers, `rt.c` and `app.ld` from mocor-sdk
and the protocol code from `tinymtproto/src`. If they live somewhere else:

```
python build.py --sdk path/to/mocor-sdk --tinymtproto path/to/tinymtproto
```

(or set `MOCOR_SDK` / `TINYMTPROTO`). It refuses an image with writable data or a wrong header,
since the loader can't run those.

## Running it

You need a phone with the mocor-sdk app loader and the f286dbg USB debug agent running (see those
two repositories), and your own api_id and api_hash from https://my.telegram.org ("API development
tools"; they belong to your Telegram account, don't publish them). Put them in the PC's keyring
once:

```
pip install keyring
python -m keyring set telegram-api api_id
python -m keyring set telegram-api api_hash
```

or set `TG_API_ID` and `TG_API_HASH` in the environment of the relay. Then start the app and the
relay:

```
python ../f286dbg/tools/f286.py run out/tg.bin
python relay/tg_relay.py
```

`tg_relay.py` imports `f286.py` (the agent's PC client) from `../f286dbg/tools`; `--tools DIR` or
`F286_TOOLS` point it elsewhere. The status tab of the chat list shows `no PC` until the relay
has found the app.

How the pipe works: the app allocates a 40 KiB block in its heap (`src/tg_pipe.h`: a header, an
8 KiB phone-to-PC ring and a 32 KiB PC-to-phone ring) and leaves its address in the name of an
empty crumb file, `D:\F286_76_<address>.TXT`. The relay finds the crumb, then polls the block
every 30 ms with the agent's memory read and write commands, and connects a real socket when the
app asks for one. It also writes the time, 32 bytes of entropy and the api_id/api_hash into the
block, so none of those are stored on the phone. The agent and the app share the MMI task, so
there is no locking: every field has one writer.

## Known problems

- The session is saved to `D:\F286_TG.BIN` in the clear, auth key included. D: has no protection,
  so anyone with the phone and a USB cable has your account. Deleting the file logs the phone out
  locally; to kill the session itself, end it from another Telegram client (Settings, Devices).
- The phone has no known hardware RNG. The relay's entropy is what makes the keys safe; without
  the relay the app has only key timings.
- The app polls the pipe with a 150 ms timer while it is open. That is a development shortcut and
  costs battery.
- Heap use is above my 128 KiB target: about 29 KiB of app state (including the client), the 40 KiB
  pipe, 89 KiB of client buffers, plus 9 KiB during the key exchange and one buffer per gzipped
  reply. The pipe goes away with native sockets.

## Roadmap

1. Native sockets. The stock firmware has a socket API (`sci_sock_*`, `sci_async_gethostbyname`,
   used by the built-in WAP browser) and PDP context activation; neither has been located and named
   yet. Once they are in the SDK's API table, `tg.c` swaps the pipe for them and nothing in
   tinymtproto changes.
2. Background polling woken by the RTC alarm. The stock alarm service can register an event whose
   callback runs on the RTC alarm with no alarm UI; a test app got 13 of 13 silent wakes on the
   minute over 36 minutes unplugged. The plan: every N minutes, wake, connect,
   `updates.getDifference`, raise a notification, disconnect, set the next alarm. No keepalives:
   battery first, latency second.
3. Two-step verification (SRP, `account.getPassword` / `auth.checkPassword`). The 2048-bit
   modexps are already in tinymtproto; missing are SHA-512 and PBKDF2-HMAC-SHA512 with 100000
   rounds, which will have to be stepped too and may take a while on this CPU. Plus a password
   entry screen.
4. An entropy source on the phone that doesn't depend on the PC.

## Licence

MIT, see `LICENSE`. tinymtproto carries its own third-party notices (TDLib, puff.c).
