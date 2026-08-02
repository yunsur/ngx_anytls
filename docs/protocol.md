# AnyTLS v2 Protocol Reference

> Behavior baseline: local reference implementation of the AnyTLS v2 server

This document provides a comprehensive reference for implementing AnyTLS v2 server in the nginx module.

---

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Authentication Mechanism](#authentication-mechanism)
3. [Frame Structure](#frame-structure)
4. [Command Types Reference](#command-types-reference)
5. [Padding and Obfuscation](#padding-and-obfuscation)
6. [Stream Multiplexing](#stream-multiplexing)
7. [UDP over TCP (UoT)](#udp-over-tcp-uot)
8. [Server Implementation Guide](#server-implementation-guide)
9. [ngx_anytls Implementation Notes](#ngx_anytls-implementation-notes)
10. [Protocol Constants](#protocol-constants)
11. [Version Negotiation](#version-negotiation)
12. [Error Handling](#error-handling)
13. [Debugging Checklist](#debugging-checklist)
14. [Reference Implementation Locations](#reference-implementation-locations)
15. [Quick Reference Card](#quick-reference-card)

---

## Protocol Overview

### Layer Structure

```
┌─────────────────────────────┐
│  Application (HTTP, etc.)   │
├─────────────────────────────┤
│  Streams (individual conns) │
├─────────────────────────────┤
│  Session (multiplexing)     │
├─────────────────────────────┤
│  Authentication (SHA256)    │
├─────────────────────────────┤
│  TLS 1.2/1.3               │
├─────────────────────────────┤
│  TCP                        │
└─────────────────────────────┘
```

### Data Flow

1. Client connects via TLS
2. Client sends authentication (SHA256 hash + padding0)
3. Client sends cmdSettings frame
4. For each proxied connection:
   - Client sends cmdSYN + cmdPSH(destination)
   - Server creates outbound connection
   - Server sends cmdSYNACK (v2 only)
   - Bidirectional data via cmdPSH frames
   - Either side sends cmdFIN on close
5. Session stays alive for reuse (multiplexing)

---

## Authentication Mechanism

### Authentication Packet Structure

**CRITICAL:** This is the FIRST data after TLS handshake completion.

```
Offset  | Size    | Type              | Description
--------|---------|-------------------|---------------------------
0       | 32      | byte[32]          | SHA256(password)
32      | 2       | Big-Endian uint16 | padding0 length
34      | N       | byte[N]           | padding0 data (zeros)
```

### Implementation Details

**Password Hashing:**
```c
// Pseudo-code
password = "your-secret-password"  // UTF-8 string
hash = SHA256(password)            // 32 bytes
```

**Reading Authentication (Server Side):**
```c
// 1. Read into buffer (may contain more than auth data)
buffer_read_from_connection();

// 2. Extract hash and compare against the configured user set
uint8_t received_hash[32];
buffer_read_bytes(received_hash, 32);

// 2a. Constant-time set comparison: walk EVERY configured user's
// hash before deciding, so the number/position of users is not
// leaked through timing.  No early exit on a match.
int matched = 0;
const char *matched_name = NULL;
for (size_t i = 0; i < user_count; i++) {
    if (constant_time_eq(received_hash, users[i].hash, 32)) {
        if (!matched_name) matched_name = users[i].name;
        matched = 1;
    }
}

if (!matched) {
    // Authentication failed - replay buffered plaintext to the
    // configured fallback upstream (anti-detection), or close if
    // no fallback is configured.
    fallback_connection();
    return;
}
// The matched user name is recorded on the connection (logs/accounting).

// 3. Read padding0 length (Big-Endian!)
uint16_t padding0_len = (buffer[0] << 8) | buffer[1];
buffer_skip(2);

// 4. Read and discard padding0
buffer_skip(padding0_len);

// 5. Now ready to read frames
```

**Multi-user authentication:**
- The server may be configured with up to 64 named users, each with an
  independent password (`anytls_user <name> <password>;` in nginx).
- The client still sends only the 32-byte SHA-256 hash of its password;
  the username is never sent on the wire.
- The server compares the received hash against the whole configured set
  in constant time (no early exit), so user count and match position are
  not observable through timing.
- Once the hash matches, the match is cached for the connection: while
  waiting for a large auth padding (up to 65535 bytes) delivered in slow
  chunks, the user set is not rescanned on every chunk (CPU amplification
  guard).  This leaks nothing, because only the sender of a valid hash
  observes the match.
- Config-time validation rejects duplicate user names and duplicate
  password hashes (a shared hash would make "which name" ambiguous).

**Default padding0 length:** 30 bytes (from padding scheme `0=30-30`)

**Security Notes:**
- Password is NEVER sent in plaintext
- Only SHA256 hash is transmitted
- If no hash matches, the server transparently replays the buffered
  plaintext bytes to the configured fallback upstream (anti-detection);
  `anytls_fallback_proxy_protocol on` prepends a PROXY protocol header
- No error message is sent to the client on auth failure

---

## Frame Structure

### Binary Layout

All data after authentication consists of frames:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     cmd       |                  streamId                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   streamId    |         data_length           |   data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Header:** 7 bytes fixed
- Byte 0: Command (uint8)
- Bytes 1-4: Stream ID (Big-Endian uint32)
- Bytes 5-6: Data Length (Big-Endian uint16)

**Data:** 0-65535 bytes (variable)

### Frame Reading Algorithm

```c
// Read frame header (atomic operation)
uint8_t header[7];
read_exactly(conn, header, 7);

uint8_t cmd = header[0];
uint32_t stream_id = (header[1] << 24) | (header[2] << 16) |
                     (header[3] << 8)  | header[4];
uint16_t data_len = (header[5] << 8) | header[6];

// Read frame data
uint8_t *data = NULL;
if (data_len > 0) {
    data = malloc(data_len);
    read_exactly(conn, data, data_len);
}

// Dispatch based on cmd
handle_frame(cmd, stream_id, data, data_len);
```

**IMPORTANT:** Always read full 7-byte header atomically. Never assume header alignment.

---

## Command Types Reference

### Command Values

```c
#define CMD_WASTE                0  // Padding frame (discard)
#define CMD_SYN                  1  // Stream open
#define CMD_PSH                  2  // Data frame
#define CMD_FIN                  3  // Stream close
#define CMD_SETTINGS             4  // Client settings
#define CMD_ALERT                5  // Server alert
#define CMD_UPDATE_PADDING       6  // Server sends new padding scheme
#define CMD_SYNACK               7  // Stream open ACK (v2)
#define CMD_HEART_REQUEST        8  // Keepalive request (v2)
#define CMD_HEART_RESPONSE       9  // Keepalive response (v2)
#define CMD_SERVER_SETTINGS     10  // Server settings (v2)
```

### Command Details

#### CMD_WASTE (0)

**Purpose:** Traffic obfuscation, padding

**Format:**
- stream_id: 0 (ignored)
- data: random bytes to discard

**Handling:**
```c
case CMD_WASTE:
    // Simply discard data, no processing
    free(data);
    break;
```

#### CMD_SYN (1)

**Purpose:** Client requests to open new stream

**Format:**
- stream_id: Client-generated ID (monotonically increasing, starts at 1)
- data: empty (length = 0)

**Server Handling:**
```c
case CMD_SYN:
    // CRITICAL: Must reject if no CMD_SETTINGS received yet
    if (!session->received_settings) {
        send_alert(session, "Settings not received");
        close_session(session);
        return;
    }

    // Create new stream object
    stream_t *stream = create_stream(session, stream_id);
    add_to_stream_map(session, stream_id, stream);

    // Trigger callback to read destination and connect
    on_new_stream(stream);
    break;
```

**Rules:**
- Client MUST send CMD_SETTINGS before any CMD_SYN
- Server MUST reject session if SYN comes first
- Stream IDs must be unique per session
- Stream ID 0 is invalid

#### CMD_PSH (2)

**Purpose:** Transfer stream data

**Format:**
- stream_id: Target stream ID
- data: payload bytes

**Handling:**
```c
case CMD_PSH:
    stream_t *stream = find_stream(session, stream_id);
    if (stream) {
        // Write data to stream buffer (for application to read)
        stream_write_buffer(stream, data, data_len);
    }
    // If stream not found, silently discard
    break;
```

**Notes:**
- Most frequent command during data transfer
- First PSH on new stream contains SOCKS5 destination address
- Can have length 0 (rare but valid)

#### CMD_FIN (3)

**Purpose:** Close stream gracefully

**Format:**
- stream_id: Stream to close
- data: empty (length = 0)

**Handling:**
```c
case CMD_FIN:
    stream_t *stream = find_stream(session, stream_id);
    if (stream) {
        stream_close(stream);  // Signal EOF to application
        remove_from_stream_map(session, stream_id);
    }
    break;
```

**Rules:**
- One-way notification (no FIN response required)
- Session continues after stream closes (keep for reuse)
- Don't send FIN if session is closing anyway

#### CMD_SETTINGS (4)

**Purpose:** Client announces capabilities and padding scheme

**Format:**
- stream_id: 0
- data: UTF-8 text, key=value pairs separated by newline (`\n`)

**Required Fields:**
```
v=2
client=anytls/0.0.11
padding-md5=a1b2c3d4e5f6...
```

**Example Data:**
```
v=2
client=anytls/0.0.11
padding-md5=8f3e7a2d9c1b5e4f6a8d7c9b2e1f3a5c
```

**Server Handling:**
```c
case CMD_SETTINGS:
    // Empty SETTINGS is treated as "not sent"
    if (data_len == 0) {
        break;
    }

    // Duplicates are processed the same way as first SETTINGS.
    parse_settings(data, data_len, &settings);

    // Extract protocol version (v>=2 enables v2 features)
    if (settings.version >= 2) {
        session->peer_version = settings.version;  // "2" -> 2
    }

    // Check padding MD5
    const char *expected_md5 = calculate_padding_md5();
    if (strcmp(settings.padding_md5, expected_md5) != 0) {
        // Send updated padding scheme
        send_update_padding_scheme(session);
    }

    // Mark settings received only when payload is non-empty and parsed
    session->received_settings = true;

    // Send server settings only when current SETTINGS says v>=2
    if (settings.version >= 2) {
        send_server_settings(session);
    }
    break;
```

**Critical Rules:**
- MUST be first frame sent by client (after authentication)
- Server MUST reject any CMD_SYN before receiving this
- Empty SETTINGS payload is treated as "SETTINGS not received" and has no side effects
- Repeated non-empty SETTINGS is re-processed (not ignored as duplicate)
- Padding MD5 is compared verbatim from payload (no trailing `\r` trimming)
- Version field determines protocol behavior

#### CMD_ALERT (5)

**Purpose:** Server sends error message before closing

**Format:**
- stream_id: 0
- data: UTF-8 error message

**Server Sending:**
```c
void send_alert(session_t *session, const char *message) {
    uint8_t header[7];
    header[0] = CMD_ALERT;
    header[1] = header[2] = header[3] = header[4] = 0;  // stream_id = 0
    uint16_t len = strlen(message);
    header[5] = (len >> 8) & 0xFF;
    header[6] = len & 0xFF;

    write_all(session->conn, header, 7);
    write_all(session->conn, message, len);

    // Close session after alert
    close_session(session);
}
```

**Client Handling:**
```c
case CMD_ALERT:
    // Log error message
    log_error("Server alert: %.*s", data_len, data);
    // Close session
    close_session(session);
    break;
```

#### CMD_UPDATE_PADDING (6)

**Purpose:** Server sends new padding scheme to client

**Format:**
- stream_id: 0
- data: Raw padding scheme (same format as file)

**Example Data:**
```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

**When Sent:**
- After receiving CMD_SETTINGS with mismatched padding-md5

**Server Sending:**
```c
if (strcmp(client_padding_md5, server_padding_md5) != 0) {
    uint8_t header[7];
    header[0] = CMD_UPDATE_PADDING;
    // ... set stream_id = 0, data_len = padding_scheme_size ...

    write_all(session->conn, header, 7);
    write_all(session->conn, padding_scheme_data, padding_scheme_size);
}
```

**Client Handling:**
- Updates local padding scheme for future connections
- Can be disabled with `CLIENT_DEBUG_PADDING_SCHEME=1`

**Server Receiving from Client:**
- Payload is consumed and ignored (no padding update, no close)
- Matches the reference server's inbound handling

#### CMD_SYNACK (7) - Version 2

**Purpose:** Server acknowledges stream open, reports connection status

**Format:**
- stream_id: Matching stream_id from CMD_SYN
- data: Empty = success, Non-empty = error message

**When Sent:**
- After outbound TCP connection succeeds or fails
- Only sent to v2 clients (peer_version >= 2)
- On outbound failure, server sends `SYNACK(error)` then closes stream via FIN path

**Server Receiving from Client (parity behavior):**
- Empty payload: ignored
- Non-empty payload and matching stream exists: close that stream (FIN path), equivalent to `closeWithError` semantics

**Server Sending:**
```c
void on_new_stream(stream_t *stream) {
    // Read destination from first PSH
    socks_addr_t dest = read_socks_addr(stream);

    // Try to connect
    int outbound_fd = connect_to_destination(dest);

    if (outbound_fd < 0) {
        // Connection failed
        send_synack(stream, "Connection refused");
        close_stream(stream);
        return;
    }

    // Connection succeeded
    send_synack(stream, "");  // Empty data = success

    // Start bidirectional copy
    copy_bidirectional(stream, outbound_fd);
}

void send_synack(stream_t *stream, const char *error) {
    uint8_t header[7];
    header[0] = CMD_SYNACK;
    // ... set stream_id, data_len ...

    write_all(stream->session->conn, header, 7);
    if (error && error[0]) {
        write_all(stream->session->conn, error, strlen(error));
    }
}
```

**Client Handling:**
```c
case CMD_SYNACK:
    stream_t *stream = find_stream(session, stream_id);
    if (stream) {
        if (data_len > 0) {
            // Error message
            log_error("SYNACK error: %.*s", data_len, data);
            close_stream(stream);
        } else {
            // Success
            stream->handshake_complete = true;
        }
    }
    break;
```

**Timeout:**
- Client waits max 3 seconds for SYNACK
- If timeout, closes stream and retries

#### CMD_HEART_REQUEST (8) - Version 2

**Purpose:** Keepalive mechanism

**Format:**
- stream_id: 0
- data: empty

**Handling:**
```c
case CMD_HEART_REQUEST:
    // Respond immediately
    uint8_t header[7] = {CMD_HEART_RESPONSE, 0, 0, 0, 0, 0, 0};
    write_all(session->conn, header, 7);
    break;
```

**Notes:**
- Server only performs passive heartbeat handling (reply to request)
- No active keepalive heartbeat or heartbeat-timeout close logic
- No AnyTLS-specific idle/session/stream policy negotiation

#### CMD_HEART_RESPONSE (9) - Version 2

**Purpose:** Response to heartbeat request

**Handling:**
```c
case CMD_HEART_RESPONSE:
    // No special handling needed
    break;
```

#### CMD_SERVER_SETTINGS (10) - Version 2

**Purpose:** Server announces its protocol version

**Format:**
- stream_id: 0
- data: `v=2` (UTF-8 text)

**When Sent:**
- After receiving CMD_SETTINGS from v2 client

**Server Sending:**
```c
if (session->peer_version >= 2) {
    uint8_t header[7];
    header[0] = CMD_SERVER_SETTINGS;
    const char *data = "v=2";
    // ... set stream_id = 0, data_len = 3 ...

    write_all(session->conn, header, 7);
    write_all(session->conn, data, 3);
}
```

**Client Handling:**
- Confirms server is v2-capable
- Enables v2 features (SYNACK, passive heartbeat)

---

## Padding and Obfuscation

### Default Padding Scheme

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

### Scheme Syntax

**Format:** `packet_number=range[,range...]`

**Range Types:**
1. `min-max` - Random size between min and max bytes
2. `fixed-fixed` - Exact size (e.g., `30-30` = exactly 30 bytes)
3. `c` - Check marker (stop sending if no data remaining)

**Stop Value:** `stop=N` means apply padding to packets 0 through N-1

### Packet Counter

**Key Concept:** Packet counter increments on each TLS write, starting at 0

```
Packet 0: Authentication (SHA256 + padding0)
Packet 1: CMD_SETTINGS + CMD_SYN + CMD_PSH(SocksAddr)
Packet 2: First proxy data (e.g., TLS ClientHello)
Packet 3: Second proxy data
...
Packet 7: Eighth proxy data
Packet 8+: No padding (raw data)
```

### Padding Algorithm

For each packet < stop:

```c
void write_with_padding(session_t *session, uint8_t *data, size_t len) {
    uint32_t pkt_num = session->pkt_counter++;

    if (pkt_num >= session->padding_stop) {
        // No padding, send raw data
        write_all(session->conn, data, len);
        return;
    }

    // Get ranges for this packet
    range_t *ranges = get_ranges_for_packet(pkt_num);
    size_t remaining = len;
    uint8_t *pos = data;

    for (size_t i = 0; ranges[i].type != RANGE_END; i++) {
        if (ranges[i].type == RANGE_CHECK) {
            // Check marker: stop if no data
            if (remaining == 0) break;
            continue;
        }

        // Calculate range size
        size_t range_size;
        if (ranges[i].min == ranges[i].max) {
            range_size = ranges[i].min;  // Fixed size
        } else {
            range_size = random_range(ranges[i].min, ranges[i].max);
        }

        // Send data + padding for this range
        if (remaining >= range_size) {
            // Have enough data
            write_all(session->conn, pos, range_size);
            pos += range_size;
            remaining -= range_size;
        } else if (remaining > 0) {
            // Need padding
            write_all(session->conn, pos, remaining);
            size_t padding_needed = range_size - remaining;
            send_waste_frame(session, padding_needed);
            pos += remaining;
            remaining = 0;
        } else {
            // No data, send pure padding
            send_waste_frame(session, range_size);
        }
    }

    // Send any remaining data
    if (remaining > 0) {
        write_all(session->conn, pos, remaining);
    }
}

void send_waste_frame(session_t *session, size_t len) {
    uint8_t header[7];
    header[0] = CMD_WASTE;
    header[1] = header[2] = header[3] = header[4] = 0;
    header[5] = (len >> 8) & 0xFF;
    header[6] = len & 0xFF;

    write_all(session->conn, header, 7);

    uint8_t waste[len];
    memset(waste, 0, len);  // Or random data
    write_all(session->conn, waste, len);
}
```

### Padding MD5 Calculation

```c
#include <openssl/md5.h>

void calculate_padding_md5(const char *scheme_data, size_t len,
                           char *out_hex) {
    unsigned char md5[16];
    MD5((unsigned char*)scheme_data, len, md5);

    // Convert to lowercase hex
    for (int i = 0; i < 16; i++) {
        sprintf(out_hex + i*2, "%02x", md5[i]);
    }
    out_hex[32] = '\0';
}
```

**IMPORTANT:** Use raw bytes of scheme file, not parsed structure.
The scheme bytes must NOT have a trailing newline: the built-in scheme is
stored without a final `\n`, and its MD5 is what the reference client
ships as `padding-md5`.  A trailing newline changes the digest and makes
clients request an `CMD_UPDATE_PADDING` on every new session.

### Example: Packet 2 Breakdown

**Scheme:** `2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000`

**Data to send:** 1200 bytes of TLS ClientHello

**Process:**
1. Range 1: `400-500` → Random 450 bytes
   - Send 450 bytes of data
   - Remaining: 750 bytes
2. Check marker: 750 > 0, continue
3. Range 2: `500-1000` → Random 800 bytes
   - Send 750 bytes of data + 50 bytes CMD_WASTE
   - Remaining: 0 bytes
4. Check marker: 0 bytes, STOP

**Result:** Data split into 2 TLS records with padding

---

## Stream Multiplexing

### Session Structure

```c
typedef struct session {
    int tls_fd;                      // TLS connection
    hash_map_t *streams;             // stream_id → stream_t*
    uint32_t next_stream_id;         // Monotonic counter (client only)
    uint8_t peer_version;            // 1 or 2
    bool received_settings;          // CMD_SETTINGS received flag
    uint32_t pkt_counter;            // Padding packet counter
    padding_factory_t *padding;      // Padding scheme
    bool is_client;                  // Client vs server
} session_t;

typedef struct stream {
    session_t *session;              // Parent session
    uint32_t stream_id;              // Stream identifier
    pipe_t *read_pipe;               // Buffer for incoming PSH data
    pipe_t *write_pipe;              // Buffer for outgoing data
    bool handshake_complete;         // SYNACK received (v2 client)
} stream_t;
```

### Stream Lifecycle

#### Client Side

1. **Open Stream:**
```c
stream_t *open_stream(session_t *session) {
    uint32_t sid = session->next_stream_id++;

    // Send CMD_SYN
    uint8_t header[7] = {CMD_SYN, 0, 0, 0, 0, 0, 0};
    header[1] = (sid >> 24) & 0xFF;
    header[2] = (sid >> 16) & 0xFF;
    header[3] = (sid >> 8) & 0xFF;
    header[4] = sid & 0xFF;
    write_all(session->tls_fd, header, 7);

    // Create stream object
    stream_t *stream = create_stream(session, sid);
    hash_map_set(session->streams, sid, stream);

    // Wait for SYNACK (v2 only)
    if (session->peer_version >= 2) {
        wait_for_synack(stream, 3000);  // 3 second timeout
    }

    return stream;
}
```

2. **Send Destination:**
```c
void send_destination(stream_t *stream, const char *host, uint16_t port) {
    // Encode as SOCKS5 address
    uint8_t addr_buf[256];
    size_t addr_len = encode_socks_addr(addr_buf, host, port);

    // Send via CMD_PSH
    send_psh_frame(stream, addr_buf, addr_len);
}
```

3. **Bidirectional Copy:**
```c
// Write to stream → sends CMD_PSH
stream_write(stream, data, len);

// Read from stream → reads from CMD_PSH buffer
stream_read(stream, buffer, len);
```

4. **Close Stream:**
```c
void close_stream(stream_t *stream) {
    // Send CMD_FIN
    uint8_t header[7] = {CMD_FIN, 0, 0, 0, 0, 0, 0};
    // ... set stream_id ...
    write_all(stream->session->tls_fd, header, 7);

    // Remove from map
    hash_map_remove(stream->session->streams, stream->stream_id);

    // Free resources
    destroy_stream(stream);
}
```

#### Server Side

1. **Receive CMD_SYN:**
```c
case CMD_SYN:
    if (!session->received_settings) {
        send_alert(session, "client did not send its settings");
        return;
    }

    stream_t *stream = create_stream(session, stream_id);
    hash_map_set(session->streams, stream_id, stream);

    // Callback to application
    on_new_stream(stream);
    break;
```

2. **Read Destination:**
```c
void on_new_stream(stream_t *stream) {
    // Read SOCKS address from first PSH
    socks_addr_t dest;
    ssize_t n = stream_read(stream, &dest, sizeof(dest));
    if (n < 0) {
        send_synack_error(stream, "Failed to read destination");
        return;
    }

    // Parse address
    char host[256];
    uint16_t port;
    parse_socks_addr(&dest, host, &port);

    // Create outbound connection
    int outbound_fd = connect_tcp(host, port);
    if (outbound_fd < 0) {
        send_synack_error(stream, strerror(errno));
        close_stream(stream);
        return;
    }

    // Send SYNACK success
    send_synack_success(stream);

    // Bidirectional copy
    copy_bidirectional(stream, outbound_fd);
}
```

3. **Bidirectional Copy:**
```c
void copy_bidirectional(stream_t *stream, int outbound_fd) {
    // Thread 1: stream → outbound
    while ((n = stream_read(stream, buf, sizeof(buf))) > 0) {
        write_all(outbound_fd, buf, n);
    }

    // Thread 2: outbound → stream
    while ((n = read(outbound_fd, buf, sizeof(buf))) > 0) {
        send_psh_frame(stream, buf, n);
    }

    // Cleanup
    close(outbound_fd);
    close_stream(stream);
}
```

### Session Reuse

**Critical:** Session MUST stay alive after stream closes (for multiplexing)

```c
// WRONG - Don't close session when stream closes
void on_stream_close(stream_t *stream) {
    close_session(stream->session);  // ❌ WRONG
}

// CORRECT - Only close stream, keep session alive
void on_stream_close(stream_t *stream) {
    send_fin_frame(stream);
    remove_from_map(stream->session->streams, stream->stream_id);
    destroy_stream(stream);
    // Session continues, ready for new streams
}
```

---

## UDP over TCP (UoT)

UDP traffic is carried as datagrams inside a regular AnyTLS stream.  The
stream is opened like any TCP stream, then its payload is interpreted as
UDP datagrams.

### Opening a UoT Stream (v2)

1. Client sends `CMD_SYN` for a new stream id.
2. Client sends the destination of the first `CMD_PSH` as a SOCKS5
   address whose host is the marker domain `sp.v2.udp-over-tcp.arpa`
   (port is ignored, conventionally 443).  The server recognizes the
   marker, answers `CMD_SYNACK`, and switches the stream to UoT mode.
3. The client then sends its first payload:

```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  mode  | SOCKS5 addr    |   mode: 0 = packet, 1 = connect
+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `mode = 1` (**connect**): the following SOCKS5 address is the fixed UDP
  peer.  Subsequent payload is a sequence of datagrams, each
  `[2-byte BE length][datagram]`.  Responses are sent the same way
  (`[2-byte BE length][datagram]`, no address).
- `mode = 0` (**packet**): the following SOCKS5 address is the default
  peer, but every datagram carries its own address.  Responses are full
  UoT packets (address included).

### Opening a UoT Stream (v1)

Same as v2, but the marker domain is `sp.udp-over-tcp.arpa` and there is
no mode byte: payload starts directly with UoT packets.

### UoT Packet Format

```
 0      1                     N           N+1      N+2            N+2+P
+------+---------------------+-----------+--------+----------------------+
| atyp |     address         |   plen    |       payload (plen)         |
+------+---------------------+-----------+--------+----------------------+
```

- `atyp`: **1 byte, DIFFERENT from SOCKS5** — `0` = IPv4, `1` = IPv6,
  `2` = domain.  (SOCKS5 uses 1/3/4; UoT packets use 0/1/2.)
- `address`: IPv4 = 4 bytes + 2-byte BE port; IPv6 = 16 bytes + 2-byte BE
  port; domain = 1-byte length + name + 2-byte BE port.
- `plen`: 2-byte Big-Endian datagram payload length.
- `payload`: the UDP datagram (plen bytes).

### Server Behavior

- The server opens a real UDP socket per UoT stream, sends each datagram
  to the resolved peer, and echoes received datagrams back as UoT
  packets (connect mode: length-prefixed, no address).
- Domain peers are resolved asynchronously; datagrams for a domain that
  is still resolving are queued (bounded by `anytls_uot_pending_packets`
  and `anytls_uot_pending_bytes`) and flushed on resolution.
- A resolution failure drops only the packets of the failed domain.
- Idle UoT streams are reaped by `anytls_uot_idle_timeout`.

---

## Server Implementation Guide

### High-Level Flow

```c
int main() {
    // 1. Setup TLS server
    SSL_CTX *ctx = create_tls_context();
    int listen_fd = listen_tcp("::", 8443);

    while (1) {
        int client_fd = accept(listen_fd, NULL, NULL);

        // 2. TLS handshake
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) != 1) {
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        // 3. Handle connection
        handle_anytls_connection(ssl);
    }
}

void handle_anytls_connection(SSL *ssl) {
    // 4. Authentication
    uint8_t auth_hash[32];
    SSL_read(ssl, auth_hash, 32);

    if (!verify_password(auth_hash)) {
        fallback_http(ssl);  // Pretend to be HTTP server
        return;
    }

    uint16_t padding0_len;
    SSL_read(ssl, &padding0_len, 2);
    padding0_len = ntohs(padding0_len);

    uint8_t *padding0 = malloc(padding0_len);
    SSL_read(ssl, padding0, padding0_len);
    free(padding0);

    // 5. Session loop
    session_t *session = create_session(ssl);
    session_run(session);  // Blocks until session dies
    destroy_session(session);
}

void session_run(session_t *session) {
    while (1) {
        // Read frame header
        uint8_t header[7];
        if (SSL_read(session->ssl, header, 7) != 7) {
            break;  // Connection closed
        }

        uint8_t cmd = header[0];
        uint32_t sid = ntohl(*(uint32_t*)(header + 1));
        uint16_t len = ntohs(*(uint16_t*)(header + 5));

        // Read frame data
        uint8_t *data = NULL;
        if (len > 0) {
            data = malloc(len);
            SSL_read(session->ssl, data, len);
        }

        // Dispatch
        handle_frame(session, cmd, sid, data, len);

        free(data);
    }
}
```

### Critical Implementation Points

1. **Byte Order:** All multi-byte integers are Big-Endian
2. **Atomic Reads:** Always read full 7-byte header in one operation
3. **Settings First:** Reject CMD_SYN before CMD_SETTINGS
4. **Session Reuse:** Don't close session when stream closes
5. **Version Check:** Send CMD_SYNACK only to v2 clients
6. **Padding Counter:** Track per-session, starts after authentication
7. **Error Handling:** Send CMD_ALERT before closing session

---

## ngx_anytls Implementation Notes

### TLS Record Alignment (fingerprint hardening)

Server-to-client data (non-UoT streams) is capped at `16384 - 7 = 16377`
bytes per `CMD_PSH`: a frame header plus 16377 data bytes fits exactly one
TLS 1.2 record (16384 bytes).  Without the cap, a 16384-byte payload
would produce a final 28-byte residual record (5-byte header + 7-byte
frame header + 16-byte AEAD tag) that is a stable traffic fingerprint.
With the cap, payload sizes land exactly on record boundaries.

### Handshake Control Frames

`CMD_SERVER_SETTINGS` (after a v2 `CMD_SETTINGS`) and `CMD_SYNACK` (after
a stream open) are sent as standalone frames as the protocol requires;
they are never coalesced with data frames.  A v2 client waits up to 3
seconds for `CMD_SYNACK`; the server answers as soon as the outbound
connection result is known.

### Server-Side Directives (nginx stream)

| Directive | Default | Purpose |
|---|---|---|
| `anytls on` | off | enable the module on a stream server |
| `anytls_user <name> <password>` | — | named user credential, repeatable up to 64; requires `on` |
| `anytls_fallback <addr>` | — | fallback upstream for failed auth (replay + optional PROXY) |
| `anytls_fallback_proxy_protocol` | off | prepend PROXY header on fallback |
| `anytls_reject_plain_http` | on | answer plaintext HTTP probes with nginx 497/400/405 pages |
| `anytls_padding <file>` | built-in | padding scheme; file or built-in (no trailing newline) |
| `anytls_handshake_timeout` | 60s | max time from connect to auth completion |
| `anytls_upstream_connect_timeout` | 5s | outbound connect timeout |
| `anytls_fallback_connect_timeout` | 60s | fallback upstream connect timeout |
| `anytls_write_timeout` | 60s | control-frame write timeout |
| `anytls_uot_idle_timeout` | 300s | reap idle UoT streams |
| `anytls_max_streams` | 1024 | concurrent streams per session |
| `anytls_buffer_size` | 65535 | stream read buffer |
| `anytls_max_pending_output` / `input` | 8M / 8M | per-connection backlog budgets |

### Authentication Timing

- Hash match is cached per connection (`auth_hash_matched`), so a large
  auth padding (up to 65535 bytes) dribbled in slow chunks does not
  rescan the user set on every chunk.
- Fallback decisions are made only after the full 34-byte auth prefix
  (hash + padding0 length) is available.

---

## Protocol Constants

### Sizes

```c
#define PASSWORD_HASH_SIZE        32    // SHA256 output
#define FRAME_HEADER_SIZE          7    // cmd + sid + len
#define STREAM_ID_SIZE             4    // uint32
#define DATA_LENGTH_SIZE           2    // uint16
#define MAX_FRAME_DATA_SIZE    65535    // uint16 max
#define DEFAULT_PADDING0_SIZE     30    // From scheme 0=30-30
```

### Timeouts

```c
#define CONTROL_FRAME_WRITE_TIMEOUT    5000  // 5 seconds
#define SYNACK_WAIT_TIMEOUT            3000  // 3 seconds
#define IDLE_SESSION_TIMEOUT          30000  // 30 seconds (client)
```

### Limits

```c
#define MIN_STREAM_ID                  1     // StreamID starts at 1
#define MAX_STREAM_ID         0xFFFFFFFF     // uint32 max
#define PACKET_COUNTER_START           0     // First packet = 0
```

### Magic Values

```c
#define CHECK_MARK_CHAR         'c'          // Check marker in scheme
#define CHECK_MARK_VALUE        -1           // Internal representation
#define SYNACK_SUCCESS_LEN       0           // Empty data = success
```

---

## Version Negotiation

### Protocol Versions

- **v1:** Original protocol (commands 0-6)
- **v2:** Enhanced protocol (commands 0-10, adds SYNACK and heartbeat frames)

### Negotiation Flow

```
Client                              Server
  |                                    |
  |  TLS Handshake                     |
  |<---------------------------------->|
  |                                    |
  |  Authentication                    |
  |---------------------------------->|
  |                                    |
  |  CMD_SETTINGS (v=2)                |
  |---------------------------------->|
  |                                   |
  |                   CMD_SERVER_SETTINGS (v=2)
  |<----------------------------------|
  |                                    |
```

### Compatibility Matrix

| Client | Server | Result                                      |
|--------|--------|---------------------------------------------|
| v1     | v1     | v1 mode (no SYNACK, no heartbeat frames)   |
| v1     | v2     | v1 mode (server downgrades)                |
| v2     | v1     | v1 mode (no CMD_SERVER_SETTINGS received)  |
| v2     | v2     | v2 mode (SYNACK + passive heartbeat)       |

### Feature Detection

```c
// Server side
if (session->peer_version >= 2) {
    // Enable v2 features
    send_synack_enabled = true;
    send_server_settings(session);
} else {
    // Disable v2 features
    send_synack_enabled = false;
}
```

---

## Error Handling

### Authentication Errors

**Failure Modes:**
- Hash matches no configured user
- Missing padding0
- Truncated authentication packet

**Recommended Response (ngx_anytls):**
```c
if (!matched) {
    // Transparent fallback: replay the buffered plaintext bytes to the
    // configured fallback upstream (anti-detection).  With
    // anytls_fallback_proxy_protocol on, a PROXY header precedes the
    // replayed bytes.  If no fallback is configured, close silently.
    fallback_connection(replay = auth_bytes);
    return;
}
```

### Plaintext HTTP Probing (reject_plain_http)

A plaintext HTTP request sent to the TLS port (a common anti-detection
probe) is answered with the same pages a real nginx HTTPS server would
produce.  ngx_anytls registers on the SSL PREREAD phase and peeks without
consuming (up to 32 KB):

- `GET`/`POST`/`PUT`/`DELETE`/`OPTIONS`/`PATCH` with a complete request
  line and (for HTTP/1.1) a `Host` header → the **497** "plain HTTP
  request was sent to HTTPS port" page, byte-identical to nginx.
  HTTP/1.0 requests get the 497 page without a `Host` header.
- `CONNECT`/`TRACE` → **405** (after the same `Host` check; HTTP/1.1
  without `Host` gets 400).
- Everything else (HTTP/1.1 without `Host`, `HEAD`, HTTP/0.9, SSH/SMTP
  banners, malformed input) → the default **400** page.
- Input shorter than 7 bytes gets no answer (connection times out),
  matching nginx.

A normal AnyTLS client is unaffected: the TLS session proceeds to
authentication as usual.

### Protocol Errors

**CMD_SYN before CMD_SETTINGS:**
```c
if (!session->received_settings) {
    send_alert(session, "client did not send its settings");
    close_session(session);
    return;
}
```

**Invalid Stream ID:**
```c
stream_t *stream = find_stream(session, stream_id);
if (!stream) {
    // Silently discard (forward compatibility)
    free(data);
    return;
}
```

**Unknown Command:**
```c
default:
    // Reference server default branch assumes unknown command has no data.
    // Handle as header-only and continue without consuming declared payload.
    break;
```

### Network Errors

**Read/Write Failures:**
```c
if (SSL_read(ssl, buf, len) <= 0) {
    // Connection lost - close entire session
    close_all_streams(session);
    close_session(session);
    return;
}
```

**Stream Errors:**
```c
if (connect_to_destination(host, port) < 0) {
    // Send SYNACK with error message (v2)
    if (session->peer_version >= 2) {
        send_synack_error(stream, strerror(errno));
    }
    close_stream(stream);
    // Session continues
    return;
}
```

### Timeout Handling (v2)

**SYNACK Timeout:**
```c
// Client side
if (!wait_for_synack(stream, 3000)) {
    // Timeout - close stream and retry
    close_stream(stream);
    return NULL;
}
```

---

## Debugging Checklist

### Authentication Phase

- [ ] SHA256 hash calculation matches the reference client
- [ ] Password is UTF-8 encoded before hashing
- [ ] Hash comparison uses constant-time comparison
- [ ] Multi-user set comparison walks every configured user (no early exit)
- [ ] Auth hash match is cached per connection (padding wait does not rescan)
- [ ] Padding0 length is Big-Endian uint16
- [ ] Padding0 data is correctly skipped
- [ ] Fallback replays buffered plaintext to the configured upstream
- [ ] Fallback behavior doesn't leak authentication failure

### Frame Handling

- [ ] Frame header is 7 bytes exactly
- [ ] All multi-byte integers use Big-Endian encoding
- [ ] Stream ID extraction: `(header[1] << 24) | (header[2] << 16) | (header[3] << 8) | header[4]`
- [ ] Data length extraction: `(header[5] << 8) | header[6]`
- [ ] Full header read atomically (not byte-by-byte)
- [ ] Data buffer allocated for data_len bytes
- [ ] Frame data read completely before processing

### Command Processing

- [ ] CMD_SETTINGS handled before any CMD_SYN
- [ ] `received_settings` flag set after CMD_SETTINGS
- [ ] CMD_SYN rejected if settings not received
- [ ] Stream ID uniqueness enforced
- [ ] CMD_PSH writes to correct stream buffer
- [ ] CMD_FIN removes stream from map but doesn't close session
- [ ] CMD_WASTE data is discarded without processing

### Version 2 Features

- [ ] CMD_SERVER_SETTINGS sent only to v2 clients
- [ ] CMD_SYNACK sent after outbound connection attempt
- [ ] SYNACK has empty data on success
- [ ] SYNACK has error message on failure
- [ ] Heartbeat requests receive immediate response
- [ ] v1 clients don't receive v2-only commands

### Padding Implementation

- [ ] Padding MD5 calculated from raw scheme bytes
- [ ] MD5 output is lowercase hex (32 characters)
- [ ] Packet counter starts at 0
- [ ] Packet counter increments per TLS write
- [ ] Padding scheme correctly parsed
- [ ] Check markers ('c') handled properly
- [ ] CMD_UPDATE_PADDING sent when MD5 mismatch

### Stream Multiplexing

- [ ] Session stays alive after stream closes
- [ ] Multiple concurrent streams supported
- [ ] Stream map properly synchronized (if multi-threaded)
- [ ] Stream IDs don't collide
- [ ] Client generates monotonically increasing IDs
- [ ] Server uses client-provided IDs only

### UDP over TCP (UoT)

- [ ] Marker domain `sp.v2.udp-over-tcp.arpa` opens a UoT stream
- [ ] v2 mode byte (0 = packet, 1 = connect) parsed before the address
- [ ] UoT packet atyp (0/1/2) is distinct from SOCKS5 atyp (1/3/4)
- [ ] Datagram length is Big-Endian uint16
- [ ] Connect mode responses are length-prefixed without address
- [ ] Packet mode responses carry the full address
- [ ] Domain peers resolved asynchronously; pending queue bounded
- [ ] Idle UoT streams reaped by timer

### Plaintext Rejection

- [ ] Valid HTTP/1.1 request with Host gets the 497 page
- [ ] HTTP/1.0 without Host gets the 497 page
- [ ] CONNECT/TRACE get 405 after the Host check
- [ ] Everything else gets 400; input < 7 bytes gets no answer
- [ ] AnyTLS clients are unaffected (TLS proceeds to auth)

### Error Handling

- [ ] Network errors close session cleanly
- [ ] Stream errors don't crash session
- [ ] Unknown commands silently ignored
- [ ] Invalid stream IDs handled gracefully
- [ ] Alert messages sent before session close
- [ ] Timeouts prevent resource leaks

### Memory Safety

- [ ] All allocated buffers freed
- [ ] No buffer overflows in frame parsing
- [ ] No use-after-free when closing streams
- [ ] No memory leaks in session lifetime

### Wireshark Debugging

- [ ] TLS decryption works (with SSLKEYLOGFILE)
- [ ] First 32 bytes after TLS handshake are password hash
- [ ] Frame boundaries visible at 7-byte intervals
- [ ] Command values match expected enum
- [ ] Stream IDs consistent across frames
- [ ] Data lengths match actual data size

### Interoperability Testing

- [ ] Works with official anytls-go client
- [ ] v1 client compatibility maintained
- [ ] v2 client uses all v2 features
- [ ] Handles padding scheme updates
- [ ] Session reuse works correctly
- [ ] Multiple streams per session work

---

## Reference Implementation Locations

**Official Go Implementation:** `anytls-go`

**Key Files:**
- `proxy/session/frame.go` - Frame definitions
- `proxy/session/session.go` - Session logic (lines 173-364: Run loop)
- `proxy/session/stream.go` - Stream implementation
- `proxy/padding/padding.go` - Padding scheme
- `cmd/server/inbound_tcp.go` - Server authentication (lines 40-84)
- `docs/protocol.md` - Official protocol docs

**Version:** anytls/0.0.11 (Protocol v2)

---

## Quick Reference Card

### Frame Header Format
```
 0       1       2       3       4       5       6
+-------+-------+-------+-------+-------+-------+-------+
|  cmd  |       stream_id       |   data_length |
+-------+-------+-------+-------+-------+-------+-------+
```

### Authentication Format
```
 0                               32      34
+-------------------------------+-------+---------------+
|      SHA256(password)         | len16 |   padding0    |
+-------------------------------+-------+---------------+
```
The server compares the hash against its configured user set in
constant time (multi-user supported, up to 64 users).

### UoT Stream Open (v2)
```
first PSH: SOCKS5 addr(sp.v2.udp-over-tcp.arpa:443)
first payload: [mode 0|1][SOCKS5 addr]   mode 1 = connect, 0 = packet
connect data:  [len16][datagram]...
packet data:   [uot-atyp 0|1|2][addr][len16][datagram]...
```

### Command Quick Reference
```
0 = WASTE      - Discard padding
1 = SYN        - Open stream
2 = PSH        - Stream data
3 = FIN        - Close stream
4 = SETTINGS   - Client settings (MUST BE FIRST)
5 = ALERT      - Server error message
6 = UPDATE_PADDING - New padding scheme
7 = SYNACK     - Stream open ACK (v2)
8 = HEART_REQ  - Keepalive request (v2)
9 = HEART_RESP - Keepalive response (v2)
10= SRV_SETTINGS - Server version (v2)
```

### Settings Format
```
v=2
client=anytls/0.0.11
padding-md5=<32-char-lowercase-hex>
```

---

*End of Protocol Reference*
