const std = @import("std");
const xev = @import("xev");
const crypto = std.crypto;
const mem = std.mem;
const net = std.net;
const posix = std.posix;

// Shadowsocks configuration
const SHADOWSOCKS_PASSWORD = "your-password-here"; // Make sure this matches your client
const AEAD_TAG_SIZE = 16;
const NONCE_SIZE = 12;
const SALT_SIZE = 32;

pub fn main() !void {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();
    const gpa = general_purpose_allocator.allocator();

    var state = ServerState{
        .connections = ConnMap.init(gpa),
        .udp_sessions = UdpSessionMap.init(gpa),
        .allocator = gpa,
    };
    defer {
        state.connections.deinit();
        state.udp_sessions.deinit();
    }

    // Create TCP server socket
    const tcp_address = try net.Address.parseIp4("127.0.0.1", 8388);
    const kernel_backlog = 128;
    const tcp_ln = try posix.socket(tcp_address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(tcp_ln);
    try posix.setsockopt(tcp_ln, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(@as(c_int, 1)));
    try posix.bind(tcp_ln, &tcp_address.any, tcp_address.getOsSockLen());
    try posix.listen(tcp_ln, kernel_backlog);

    // Create UDP server socket
    const udp_address = try net.Address.parseIp4("127.0.0.1", 8388);
    const udp_fd = try posix.socket(udp_address.any.family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(udp_fd);
    try posix.setsockopt(udp_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(@as(c_int, 1)));
    try posix.bind(udp_fd, &udp_address.any, udp_address.getOsSockLen());

    state.udp_fd = udp_fd;

    std.log.info("Shadowsocks server listening on TCP {any}", .{tcp_address});
    std.log.info("Shadowsocks server listening on UDP {any}", .{udp_address});

    // Accept TCP connections
    var c_accept: xev.Completion = .{
        .op = .{ .accept = .{ .socket = tcp_ln } },
        .userdata = &state,
        .callback = acceptCallback,
    };
    loop.add(&c_accept);

    // Start UDP receive
    var udp_handler = try gpa.create(UdpHandler);
    udp_handler.* = UdpHandler{
        .state = &state,
        .comp = undefined,
        .recv_buf = undefined,
        .client_addr = undefined,
        .client_addr_len = @sizeOf(posix.sockaddr),
    };

    udp_handler.startReceive(&loop);

    // Run the loop until there are no more completions.
    try loop.run(.until_done);
}

const ServerState = struct {
    connections: ConnMap,
    udp_sessions: UdpSessionMap,
    udp_fd: posix.socket_t = undefined,
    allocator: mem.Allocator,

    pub fn remove(self: *ServerState, fd: posix.socket_t) void {
        if (self.connections.fetchRemove(fd)) |pair| {
            // Close the target fd if it exists, but be careful about the main fd
            if (pair.value.target_fd) |target| {
                posix.close(target);
                pair.value.target_fd = null;
            }
            // Don't close the main fd here - it might already be closed
            self.allocator.destroy(pair.value);
        } else {
            std.log.warn("Attempted to remove non-existent connection: fd={}", .{fd});
        }
    }

    pub fn removeUdpSession(self: *ServerState, key: UdpSessionKey) void {
        if (self.udp_sessions.fetchRemove(key)) |pair| {
            pair.value.deinit();
        }
    }
};

const ConnMap = std.AutoHashMap(posix.socket_t, *Connection);

// UDP session management
const UdpSessionKey = struct {
    client_addr: net.Address,
    target_addr: net.Address,

    pub fn eql(self: UdpSessionKey, other: UdpSessionKey) bool {
        return self.client_addr.eql(other.client_addr) and self.target_addr.eql(other.target_addr);
    }

    pub fn hash(self: UdpSessionKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.client_addr));
        hasher.update(std.mem.asBytes(&self.target_addr));
        return hasher.final();
    }
};

const UdpSession = struct {
    key: UdpSessionKey,
    target_fd: posix.socket_t,
    master_key: [32]u8,
    subkey: [32]u8,
    nonce: [NONCE_SIZE]u8,
    last_activity: i64,
    state: *ServerState,
    comp: xev.Completion,
    recv_buf: [4096]u8,

    pub fn init(state: *ServerState, key: UdpSessionKey) !*UdpSession {
        const session = try state.allocator.create(UdpSession);

        // Create target socket
        const target_fd = try posix.socket(key.target_addr.any.family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);

        session.* = UdpSession{
            .key = key,
            .target_fd = target_fd,
            .master_key = undefined,
            .subkey = undefined,
            .nonce = std.mem.zeroes([NONCE_SIZE]u8),
            .last_activity = std.time.timestamp(),
            .state = state,
            .comp = undefined,
            .recv_buf = undefined,
        };

        // Derive master key using EVP_BytesToKey algorithm (MD5-based)
        evpBytesToKey(SHADOWSOCKS_PASSWORD, &session.master_key);

        return session;
    }

    pub fn deinit(self: *UdpSession) void {
        posix.close(self.target_fd);
        self.state.allocator.destroy(self);
    }

    pub fn deriveSubkey(self: *UdpSession, salt: []const u8) void {
        const hkdf = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.HmacSha1);
        const prk = hkdf.extract(salt, &self.master_key);
        hkdf.expand(&self.subkey, "ss-subkey", prk);
        self.nonce = std.mem.zeroes([NONCE_SIZE]u8);
    }

    pub fn decrypt(self: *UdpSession, ciphertext: []const u8, plaintext: []u8) !usize {
        if (ciphertext.len < AEAD_TAG_SIZE) return error.InvalidCiphertext;

        const data_len = ciphertext.len - AEAD_TAG_SIZE;
        if (data_len > plaintext.len) return error.BufferTooSmall;

        const data = ciphertext[0..data_len];
        const tag = ciphertext[data_len..][0..AEAD_TAG_SIZE];

        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(plaintext[0..data_len], data, tag.*, &[_]u8{}, // No additional data
            self.nonce, self.subkey) catch return error.DecryptionFailed;

        return data_len;
    }

    pub fn encrypt(self: *UdpSession, plaintext: []const u8, ciphertext: []u8) !usize {
        if (ciphertext.len < plaintext.len + AEAD_TAG_SIZE) return error.BufferTooSmall;

        const data = ciphertext[0..plaintext.len];
        const tag = ciphertext[plaintext.len..][0..AEAD_TAG_SIZE];

        @memcpy(data, plaintext);

        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(data, tag, plaintext, &[_]u8{}, // No additional data
            self.nonce, self.subkey);

        return plaintext.len + AEAD_TAG_SIZE;
    }

    pub fn startReceive(self: *UdpSession, loop: *xev.Loop) void {
        self.comp = .{
            .op = .{
                .recv = .{
                    .fd = self.target_fd,
                    .buffer = .{ .slice = &self.recv_buf },
                },
            },
            .userdata = self,
            .callback = udpTargetRecvCallback,
        };
        loop.add(&self.comp);
    }
};

const UdpSessionMap = std.HashMap(UdpSessionKey, *UdpSession, struct {
    pub fn hash(self: @This(), key: UdpSessionKey) u64 {
        _ = self;
        return key.hash();
    }
    pub fn eql(self: @This(), a: UdpSessionKey, b: UdpSessionKey) bool {
        _ = self;
        return a.eql(b);
    }
}, std.hash_map.default_max_load_percentage);

const UdpHandler = struct {
    state: *ServerState,
    comp: xev.Completion,
    recv_buf: [4096]u8,
    client_addr: posix.sockaddr,
    client_addr_len: posix.socklen_t,

    pub fn startReceive(self: *UdpHandler, loop: *xev.Loop) void {
        self.client_addr_len = @sizeOf(posix.sockaddr);
        self.comp = .{
            .op = .{
                .recvfrom = .{
                    .fd = self.state.udp_fd,
                    .buffer = .{ .slice = &self.recv_buf },
                    .addr = self.client_addr,
                    .addr_size = self.client_addr_len,
                },
            },
            .userdata = self,
            .callback = udpRecvCallback,
        };
        loop.add(&self.comp);
    }
};

const ConnectionState = enum {
    reading_salt,
    reading_length,
    reading_payload,
    connecting_target,
    relaying,
    target_relaying,
};

const Connection = struct {
    fd: posix.socket_t,
    target_fd: ?posix.socket_t = null,
    read_buf: [4096]u8,
    write_buf: [4096]u8,
    target_read_buf: [4096]u8,
    comp: xev.Completion,
    target_comp: xev.Completion,

    // Shadowsocks state
    state: ConnectionState = .reading_salt,
    master_key: [32]u8,
    salt: [SALT_SIZE]u8 = undefined,
    subkey: [32]u8 = undefined,
    nonce: [NONCE_SIZE]u8 = std.mem.zeroes([NONCE_SIZE]u8),
    target_nonce: [NONCE_SIZE]u8 = std.mem.zeroes([NONCE_SIZE]u8),
    expected_length: u16 = 0,
    bytes_read: usize = 0,

    // Write state tracking
    write_data: []const u8 = &[_]u8{},
    write_offset: usize = 0,

    server_state: *ServerState,

    pub fn init(server_state: *ServerState, new_fd: posix.socket_t) !*Connection {
        const conn = try server_state.allocator.create(Connection);
        conn.* = Connection{
            .fd = new_fd,
            .read_buf = undefined,
            .write_buf = undefined,
            .target_read_buf = undefined,
            .comp = undefined,
            .target_comp = undefined,
            .write_data = &[_]u8{},
            .write_offset = 0,
            .server_state = server_state,
            .master_key = undefined,
            .subkey = undefined,
        };

        // Derive master key using EVP_BytesToKey algorithm (MD5-based)
        evpBytesToKey(SHADOWSOCKS_PASSWORD, &conn.master_key);

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        if (self.target_fd) |target| {
            posix.close(target);
            self.target_fd = null;
        }
        // Don't close self.fd here - it should be handled by the close callback or is already closed
        self.server_state.allocator.destroy(self);
    }

    pub fn read(self: *Connection, loop: *xev.Loop) void {
        self.comp = .{
            .op = .{
                .recv = .{
                    .fd = self.fd,
                    .buffer = .{ .slice = &self.read_buf },
                },
            },
            .userdata = self,
            .callback = recvCallback,
        };
        loop.add(&self.comp);
    }

    pub fn readTarget(self: *Connection, loop: *xev.Loop) void {
        if (self.target_fd == null) return;

        self.target_comp = .{
            .op = .{
                .recv = .{
                    .fd = self.target_fd.?,
                    .buffer = .{ .slice = &self.target_read_buf },
                },
            },
            .userdata = self,
            .callback = targetRecvCallback,
        };
        loop.add(&self.target_comp);
    }

    pub fn write(self: *Connection, loop: *xev.Loop, data: []const u8) void {
        const copy_len = @min(data.len, self.write_buf.len);
        if (copy_len < data.len) {
            std.log.warn("Message truncated: {} bytes -> {} bytes", .{ data.len, copy_len });
        }
        @memcpy(self.write_buf[0..copy_len], data[0..copy_len]);

        self.write_data = self.write_buf[0..copy_len];
        self.write_offset = 0;
        self.writeInternal(loop);
    }

    fn writeInternal(self: *Connection, loop: *xev.Loop) void {
        const remaining = self.write_data[self.write_offset..];
        self.comp = .{
            .op = .{
                .send = .{
                    .fd = self.fd,
                    .buffer = .{ .slice = remaining },
                },
            },
            .userdata = self,
            .callback = sendCallback,
        };
        loop.add(&self.comp);
    }

    pub fn close(self: *Connection, loop: *xev.Loop) void {
        self.comp = .{
            .op = .{ .close = .{ .fd = self.fd } },
            .userdata = self,
            .callback = closeCallback,
        };
        loop.add(&self.comp);
    }

    fn deriveSubkey(self: *Connection) void {
        // Original Shadowsocks AEAD key derivation: HKDF-SHA1(salt, master_key, "ss-subkey", 32)
        const hkdf = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.HmacSha1);
        const prk = hkdf.extract(&self.salt, &self.master_key);
        hkdf.expand(&self.subkey, "ss-subkey", prk);

        // Reset nonces after deriving new subkey
        self.nonce = std.mem.zeroes([NONCE_SIZE]u8);
        self.target_nonce = std.mem.zeroes([NONCE_SIZE]u8);

        std.log.info("Derived subkey from salt: {any}", .{self.salt[0..8]});
        std.log.info("Subkey: {any}", .{self.subkey[0..8]});
    }

    fn decrypt(self: *Connection, ciphertext: []const u8, plaintext: []u8, nonce: *[NONCE_SIZE]u8) !usize {
        if (ciphertext.len < AEAD_TAG_SIZE) return error.InvalidCiphertext;

        const data_len = ciphertext.len - AEAD_TAG_SIZE;
        if (data_len > plaintext.len) return error.BufferTooSmall;

        const data = ciphertext[0..data_len];
        const tag = ciphertext[data_len..][0..AEAD_TAG_SIZE];

        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(plaintext[0..data_len], data, tag.*, &[_]u8{}, // No additional data
            nonce.*, self.subkey) catch return error.DecryptionFailed;

        // Increment nonce AFTER successful decryption
        incrementNonce(nonce);

        return data_len;
    }

    fn encrypt(self: *Connection, plaintext: []const u8, ciphertext: []u8, nonce: *[NONCE_SIZE]u8) !usize {
        if (ciphertext.len < plaintext.len + AEAD_TAG_SIZE) return error.BufferTooSmall;

        const data = ciphertext[0..plaintext.len];
        const tag = ciphertext[plaintext.len..][0..AEAD_TAG_SIZE];

        @memcpy(data, plaintext);

        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(data, tag, plaintext, &[_]u8{}, // No additional data
            nonce.*, self.subkey);

        // Increment nonce
        incrementNonce(nonce);

        return plaintext.len + AEAD_TAG_SIZE;
    }

    fn connectToTarget(self: *Connection, loop: *xev.Loop, address: net.Address) !void {
        const target_fd = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        self.target_fd = target_fd;
        self.state = .connecting_target;

        // Use async connect
        self.comp = .{
            .op = .{
                .connect = .{
                    .socket = target_fd,
                    .addr = address,
                },
            },
            .userdata = self,
            .callback = connectCallback,
        };
        loop.add(&self.comp);
    }
};

fn incrementNonce(nonce: *[NONCE_SIZE]u8) void {
    var carry: u16 = 1;
    for (0..nonce.len) |i| {
        carry += nonce[i];
        nonce[i] = @truncate(carry);
        carry >>= 8;
        if (carry == 0) break;
    }
}

// UDP callback functions
fn udpRecvCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const handler = @as(*UdpHandler, @ptrCast(@alignCast(ud.?)));
    const recv = comp.op.recvfrom;

    const read_len = result.recv catch |err| {
        std.log.err("UDP recv failed: {}", .{err});
        handler.startReceive(loop);
        return .disarm;
    };

    if (read_len == 0) {
        handler.startReceive(loop);
        return .disarm;
    }

    const data = recv.buffer.slice[0..read_len];
    const client_addr = net.Address.initPosix(@alignCast(&handler.client_addr));

    std.log.info("UDP packet received from {}: {} bytes", .{ client_addr, read_len });

    processUdpPacket(handler.state, loop, client_addr, data) catch |err| {
        std.log.err("Failed to process UDP packet: {}", .{err});
    };

    handler.startReceive(loop);
    return .disarm;
}

fn processUdpPacket(state: *ServerState, loop: *xev.Loop, client_addr: net.Address, data: []const u8) !void {
    if (data.len < SALT_SIZE + AEAD_TAG_SIZE + 1) {
        return error.PacketTooSmall;
    }

    // Extract salt and encrypted payload
    const salt = data[0..SALT_SIZE];
    const encrypted_payload = data[SALT_SIZE..];

    // Parse target address from encrypted payload
    var temp_session = UdpSession{
        .key = undefined,
        .target_fd = undefined,
        .master_key = undefined,
        .subkey = undefined,
        .nonce = std.mem.zeroes([NONCE_SIZE]u8),
        .last_activity = 0,
        .state = state,
        .comp = undefined,
        .recv_buf = undefined,
    };

    // Derive master key
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(SHADOWSOCKS_PASSWORD);
    hasher.final(&temp_session.master_key);

    // Derive subkey
    temp_session.deriveSubkey(salt);

    // Decrypt payload
    var decrypted_buf: [4096]u8 = undefined;
    const decrypted_len = temp_session.decrypt(encrypted_payload, &decrypted_buf) catch {
        std.log.err("Failed to decrypt UDP packet", .{});
        return;
    };

    // Parse target address
    const target_addr = parseAddress(decrypted_buf[0..decrypted_len]) catch {
        std.log.err("Failed to parse target address from UDP packet", .{});
        return;
    };

    const session_key = UdpSessionKey{
        .client_addr = client_addr,
        .target_addr = target_addr,
    };

    // Get or create session
    var session = state.udp_sessions.get(session_key);
    if (session == null) {
        const new_session = UdpSession.init(state, session_key) catch {
            std.log.err("Failed to create UDP session", .{});
            return;
        };
        new_session.deriveSubkey(salt);

        state.udp_sessions.put(session_key, new_session) catch {
            new_session.deinit();
            return;
        };

        session = new_session;
        new_session.startReceive(loop);
        std.log.info("Created new UDP session for {}", .{target_addr});
    }

    const sess = session.?;
    sess.last_activity = std.time.timestamp();

    // Extract actual payload (skip address header)
    const addr_header_len = getAddressHeaderLength(decrypted_buf[0..decrypted_len]);
    if (addr_header_len >= decrypted_len) {
        return error.InvalidAddressHeader;
    }

    const payload = decrypted_buf[addr_header_len..decrypted_len];

    // Send to target
    const send_comp = try state.allocator.create(xev.Completion);
    send_comp.* = .{
        .op = .{
            .sendto = .{
                .fd = sess.target_fd,
                .buffer = .{ .slice = payload },
                .addr = target_addr,
            },
        },
        .userdata = send_comp,
        .callback = udpSendCallback,
    };
    loop.add(send_comp);

    std.log.info("Forwarded UDP packet to {}: {} bytes", .{ target_addr, payload.len });
}

fn udpTargetRecvCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const session = @as(*UdpSession, @ptrCast(@alignCast(ud.?)));
    const recv = comp.op.recv;

    const read_len = result.recv catch |err| {
        std.log.err("UDP target recv failed: {}", .{err});
        session.startReceive(loop);
        return .disarm;
    };

    if (read_len == 0) {
        session.startReceive(loop);
        return .disarm;
    }

    const data = recv.buffer.slice[0..read_len];
    session.last_activity = std.time.timestamp();

    // Create response packet with address header + data
    var response_buf: [4096]u8 = undefined;
    const addr_header_len = createAddressHeader(&response_buf, session.key.target_addr) catch {
        std.log.err("Failed to create address header", .{});
        session.startReceive(loop);
        return .disarm;
    };

    // Copy payload after address header
    const total_len = addr_header_len + data.len;
    if (total_len > response_buf.len) {
        std.log.err("Response packet too large", .{});
        session.startReceive(loop);
        return .disarm;
    }
    @memcpy(response_buf[addr_header_len..total_len], data);

    // Encrypt response
    var encrypted_buf: [4096 + AEAD_TAG_SIZE]u8 = undefined;
    const encrypted_len = session.encrypt(response_buf[0..total_len], &encrypted_buf) catch {
        std.log.err("Failed to encrypt UDP response", .{});
        session.startReceive(loop);
        return .disarm;
    };

    // Send back to client
    const send_comp = session.state.allocator.create(xev.Completion) catch {
        std.log.err("Failed to allocate send completion", .{});
        session.startReceive(loop);
        return .disarm;
    };

    send_comp.* = .{
        .op = .{
            .sendto = .{
                .fd = session.state.udp_fd,
                .buffer = .{ .slice = encrypted_buf[0..encrypted_len] },
                .addr = session.key.client_addr,
            },
        },
        .userdata = send_comp,
        .callback = udpSendCallback,
    };
    loop.add(send_comp);

    std.log.info("Sent UDP response to client: {} bytes", .{encrypted_len});
    session.startReceive(loop);
    return .disarm;
}

fn udpSendCallback(
    ud: ?*anyopaque,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const send_comp = @as(*xev.Completion, @ptrCast(@alignCast(ud.?)));

    _ = result.send catch |err| {
        std.log.err("UDP send failed: {}", .{err});
    };

    // Free the completion
    const allocator = std.heap.page_allocator; // This is a hack - in real code you'd pass the allocator
    allocator.destroy(send_comp);

    return .disarm;
}

fn createAddressHeader(buf: []u8, addr: net.Address) !usize {
    switch (addr.any.family) {
        posix.AF.INET => {
            if (buf.len < 7) return error.BufferTooSmall;
            buf[0] = 1; // IPv4
            const ip4 = addr.in;
            @memcpy(buf[1..5], std.mem.asBytes(&ip4.sa.addr));
            std.mem.writeInt(u16, buf[5..7], addr.getPort(), .big);
            return 7;
        },
        posix.AF.INET6 => {
            if (buf.len < 19) return error.BufferTooSmall;
            buf[0] = 4; // IPv6
            const ip6 = addr.in6;
            @memcpy(buf[1..17], std.mem.asBytes(&ip6.sa.addr));
            std.mem.writeInt(u16, buf[17..19], addr.getPort(), .big);
            return 19;
        },
        else => return error.UnsupportedAddressFamily,
    }
}

// TCP callback functions (unchanged)
fn acceptCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const new_fd = result.accept catch |err| {
        std.log.err("Accept failed: {}", .{err});
        return .rearm;
    };

    var state = @as(*ServerState, @ptrCast(@alignCast(ud.?)));

    const new_conn = Connection.init(state, new_fd) catch |err| {
        posix.close(new_fd);
        std.log.err("Failed to create connection: {}", .{err});
        return .rearm;
    };

    state.connections.put(new_fd, new_conn) catch |err| {
        new_conn.deinit();
        std.log.err("Failed to store connection: {}", .{err});
        return .rearm;
    };

    std.log.info("New Shadowsocks connection accepted: fd={}", .{new_fd});
    new_conn.read(loop);
    return .rearm;
}

fn connectCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const conn = @as(*Connection, @ptrCast(@alignCast(ud.?)));

    _ = result.connect catch |err| {
        std.log.err("Connect to target failed: {}", .{err});
        conn.close(loop);
        return .disarm;
    };

    std.log.info("Connected to target successfully", .{});
    conn.state = .relaying;

    // Send any initial payload that was stored
    if (conn.bytes_read > 0) {
        std.log.info("Sending {} bytes of initial payload to target", .{conn.bytes_read});
        conn.target_comp = .{
            .op = .{
                .send = .{
                    .fd = conn.target_fd.?,
                    .buffer = .{ .slice = conn.target_read_buf[0..conn.bytes_read] },
                },
            },
            .userdata = conn,
            .callback = initialPayloadSendCallback,
        };
        loop.add(&conn.target_comp);
        conn.bytes_read = 0; // Reset
    } else {
        // Start reading from both client and target
        std.log.info("No initial payload, starting relay", .{});
        conn.read(loop);
        conn.readTarget(loop);
    }

    return .disarm;
}

fn initialPayloadSendCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const conn = @as(*Connection, @ptrCast(@alignCast(ud.?)));

    const sent_len = result.send catch |err| {
        std.log.err("Initial payload send failed: {}", .{err});
        conn.close(loop);
        return .disarm;
    };

    std.log.info("Sent {} bytes of initial payload to target", .{sent_len});

    // Now start reading from both client and target
    conn.read(loop);
    conn.readTarget(loop);

    return .disarm;
}

fn recvCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const recv = comp.op.recv;
    const conn = @as(*Connection, @ptrCast(@alignCast(ud.?)));

    const read_len = result.recv catch |err| {
        if (err == error.EOF) {
            std.log.info("Client closed connection (EOF): fd={}", .{conn.fd});
            // Don't try to close again, just clean up the connection state
            conn.server_state.remove(conn.fd);
            return .disarm;
        }
        std.log.err("Recv failed: {}", .{err});
        conn.close(loop);
        return .disarm;
    };

    if (read_len == 0) {
        std.log.info("Client closed connection: fd={}", .{conn.fd});
        conn.server_state.remove(conn.fd);
        return .disarm;
    }

    const data = recv.buffer.slice[0..read_len];
    std.log.info("Received {} bytes from client in state: {}", .{ read_len, conn.state });

    switch (conn.state) {
        .reading_salt => {
            const bytes_needed = SALT_SIZE - conn.bytes_read;
            const copy_len = @min(bytes_needed, read_len);

            std.log.info("Salt progress: {}/{} bytes, copying {} bytes", .{ conn.bytes_read, SALT_SIZE, copy_len });

            @memcpy(conn.salt[conn.bytes_read .. conn.bytes_read + copy_len], data[0..copy_len]);
            conn.bytes_read += copy_len;

            if (conn.bytes_read >= SALT_SIZE) {
                conn.deriveSubkey();
                conn.bytes_read = 0;
                conn.state = .reading_length;
                std.log.info("Salt received, derived subkey, waiting for length", .{});

                // Process remaining data if any
                if (copy_len < read_len) {
                    const remaining = data[copy_len..];
                    std.log.info("Processing {} remaining bytes after salt", .{remaining.len});
                    if (remaining.len >= 2 + AEAD_TAG_SIZE) {
                        return processLengthData(conn, loop, remaining);
                    }
                }
            } else {
                std.log.info("Need {} more bytes for salt, continuing to read...", .{SALT_SIZE - conn.bytes_read});
            }

            // Always continue reading
            conn.read(loop);
        },

        .reading_length => {
            std.log.info("Processing length data: {} bytes", .{data.len});
            return processLengthData(conn, loop, data);
        },

        .reading_payload => {
            std.log.info("Processing payload data: {} bytes", .{data.len});
            return processPayloadData(conn, loop, data);
        },

        .relaying => {
            std.log.info("Processing relay data: {} bytes", .{data.len});
            return processRelayData(conn, loop, data);
        },

        else => {
            std.log.warn("Unexpected state: {}", .{conn.state});
            conn.read(loop);
        },
    }

    return .disarm;
}

fn processLengthData(conn: *Connection, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    if (data.len >= 2 + AEAD_TAG_SIZE) {
        var length_buf: [2]u8 = undefined;
        const decrypted_len = conn.decrypt(data[0 .. 2 + AEAD_TAG_SIZE], &length_buf, &conn.nonce) catch {
            std.log.err("Failed to decrypt length", .{});
            conn.close(loop);
            return .disarm;
        };

        if (decrypted_len != 2) {
            std.log.err("Invalid length field: got {} bytes, expected 2", .{decrypted_len});
            conn.close(loop);
            return .disarm;
        }

        conn.expected_length = std.mem.readInt(u16, &length_buf, .big);
        conn.state = .reading_payload;
        std.log.info("Expected payload length: {}", .{conn.expected_length});

        // Process remaining data if any
        const consumed = 2 + AEAD_TAG_SIZE;
        if (data.len > consumed) {
            return processPayloadData(conn, loop, data[consumed..]);
        }
    }
    conn.read(loop);
    return .disarm;
}

fn processPayloadData(conn: *Connection, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    const expected_encrypted_len = conn.expected_length + AEAD_TAG_SIZE;
    if (data.len >= expected_encrypted_len) {
        var payload_buf: [4096]u8 = undefined;
        const decrypted_len = conn.decrypt(data[0..expected_encrypted_len], &payload_buf, &conn.nonce) catch {
            std.log.err("Failed to decrypt payload", .{});
            conn.close(loop);
            return .disarm;
        };

        const address = parseAddress(payload_buf[0..decrypted_len]) catch {
            std.log.err("Failed to parse target address", .{});
            conn.close(loop);
            return .disarm;
        };

        std.log.info("Connecting to target: {}", .{address});

        // Check if there's initial payload after the address
        const addr_header_len = getAddressHeaderLength(payload_buf[0..decrypted_len]);
        if (addr_header_len < decrypted_len) {
            // There's initial payload, store it
            const initial_payload = payload_buf[addr_header_len..decrypted_len];
            const copy_len = @min(initial_payload.len, conn.target_read_buf.len);
            @memcpy(conn.target_read_buf[0..copy_len], initial_payload);
            conn.bytes_read = copy_len; // Store initial payload length
            std.log.info("Found {} bytes of initial payload in address packet", .{copy_len});
        } else {
            conn.bytes_read = 0; // No initial payload
        }

        // Also check if there's more encrypted data after the address packet
        const consumed = expected_encrypted_len;
        if (data.len > consumed) {
            const remaining = data[consumed..];
            std.log.info("Found {} bytes of additional encrypted data after address", .{remaining.len});

            // Try to decrypt the next chunk
            if (remaining.len >= 2 + AEAD_TAG_SIZE) {
                // This might be a length chunk for more data
                var length_buf: [2]u8 = undefined;
                const length_decrypted = conn.decrypt(remaining[0 .. 2 + AEAD_TAG_SIZE], &length_buf, &conn.nonce) catch {
                    std.log.warn("Could not decrypt additional length chunk, ignoring", .{});
                    conn.connectToTarget(loop, address) catch {
                        conn.close(loop);
                        return .disarm;
                    };
                    return .disarm;
                };

                if (length_decrypted == 2) {
                    const next_payload_len = std.mem.readInt(u16, &length_buf, .big);
                    std.log.info("Next payload length: {}", .{next_payload_len});

                    const next_encrypted_len = next_payload_len + AEAD_TAG_SIZE;
                    const next_start = 2 + AEAD_TAG_SIZE;

                    if (remaining.len >= next_start + next_encrypted_len) {
                        // We have the complete next payload
                        var next_payload_buf: [4096]u8 = undefined;
                        const next_decrypted_len = conn.decrypt(remaining[next_start .. next_start + next_encrypted_len], &next_payload_buf, &conn.nonce) catch {
                            std.log.warn("Could not decrypt additional payload chunk", .{});
                            conn.connectToTarget(loop, address) catch {
                                conn.close(loop);
                                return .disarm;
                            };
                            return .disarm;
                        };

                        std.log.info("Decrypted additional {} bytes of payload", .{next_decrypted_len});

                        // Append this to our initial payload
                        if (conn.bytes_read + next_decrypted_len <= conn.target_read_buf.len) {
                            @memcpy(conn.target_read_buf[conn.bytes_read .. conn.bytes_read + next_decrypted_len], next_payload_buf[0..next_decrypted_len]);
                            conn.bytes_read += next_decrypted_len;
                            std.log.info("Total initial payload: {} bytes", .{conn.bytes_read});
                        }
                    }
                }
            }
        }

        conn.connectToTarget(loop, address) catch {
            conn.close(loop);
            return .disarm;
        };
        return .disarm;
    }
    conn.read(loop);
    return .disarm;
}

fn processRelayData(conn: *Connection, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    if (conn.target_fd) |target_fd| {
        var decrypted_buf: [4096]u8 = undefined;
        const decrypted_len = conn.decrypt(data, &decrypted_buf, &conn.nonce) catch {
            std.log.err("Failed to decrypt relay data", .{});
            conn.close(loop);
            return .disarm;
        };

        std.log.info("Decrypted {} bytes, forwarding to target", .{decrypted_len});

        // Copy to target_read_buf for persistent storage during async send
        const copy_len = @min(decrypted_len, conn.target_read_buf.len);
        @memcpy(conn.target_read_buf[0..copy_len], decrypted_buf[0..copy_len]);

        // Forward to target (async send)
        conn.target_comp = .{
            .op = .{
                .send = .{
                    .fd = target_fd,
                    .buffer = .{ .slice = conn.target_read_buf[0..copy_len] },
                },
            },
            .userdata = conn,
            .callback = targetSendCallback,
        };
        loop.add(&conn.target_comp);

        return .disarm;
    }
    conn.read(loop);
    return .disarm;
}

fn targetRecvCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const recv = comp.op.recv;
    const conn = @as(*Connection, @ptrCast(@alignCast(ud.?)));

    const read_len = result.recv catch |err| {
        if (err == error.EOF) {
            std.log.info("Target closed connection (EOF)", .{});
            conn.server_state.remove(conn.fd);
            return .disarm;
        }
        std.log.err("Target recv failed: {}", .{err});
        conn.close(loop);
        return .disarm;
    };

    if (read_len == 0) {
        std.log.info("Target closed connection", .{});
        conn.server_state.remove(conn.fd);
        return .disarm;
    }

    const data = recv.buffer.slice[0..read_len];
    std.log.info("Received {} bytes from target, encrypting and sending to client", .{read_len});

    // Encrypt and send back to client
    var encrypted_buf: [4096 + AEAD_TAG_SIZE]u8 = undefined;
    const encrypted_len = conn.encrypt(data, &encrypted_buf, &conn.target_nonce) catch {
        std.log.err("Failed to encrypt target data", .{});
        conn.close(loop);
        return .disarm;
    };

    std.log.info("Encrypted {} bytes, sending to client", .{encrypted_len});
    conn.write(loop, encrypted_buf[0..encrypted_len]);

    // Continue reading from target
    conn.readTarget(loop);

    return .disarm;
}

fn targetSendCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const conn = @as(*Connection, @ptrCast(@alignCast(ud.?)));

    const sent_len = result.send catch |err| {
        std.log.err("Target send failed: {}", .{err});
        conn.close(loop);
        return .disarm;
    };

    std.log.info("Sent {} bytes to target", .{sent_len});

    // Continue reading from client
    conn.read(loop);
    return .disarm;
}

fn sendCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const conn = @as(*Connection, @ptrCast(@alignCast(ud.?)));

    const send_len = result.send catch |err| {
        std.log.err("Send failed: {}", .{err});
        conn.close(loop);
        return .disarm;
    };

    conn.write_offset += send_len;

    if (conn.write_offset >= conn.write_data.len) {
        // Write complete, continue with normal operation
        if (conn.state == .relaying) {
            conn.read(loop);
        }
        return .disarm;
    } else {
        conn.writeInternal(loop);
        return .disarm;
    }
}

fn closeCallback(
    ud: ?*anyopaque,
    _: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const conn = @as(*Connection, @ptrCast(@alignCast(ud.?)));

    _ = result.close catch |err| {
        // Only log non-BADF errors since BADF means it was already closed
        if (err != error.BadFileDescriptor) {
            std.log.err("Close failed: {}", .{err});
        }
    };

    const fd = comp.op.close.fd;
    std.log.info("Shadowsocks connection closed: fd={}", .{fd});

    // Clean up connection without trying to close the fd again
    if (conn.server_state.connections.fetchRemove(fd)) |pair| {
        // Close target fd if it exists
        if (pair.value.target_fd) |target| {
            posix.close(target);
        }
        conn.server_state.allocator.destroy(pair.value);
    }

    return .disarm;
}

fn parseAddress(payload: []const u8) !net.Address {
    if (payload.len < 1) return error.InvalidPayload;

    const atyp = payload[0];

    switch (atyp) {
        1 => { // IPv4
            if (payload.len < 7) return error.InvalidIPv4Address;
            const ip = payload[1..5];
            const port = std.mem.readInt(u16, payload[5..7], .big);
            return net.Address.initIp4(ip.*, port);
        },
        3 => { // Domain name
            if (payload.len < 2) return error.InvalidDomainAddress;
            const domain_len = payload[1];
            if (payload.len < 2 + domain_len + 2) return error.InvalidDomainLength;

            const domain = payload[2 .. 2 + domain_len];
            const port_bytes = payload[2 + domain_len .. 2 + domain_len + 2];
            const port = std.mem.readInt(u16, port_bytes[0..2], .big);

            std.log.info("Resolving domain: {s}:{}", .{ domain, port });

            // Use std.net.getAddressList for DNS resolution
            const allocator = std.heap.page_allocator;
            const domain_str = allocator.dupe(u8, domain) catch return error.OutOfMemory;
            defer allocator.free(domain_str);

            const address_list = std.net.getAddressList(allocator, domain_str, port) catch {
                std.log.err("Failed to resolve domain: {s}", .{domain});
                return error.DomainResolutionFailed;
            };
            defer address_list.deinit();

            if (address_list.addrs.len > 0) {
                const resolved_addr = address_list.addrs[0];
                std.log.info("Resolved {s}:{} to {}", .{ domain, port, resolved_addr });
                return resolved_addr;
            }

            return error.DomainResolutionFailed;
        },
        4 => { // IPv6
            if (payload.len < 19) return error.InvalidIPv6Address;
            const ip = payload[1..17];
            const port = std.mem.readInt(u16, payload[17..19], .big);
            return net.Address.initIp6(ip.*, port, 0, 0);
        },
        else => return error.UnsupportedAddressType,
    }
}

fn evpBytesToKey(password: []const u8, key: *[32]u8) void {
    var hasher = crypto.hash.Md5.init(.{});
    var result: [16]u8 = undefined;
    var key_len: usize = 0;

    // First round
    hasher.update(password);
    hasher.final(&result);
    const copy_len1 = @min(result.len, key.len);
    @memcpy(key[0..copy_len1], result[0..copy_len1]);
    key_len += copy_len1;

    // Second round if we need more bytes
    if (key_len < key.len) {
        hasher = crypto.hash.Md5.init(.{});
        hasher.update(&result);
        hasher.update(password);
        hasher.final(&result);
        const remaining = key.len - key_len;
        const copy_len2 = @min(result.len, remaining);
        @memcpy(key[key_len .. key_len + copy_len2], result[0..copy_len2]);
    }
}

fn getAddressHeaderLength(data: []const u8) usize {
    if (data.len < 1) return 0;

    const atyp = data[0];
    switch (atyp) {
        1 => return 7, // IPv4: 1 + 4 + 2
        3 => {
            if (data.len < 2) return 0;
            return 2 + data[1] + 2; // Domain: 1 + len + domain + 2
        },
        4 => return 19, // IPv6: 1 + 16 + 2
        else => return 0,
    }
}
