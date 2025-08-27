const std = @import("std");
const net = std.net;
const posix = std.posix;

const xev = @import("xev");

const crypt = @import("crypt.zig");
const utils = @import("utils.zig");

pub const Server = struct {
    address: net.Address,
    allocator: std.mem.Allocator,
    tcp_listener: std.posix.socket_t = undefined,
    tcp_connections: TcpConnections = undefined,

    pub fn init(self: *Server) !void {
        const address = self.address;
        self.tcp_connections = TcpConnections.init(self.allocator);
        const tcp_listener = try posix.socket(address.any.family, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        errdefer posix.close(tcp_listener);
        try posix.setsockopt(tcp_listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        try posix.bind(tcp_listener, &address.any, address.getOsSockLen());
        const backlog = 128;
        try posix.listen(tcp_listener, backlog);
        std.debug.print("TCP server started on {}\n", .{address});
        self.tcp_listener = tcp_listener;
    }

    pub fn deinit(self: *Server) void {
        posix.close(self.tcp_listener);
        self.tcp_connections.deinit();
    }

    pub fn addConnection(self: *Server, connection: *TcpConnection) !void {
        try self.tcp_connections.put(connection.client_socket, connection);
    }

    pub fn removeConnection(self: *Server, socket: posix.socket_t, loop: *xev.Loop) void {
        const connection_entry = self.tcp_connections.fetchRemove(socket);
        if (connection_entry) |connection| {
            connection.value.deinit(loop);
            self.allocator.destroy(connection.value);
        }
    }
};

pub const TcpConnection = struct {
    server: *Server,

    client_read_completion: ?*ClientReadData = null,

    client_read_closed: bool = false,
    client_socket_closed: bool = false,
    client_writes: u64 = 0,
    client_address: net.Address,
    client_socket: posix.socket_t,
    client_stream_state: TcpClientStreamState = TcpClientStreamState.reading_salt,

    ciphertext_read_buf: [8192]u8 = undefined,
    ciphertext_buf: [16384]u8 = undefined,
    ciphertext_remaining_len: usize = 0,

    decryptor: crypt.Encryptor = undefined,

    target_read_completion: ?*TargetReadData = null,

    target_read_closed: bool = false,
    target_writes: u64 = 0,
    target_address: net.Address = undefined,
    target_socket: ?posix.socket_t = null,
    server_stream_state: TcpServerStreamState = TcpServerStreamState.writing_salt,

    target_read_buf: [8192]u8 = undefined,

    encryptor: crypt.Encryptor = undefined,

    pub fn deinit(self: *TcpConnection, loop: *xev.Loop) void {
        self.disconnectFromTarget();
        self.disconnectFromClient();
        if (self.target_read_completion != null) {
            std.debug.print("TCP schedule cancel target read\n", .{});
            const target_read_data = self.target_read_completion.?;
            self.target_read_completion = null;
            loop.add(&target_read_data.cancel_completion);
        }
    }

    pub fn read(self: *TcpConnection, ciphertext_len: usize, plaintext_buf: []u8) !usize {
        var plaintext_len: usize = 0;
        var ciphertext_idx: usize = 0;
        @memcpy(self.ciphertext_buf[self.ciphertext_remaining_len .. self.ciphertext_remaining_len + ciphertext_len], self.ciphertext_read_buf[0..ciphertext_len]);

        while (true) {
            const chunk_len = switch (self.client_stream_state) {
                .reading_salt => blk: {
                    const request_salt = self.ciphertext_buf[0..crypt.SALT_SIZE];
                    self.decryptor = crypt.Encryptor{ .salt = request_salt.* };
                    self.decryptor.init();
                    ciphertext_idx = crypt.SALT_SIZE;
                    self.client_stream_state = .reading_address;
                    break :blk crypt.SALT_SIZE;
                },

                .reading_address => blk: {
                    const decrypt_result = try self.decryptor.decryptChunk(self.ciphertext_buf[ciphertext_idx..], plaintext_buf);
                    const target_address = try utils.parseAddress(plaintext_buf[0..decrypt_result.plaintext_written]);
                    self.target_address = target_address;
                    ciphertext_idx += decrypt_result.ciphertext_read;
                    self.client_stream_state = .reading_chunk;
                    break :blk decrypt_result.plaintext_written;
                },

                .reading_chunk => blk: {
                    if (ciphertext_idx == ciphertext_len) {
                        self.ciphertext_remaining_len = 0;
                        break :blk 0;
                    }
                    if (ciphertext_idx + crypt.PAYLOAD_LENGTH_SIZE + crypt.TAG_SIZE >= ciphertext_len) {
                        const remaining_len = ciphertext_len - ciphertext_idx;
                        @memcpy(self.ciphertext_buf[0..remaining_len], self.ciphertext_buf[ciphertext_idx..ciphertext_len]);
                        self.ciphertext_remaining_len = remaining_len;
                        std.debug.print("PARTIAL CHUNK", .{});
                        break :blk 0;
                    }
                    const payload_length_data = self.ciphertext_buf[ciphertext_idx .. ciphertext_idx + crypt.PAYLOAD_LENGTH_SIZE + crypt.TAG_SIZE];
                    var payload_length_buf: [crypt.PAYLOAD_LENGTH_SIZE]u8 = undefined;
                    _ = try self.decryptor.decrypt(payload_length_data, payload_length_buf[0..]);
                    const payload_length = std.mem.readInt(u16, &payload_length_buf, .big);
                    ciphertext_idx += crypt.PAYLOAD_LENGTH_SIZE + crypt.TAG_SIZE;

                    if (ciphertext_idx + payload_length + crypt.TAG_SIZE <= ciphertext_len) {
                        const payload_data = self.ciphertext_buf[ciphertext_idx .. ciphertext_idx + payload_length + crypt.TAG_SIZE];
                        _ = try self.decryptor.decrypt(payload_data, plaintext_buf[plaintext_len..]);
                        ciphertext_idx += payload_length + crypt.TAG_SIZE;
                        plaintext_len += payload_length;
                        break :blk payload_length;
                    } else {
                        std.debug.print("PARTIAL CHUNK", .{});
                        ciphertext_idx -= crypt.PAYLOAD_LENGTH_SIZE + crypt.TAG_SIZE;
                        const remaining_len = ciphertext_len - ciphertext_idx;

                        std.mem.copyForwards(u8, self.ciphertext_buf[0..remaining_len], self.ciphertext_buf[ciphertext_idx..ciphertext_len]);
                        self.ciphertext_remaining_len = remaining_len;
                        break :blk 0;
                    }
                },
            };
            if (chunk_len == 0) {
                break;
            }
        }
        return plaintext_len;
    }

    pub fn write(self: *TcpConnection, plaintext_len: usize, ciphertext_buf: []u8) usize {
        var ciphertext_len: usize = 0;
        var plaintext_idx: usize = 0;

        while (true) {
            const chunk_len = switch (self.server_stream_state) {
                .writing_salt => blk: {
                    var response_salt: [crypt.SALT_SIZE]u8 = undefined;
                    std.crypto.random.bytes(&response_salt);
                    self.encryptor = crypt.Encryptor{ .salt = response_salt };
                    self.encryptor.init();

                    @memcpy(ciphertext_buf[0..crypt.SALT_SIZE], &response_salt);

                    ciphertext_len = crypt.SALT_SIZE;
                    self.server_stream_state = .writing_chunk;
                    break :blk crypt.SALT_SIZE;
                },

                .writing_chunk => blk: {
                    if (plaintext_idx == plaintext_len) {
                        break :blk 0;
                    }
                    const remaining_len = plaintext_len - plaintext_idx;
                    const next_chunk_len = @min(crypt.MAX_PAYLOAD_SIZE, remaining_len);
                    const length_bytes = std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(next_chunk_len)));

                    const encrypted_len_len = self.encryptor.encrypt(&length_bytes, ciphertext_buf[ciphertext_len..]);
                    ciphertext_len += encrypted_len_len;
                    const encrypted_data_len = self.encryptor.encrypt(
                        self.target_read_buf[plaintext_idx .. plaintext_idx + next_chunk_len],
                        ciphertext_buf[ciphertext_len..],
                    );
                    ciphertext_len += encrypted_data_len;
                    plaintext_idx += next_chunk_len;

                    break :blk ciphertext_len;
                },
            };
            if (chunk_len == 0) {
                break;
            }
        }
        return ciphertext_len;
    }

    pub fn connectToTarget(self: *TcpConnection) !bool {
        if (self.target_socket != null) {
            return false;
        }
        const target_stream = try net.tcpConnectToAddress(self.target_address);
        self.target_socket = target_stream.handle;
        return true;
    }

    pub fn disconnectFromClient(self: *TcpConnection) void {
        if (self.client_socket_closed) {
            return;
        }
        std.debug.print("Disconnected from client\n", .{});
        posix.close(self.client_socket);
        self.client_socket_closed = true;
    }

    pub fn disconnectFromTarget(self: *TcpConnection) void {
        if (self.target_socket == null) {
            return;
        }
        std.debug.print("Disconnected from target\n", .{});
        posix.close(self.target_socket.?);
        self.target_socket = null;
    }

    pub fn onClientReadClosed(self: *TcpConnection) void {
        self.client_read_closed = true;
        if (self.target_writes == 0) {
            std.debug.print("onClientReadClosed\n", .{});
            posix.shutdown(self.target_socket.?, .send) catch @panic("sht");
        }
    }

    pub fn onTargetWrite(self: *TcpConnection) void {
        self.target_writes -= 1;
        if (self.client_read_closed and self.target_writes == 0) {
            std.debug.print("onTargetWrite\n", .{});
            posix.shutdown(self.target_socket.?, .send) catch @panic("sht");
        }
    }

    pub fn onTargetReadClosed(self: *TcpConnection, _: *xev.Loop) void {
        self.disconnectFromTarget();
        self.target_read_closed = true;
        if (self.client_writes == 0) {
            std.debug.print("onTargetReadClosed\n", .{});
            self.disconnectFromClient();
            self.disconnectFromTarget();
        }
    }

    pub fn onClientWrite(self: *TcpConnection, _: *xev.Loop) void {
        self.client_writes -= 1;
        if (self.target_read_closed and self.client_writes == 0) {
            std.debug.print("onClientWrite\n", .{});
            self.disconnectFromClient();
            self.disconnectFromTarget();
        }
    }
};

pub const TcpClientStreamState = enum {
    reading_salt,
    reading_address,
    reading_chunk,
};

pub const TcpServerStreamState = enum {
    writing_salt,
    writing_chunk,
};

pub const TcpConnections = std.AutoHashMap(posix.socket_t, *TcpConnection);

pub const ClientReadData = struct {
    server: *Server,
    connection: *TcpConnection,
    completion: xev.Completion,
    cancel_completion: xev.Completion,
};

pub const TargetReadData = struct {
    server: *Server,
    client_socket: posix.socket_t,
    target_socket: posix.socket_t,
    completion: xev.Completion,
    cancel_completion: xev.Completion,
};
