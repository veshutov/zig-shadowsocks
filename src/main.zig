const std = @import("std");
const xev = @import("xev");

const Instant = std.time.Instant;
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const assert = std.debug.assert;

pub fn main() !void {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    // Create a TCP server socket
    const address = try net.Address.parseIp4("127.0.0.1", 3131);
    const kernel_backlog = 1;
    const ln = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(ln);
    try posix.setsockopt(ln, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(@as(c_int, 1)));
    try posix.bind(ln, &address.any, address.getOsSockLen());
    try posix.listen(ln, kernel_backlog);

    std.log.info("Listen on {any}", .{address});

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = general_purpose_allocator.allocator();
    var state = ServerState{
        .connections = ConnMap.init(gpa),
        .allocator = gpa,
    };

    // Accept
    var c_accept: xev.Completion = .{
        .op = .{ .accept = .{ .socket = ln } },
        .userdata = &state,
        .callback = acceptCallback,
    };
    loop.add(&c_accept);

    // Run the loop until there are no more completions.
    try loop.run(.until_done);
}

const ServerState = struct {
    connections: ConnMap,
    allocator: mem.Allocator,

    pub fn remove(self: *ServerState, fd: posix.socket_t) void {
        if (self.connections.fetchRemove(fd)) |pair| {
            pair.value.deinit();
        } else {
            std.log.warn("Attempted to remove non-existent connection: fd={}", .{fd});
        }
    }
};

const ConnMap = std.AutoHashMap(posix.socket_t, *Connection);

const Connection = struct {
    fd: posix.socket_t,
    read_buf: [4096]u8,
    write_buf: [4096]u8,
    comp: xev.Completion,

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
            .comp = undefined,
            .write_data = &[_]u8{},
            .write_offset = 0,
            .server_state = server_state,
        };
        return conn;
    }

    pub fn deinit(self: *Connection) void {
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
};
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

    std.log.info("New connection accepted: fd={}", .{new_fd});
    new_conn.read(loop);
    return .rearm;
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
        std.log.err("Recv failed: {}", .{err});
        conn.close(loop);
        return .disarm;
    };

    if (read_len == 0) {
        // Client closed connection
        std.log.info("Client closed connection: fd={}", .{conn.fd});
        conn.close(loop);
        return .disarm;
    }

    std.log.info(
        "Recv from {} ({} bytes)",
        .{ recv.fd, read_len },
    );

    // Echo the received data back
    conn.write(loop, recv.buffer.slice[0..read_len]);
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

    std.log.info("Send to {} ({} bytes)", .{ conn.fd, send_len });

    conn.write_offset += send_len;

    if (conn.write_offset >= conn.write_data.len) {
        // Complete write - all data has been sent
        std.log.info("Write complete for fd={}, starting read", .{conn.fd});
        conn.read(loop);
        return .disarm;
    } else {
        // Partial write - continue with remaining data
        std.log.info("Partial write for fd={}: sent {}/{} bytes, continuing...", .{ conn.fd, conn.write_offset, conn.write_data.len });
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
        std.log.err("Close failed: {}", .{err});
    };

    std.log.info("Connection closed: fd={}", .{conn.fd});
    conn.server_state.remove(comp.op.close.fd);
    return .disarm;
}
