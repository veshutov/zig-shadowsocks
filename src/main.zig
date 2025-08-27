const std = @import("std");
const net = std.net;
const posix = std.posix;

const xev = @import("xev");
const Completion = xev.Completion;

const crypt = @import("crypt.zig");
const server = @import("server.zig");
const Server = server.Server;
const TcpConnection = server.TcpConnection;
const utils = @import("utils.zig");

pub fn main() !void {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();
    const allocator = general_purpose_allocator.allocator();

    const address = try net.Address.parseIp("127.0.0.1", 8086);
    var srv = Server{ .allocator = allocator, .address = address };
    try srv.init();
    defer srv.deinit();

    const tcp_accept_completion = try allocator.create(Completion);
    defer allocator.destroy(tcp_accept_completion);
    tcp_accept_completion.* = .{
        .op = .{
            .accept = .{ .socket = srv.tcp_listener },
        },
        .userdata = &srv,
        .callback = tcpAcceptCallback,
    };
    loop.add(tcp_accept_completion);

    try loop.run(.until_done);
}

fn tcpAcceptCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const srv = @as(*Server, @ptrCast(@alignCast(ud.?)));
    const allocator = srv.allocator;

    const socket = result.accept catch |e| {
        std.log.err("TCP accept client failed: {}", .{e});
        return .disarm;
    };
    const client_address = net.Address.initPosix(@alignCast(&comp.op.accept.addr));
    // std.debug.print("TCP {} {} client connected\n", .{ client_address, socket });

    const connection = allocator.create(TcpConnection) catch |e| {
        std.debug.print("Could not allocate TCP connection {}\n", .{e});
        return .disarm;
    };
    connection.* = TcpConnection{
        .client_socket = socket,
        .client_address = client_address,
    };

    srv.addConnection(connection) catch |e| {
        std.debug.print("Could not add TCP connection {}\n", .{e});
        posix.close(socket);
        allocator.destroy(connection);
        return .disarm;
    };

    const tcp_client_read_completion = allocator.create(Completion) catch |e| {
        std.debug.print("Could not allocate TCP client read completion {}\n", .{e});
        srv.removeConnection(socket);
        return .disarm;
    };
    tcp_client_read_completion.* = .{
        .op = .{
            .read = .{
                .fd = socket,
                .buffer = .{
                    .slice = &connection.ciphertext_read_buf,
                },
            },
        },
        .callback = tcpClientReadCallback,
        .userdata = srv,
    };
    loop.add(tcp_client_read_completion);

    return .rearm;
}

fn tcpClientReadCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const srv = @as(*Server, @ptrCast(@alignCast(ud.?)));
    const read = comp.op.read;
    const socket = read.fd;
    const allocator = srv.allocator;
    const connection = srv.tcp_connections.get(socket).?;

    const read_len = result.read catch |e| {
        std.debug.print("TCP {} client disconnected {}\n", .{ connection.client_address, e });
        srv.removeConnection(socket);
        allocator.destroy(comp);
        return .disarm;
    };
    // std.debug.print("TCP client read {} bytes\n", .{read_len});

    const tcp_target_write_data = allocator.create(TargetWriteData) catch |e| {
        std.debug.print("Could not allocate TCP target write completion {}\n", .{e});
        srv.removeConnection(socket);
        allocator.destroy(comp);
        return .disarm;
    };
    tcp_target_write_data.* = TargetWriteData{
        .server = srv,
        .plaintext_buf = undefined,
        .completion = undefined,
    };

    const plaintext_len = connection.read(read_len, &tcp_target_write_data.plaintext_buf) catch |e| {
        std.debug.print("TCP could not decrypt client data {}\n", .{e});
        srv.removeConnection(socket);
        allocator.destroy(comp);
        allocator.destroy(tcp_target_write_data);
        return .disarm;
    };
    // std.debug.print("TCP client read {} text bytes\n", .{plaintext_len});

    const connected = connection.connectToTarget() catch |e| {
        std.debug.print("TCP could not connect to target {}\n", .{e});
        srv.removeConnection(socket);
        allocator.destroy(comp);
        allocator.destroy(tcp_target_write_data);
        return .disarm;
    };

    if (connected) {
        const tcp_target_read_data = allocator.create(TargetReadData) catch |e| {
            std.debug.print("Could not allocate TCP target read completion {}\n", .{e});
            srv.removeConnection(socket);
            allocator.destroy(comp);
            allocator.destroy(tcp_target_write_data);
            return .disarm;
        };
        tcp_target_read_data.* = TargetReadData{
            .server = srv,
            .client_socket = socket,
            .completion = .{
                .op = .{
                    .read = .{
                        .fd = connection.target_socket.?,
                        .buffer = .{
                            .slice = &connection.target_read_buf,
                        },
                    },
                },
                .callback = tcpTargetReadCallback,
                .userdata = tcp_target_read_data,
            },
        };
        loop.add(&tcp_target_read_data.completion);
    }

    tcp_target_write_data.completion = xev.Completion{
        .op = .{
            .write = .{
                .fd = connection.target_socket.?,
                .buffer = .{
                    .slice = tcp_target_write_data.plaintext_buf[0..plaintext_len],
                },
            },
        },
        .userdata = tcp_target_write_data,
        .callback = tcpTargetWriteCallback,
    };
    loop.add(&tcp_target_write_data.completion);

    return .rearm;
}

const TargetWriteData = struct {
    server: *Server,
    plaintext_buf: [16384]u8,
    completion: xev.Completion,
};

fn tcpTargetWriteCallback(
    ud: ?*anyopaque,
    _: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const data = @as(*TargetWriteData, @ptrCast(@alignCast(ud.?)));
    const srv = data.server;
    const allocator = srv.allocator;
    defer allocator.destroy(data);

    const write_len = result.write catch |e| {
        std.debug.print("TCP target write error {}\n", .{e});
        return .disarm;
    };
    const data_len = comp.op.write.buffer.slice.len;
    if (data_len > write_len) {
        std.debug.print("PARTIAL target write: {} {} \n", .{ write_len, data_len });
    }

    // std.debug.print("TCP target write {} bytes\n", .{write_len});
    return .disarm;
}

const TargetReadData = struct {
    server: *Server,
    client_socket: posix.socket_t,
    completion: xev.Completion,
};

fn tcpTargetReadCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const data = @as(*TargetReadData, @ptrCast(@alignCast(ud.?)));
    const srv = data.server;
    const connection = srv.tcp_connections.get(data.client_socket);
    const allocator = srv.allocator;
    if (connection == null) {
        std.debug.print("TCP connection not found", .{});
        allocator.destroy(data);
        return .disarm;
    }

    const read_len = result.read catch |e| {
        std.debug.print("TCP target read error {}\n", .{e});
        connection.?.disconnectFromTarget();
        allocator.destroy(data);
        return .disarm;
    };
    // std.debug.print("TCP target read {} bytes\n", .{read_len});

    const tcp_client_write_data = allocator.create(ClientWriteData) catch |e| {
        std.debug.print("Could not allocate TCP client write completion {}\n", .{e});
        connection.?.disconnectFromTarget();
        allocator.destroy(data);
        return .disarm;
    };
    tcp_client_write_data.* = ClientWriteData{
        .server = srv,
        .ciphertext = undefined,
        .completion = undefined,
    };
    const ciphertext_len = connection.?.write(read_len, &tcp_client_write_data.ciphertext);

    tcp_client_write_data.completion = .{
        .op = .{
            .write = .{
                .fd = connection.?.client_socket,
                .buffer = .{
                    .slice = tcp_client_write_data.ciphertext[0..ciphertext_len],
                },
            },
        },
        .callback = tcpClientWriteCallback,
        .userdata = tcp_client_write_data,
    };
    loop.add(&tcp_client_write_data.completion);

    return .rearm;
}

const ClientWriteData = struct {
    server: *Server,
    ciphertext: [16384]u8,
    completion: xev.Completion,
};

fn tcpClientWriteCallback(
    ud: ?*anyopaque,
    _: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const data = @as(*ClientWriteData, @ptrCast(@alignCast(ud.?)));
    const srv = data.server;
    const allocator = srv.allocator;
    defer allocator.destroy(data);

    const write_len = result.write catch |e| {
        std.debug.print("TCP client write error {}\n", .{e});
        return .disarm;
    };

    const data_len = comp.op.write.buffer.slice.len;
    if (data_len > write_len) {
        std.debug.print("PARTIAL client write: {} {} \n", .{ write_len, data_len });
    }

    // std.debug.print("TCP client write {} bytes\n", .{write_len});
    return .disarm;
}
