const std = @import("std");
const net = std.net;
const posix = std.posix;

const xev = @import("xev");

const crypt = @import("crypt.zig");
const server = @import("server.zig");
const Server = server.Server;
const TcpConnection = server.TcpConnection;
const TargetReadData = server.TargetReadData;
const ClientReadData = server.ClientReadData;
const utils = @import("utils.zig");

pub fn main() !void {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();
    const allocator = general_purpose_allocator.allocator();

    const address = try net.Address.parseIp("0.0.0.0", 8086);
    var srv = Server{ .allocator = allocator, .address = address };
    try srv.init();
    defer srv.deinit();

    const tcp_accept_completion = try allocator.create(xev.Completion);
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
    std.debug.print("TCP {} {} client connected, active:{}\n", .{ client_address, socket, loop.active });

    const connection = allocator.create(TcpConnection) catch |e| {
        std.debug.print("Could not allocate TCP connection {}\n", .{e});
        return .disarm;
    };
    connection.* = TcpConnection{
        .server = srv,
        .client_socket = socket,
        .client_address = client_address,
    };

    srv.addConnection(connection) catch |e| {
        std.debug.print("Could not add TCP connection {}\n", .{e});
        posix.close(socket);
        allocator.destroy(connection);
        return .disarm;
    };

    const tcp_client_read_completion = allocator.create(ClientReadData) catch |e| {
        std.debug.print("Could not allocate TCP client read completion {}\n", .{e});
        srv.removeConnection(socket, loop);
        return .disarm;
    };
    tcp_client_read_completion.* = ClientReadData{
        .server = srv,
        .connection = connection,
        .completion = .{
            .op = .{
                .read = .{
                    .fd = socket,
                    .buffer = .{
                        .slice = &connection.ciphertext_read_buf,
                    },
                },
            },
            .callback = tcpClientReadCallback,
            .userdata = tcp_client_read_completion,
        },
        .cancel_completion = .{
            .op = .{
                // .close = .{
                //     .fd = connection.client_socket,
                // },
                .shutdown = .{
                    .how = .both,
                    .socket = connection.client_socket,
                },
            },
        },
    };
    loop.add(&tcp_client_read_completion.completion);
    connection.client_read_completion = tcp_client_read_completion;

    return .rearm;
}

fn tcpClientReadCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const data = @as(*ClientReadData, @ptrCast(@alignCast(ud.?)));
    const srv = data.server;
    const read = comp.op.read;
    const socket = read.fd;
    const allocator = srv.allocator;
    const connection_opt = srv.tcp_connections.get(socket);

    if (connection_opt == null) {
        std.debug.print("TCP connection not found in client read", .{});
        allocator.destroy(data);
        return .disarm;
    }
    const connection = connection_opt.?;

    const read_len = result.read catch |e| {
        std.debug.print("TCP {} {} client disconnected {}\n", .{ connection.client_address, connection.client_socket, e });
        if (e == xev.ReadError.EOF) {
            connection.onClientReadClosed();
        } else {
            srv.removeConnection(socket, loop);
        }
        allocator.destroy(data);
        return .disarm;
    };
    // std.debug.print("TCP client read {} bytes\n", .{read_len});

    const tcp_target_write_data = allocator.create(TargetWriteData) catch |e| {
        std.debug.print("Could not allocate TCP target write completion {}\n", .{e});
        srv.removeConnection(socket, loop);
        allocator.destroy(data);
        return .disarm;
    };
    tcp_target_write_data.* = TargetWriteData{
        .server = srv,
        .connection = connection,
        .plaintext_buf = undefined,
        .completion = undefined,
    };

    const plaintext_len = connection.read(read_len, &tcp_target_write_data.plaintext_buf) catch |e| {
        std.debug.print("TCP could not decrypt client data {}\n", .{e});
        srv.removeConnection(socket, loop);
        allocator.destroy(data);
        allocator.destroy(tcp_target_write_data);
        return .disarm;
    };
    // std.debug.print("TCP client read text {s}\n", .{tcp_target_write_data.plaintext_buf[0..plaintext_len]});

    const connected = connection.connectToTarget() catch |e| {
        std.debug.print("TCP could not connect to target {} {} {}\n", .{ connection.target_address, connection.target_address2, e });
        srv.removeConnection(socket, loop);
        allocator.destroy(data);
        allocator.destroy(tcp_target_write_data);
        return .disarm;
    };

    if (connected) {
        const tcp_target_read_data = allocator.create(TargetReadData) catch |e| {
            std.debug.print("Could not allocate TCP target read completion {}\n", .{e});
            srv.removeConnection(socket, loop);
            allocator.destroy(data);
            allocator.destroy(tcp_target_write_data);
            return .disarm;
        };
        tcp_target_read_data.* = TargetReadData{
            .server = srv,
            .client_socket = socket,
            .target_socket = connection.target_socket.?,
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
            .cancel_completion = .{
                .op = .{
                    // .close = .{
                    //     .fd = connection.target_socket.?,
                    // },
                    .shutdown = .{
                        .how = .both,
                        .socket = connection.target_socket.?,
                    },
                },
            },
        };
        connection.target_read_completion = tcp_target_read_data;
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
    connection.target_writes += 1;
    loop.add(&tcp_target_write_data.completion);

    return .rearm;
}

const TargetWriteData = struct {
    connection: *TcpConnection,
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
    const connection = data.connection;
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
    connection.onTargetWrite();
    return .disarm;
}

fn tcpTargetReadCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const data = @as(*TargetReadData, @ptrCast(@alignCast(ud.?)));
    const srv = data.server;
    const connection_opt = srv.tcp_connections.get(data.client_socket);
    const allocator = srv.allocator;
    if (connection_opt == null) {
        std.debug.print("TCP connection not found in target read\n", .{});
        allocator.destroy(data);
        return .disarm;
    }
    const connection = connection_opt.?;

    const read_len = result.read catch |e| {
        std.debug.print("TCP target read error {}\n", .{e});
        if (e == xev.ReadError.EOF) {
            connection.onTargetReadClosed(loop);
        } else {
            srv.removeConnection(connection.client_socket, loop);
            connection.target_read_completion = null;
        }
        allocator.destroy(data);
        return .disarm;
    };
    // std.debug.print("TCP target read {} bytes\n", .{read_len});

    const tcp_client_write_data = allocator.create(ClientWriteData) catch |e| {
        std.debug.print("Could not allocate TCP client write completion {}\n", .{e});
        connection.disconnectFromTarget();
        allocator.destroy(data);
        return .disarm;
    };
    tcp_client_write_data.* = ClientWriteData{
        .server = srv,
        .connection = connection,
        .ciphertext = undefined,
        .completion = undefined,
    };
    const ciphertext_len = connection.write(read_len, &tcp_client_write_data.ciphertext);
    // std.debug.print("TCP target read {} bytes\n", .{ciphertext_len});

    tcp_client_write_data.completion = .{
        .op = .{
            .write = .{
                .fd = data.client_socket,
                .buffer = .{
                    .slice = tcp_client_write_data.ciphertext[0..ciphertext_len],
                },
            },
        },
        .callback = tcpClientWriteCallback,
        .userdata = tcp_client_write_data,
    };
    connection.client_writes += 1;
    loop.add(&tcp_client_write_data.completion);

    return .rearm;
}

const ClientWriteData = struct {
    server: *Server,
    connection: *TcpConnection,
    ciphertext: [16384]u8,
    completion: xev.Completion,
};

fn tcpClientWriteCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
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
    data.connection.onClientWrite(loop);
    return .disarm;
}
