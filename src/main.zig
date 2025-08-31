const std = @import("std");
const net = std.net;
const posix = std.posix;

const xev = @import("xev");

const crypt = @import("crypt.zig");
const server = @import("server.zig");
const Server = server.Server;
const TcpRelay = server.TcpRelay;
const TargetReadData = server.TargetReadData;
const TargetWriteData = server.TargetWriteData;
const ClientReadData = server.ClientReadData;
const ClientWriteData = server.ClientWriteData;
const ClientWriteQueue = server.ClientWriteQueue;
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

    const client_socket = result.accept catch |e| {
        std.log.err("TCP accept client failed: {}", .{e});
        return .disarm;
    };
    const client_address = net.Address.initPosix(@alignCast(&comp.op.accept.addr));
    std.debug.print("TCP client connected {}, active callbacks: {}, relays: {}\n", .{ client_address, loop.active, srv.tcp_relays.count() });

    const relay = allocator.create(TcpRelay) catch |e| {
        std.debug.print("TCP could not allocate relay {}\n", .{e});
        return .disarm;
    };
    relay.* = TcpRelay{
        .server = srv,
        .client_socket = client_socket,
        .client_address = client_address,
    };

    srv.addTcpRelay(relay) catch |e| {
        std.debug.print("TCP could not add relay {}\n", .{e});
        posix.close(client_socket);
        allocator.destroy(relay);
        return .disarm;
    };

    const tcp_client_read_completion = allocator.create(ClientReadData) catch |e| {
        std.debug.print("TCP could not allocate client read completion {}\n", .{e});
        srv.removeTcpRelay(client_socket, loop);
        return .disarm;
    };
    tcp_client_read_completion.* = ClientReadData{
        .server = srv,
        .completion = .{
            .op = .{
                .read = .{
                    .fd = client_socket,
                    .buffer = .{
                        .slice = &relay.ciphertext_read_buf,
                    },
                },
            },
            .callback = tcpClientReadCallback,
            .userdata = tcp_client_read_completion,
        },
        .cancel_completion = .{
            .op = .{
                .shutdown = .{
                    .how = .both,
                    .socket = relay.client_socket,
                },
            },
        },
    };
    loop.add(&tcp_client_read_completion.completion);
    relay.client_read_completion = tcp_client_read_completion;

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
    const client_socket = comp.op.read.fd;
    const allocator = srv.allocator;

    const relay_opt = srv.tcp_relays.get(client_socket);
    if (relay_opt == null) {
        std.debug.print("TCP relay not found in client read callback\n", .{});
        allocator.destroy(data);
        return .disarm;
    }
    const relay = relay_opt.?;

    const read_len = result.read catch |e| {
        if (e == xev.ReadError.EOF) {
            std.debug.print("TCP client closed socket write {} {}\n", .{ relay.client_address, e });
            relay.onClientReadClosed();
        } else {
            std.debug.print("TCP client read eror {} {}, active callbacks {}, write queue {}\n", .{
                relay.client_address,
                e,
                loop.active,
                relay.client_write_queue.len,
            });
            srv.removeTcpRelay(client_socket, loop);
        }
        allocator.destroy(data);
        return .disarm;
    };

    const tcp_target_write_data = allocator.create(TargetWriteData) catch |e| {
        std.debug.print("TCP could not allocate TCP target write completion {}\n", .{e});
        srv.removeTcpRelay(client_socket, loop);
        allocator.destroy(data);
        return .disarm;
    };
    tcp_target_write_data.* = TargetWriteData{
        .server = srv,
        .client_socket = client_socket,
        .plaintext_buf = undefined,
        .completion = undefined,
    };

    const plaintext_len = relay.read(read_len, &tcp_target_write_data.plaintext_buf) catch |e| {
        std.debug.print("TCP could not decrypt client data {}\n", .{e});
        srv.removeTcpRelay(client_socket, loop);
        allocator.destroy(data);
        allocator.destroy(tcp_target_write_data);
        return .disarm;
    };

    const connected = relay.connectToTarget() catch |e| {
        std.debug.print("TCP could not connect to target {any} {}\n", .{ relay.target_address, e });
        srv.removeTcpRelay(client_socket, loop);
        allocator.destroy(data);
        allocator.destroy(tcp_target_write_data);
        return .disarm;
    };

    if (connected) {
        const tcp_target_read_data = allocator.create(TargetReadData) catch |e| {
            std.debug.print("TCP could not allocate target read completion {}\n", .{e});
            srv.removeTcpRelay(client_socket, loop);
            allocator.destroy(data);
            allocator.destroy(tcp_target_write_data);
            return .disarm;
        };
        tcp_target_read_data.* = TargetReadData{
            .server = srv,
            .client_socket = client_socket,
            .completion = .{
                .op = .{
                    .read = .{
                        .fd = relay.target_socket.?,
                        .buffer = .{
                            .slice = &relay.target_read_buf,
                        },
                    },
                },
                .callback = tcpTargetReadCallback,
                .userdata = tcp_target_read_data,
            },
            .cancel_completion = .{
                .op = .{
                    .shutdown = .{
                        .how = .both,
                        .socket = relay.target_socket.?,
                    },
                },
            },
        };
        relay.target_read_completion = tcp_target_read_data;
        loop.add(&tcp_target_read_data.completion);
    }

    if (plaintext_len == 0) {
        allocator.destroy(tcp_target_write_data);
    } else {
        tcp_target_write_data.completion = xev.Completion{
            .op = .{
                .write = .{
                    .fd = relay.target_socket.?,
                    .buffer = .{
                        .slice = tcp_target_write_data.plaintext_buf[0..plaintext_len],
                    },
                },
            },
            .userdata = tcp_target_write_data,
            .callback = tcpTargetWriteCallback,
        };
        relay.target_writes += 1;
        loop.add(&tcp_target_write_data.completion);
    }

    return .rearm;
}

fn tcpTargetWriteCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const data = @as(*TargetWriteData, @ptrCast(@alignCast(ud.?)));
    const srv = data.server;
    const allocator = srv.allocator;
    defer allocator.destroy(data);

    const relay_opt = srv.tcp_relays.get(data.client_socket);
    if (relay_opt == null) {
        std.debug.print("TCP relay not found in target write callback\n", .{});
        return .disarm;
    }
    const relay = relay_opt.?;

    const write_len = result.write catch |e| {
        std.debug.print("TCP target write error {}\n", .{e});
        srv.removeTcpRelay(data.client_socket, loop);
        return .disarm;
    };
    const data_len = comp.op.write.buffer.slice.len;
    if (data_len > write_len) {
        std.debug.print("TCP partial target write: {} {} \n", .{ write_len, data_len });
    }

    relay.onTargetWrite();
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
    const allocator = srv.allocator;
    
    const relay_opt = srv.tcp_relays.get(data.client_socket);
    if (relay_opt == null) {
        std.debug.print("TCP relay not found in target read callback\n", .{});
        allocator.destroy(data);
        return .disarm;
    }
    const relay = relay_opt.?;

    const read_len = result.read catch |e| {
        if (e == xev.ReadError.EOF) {
            std.debug.print("TCP target closed socket read {} {}\n", .{ relay.client_address, e });
            relay.onTargetReadClosed(loop);
        } else {
            std.debug.print("TCP target read error {} {}\n", .{ relay.client_socket, e });
            relay.target_read_completion = null;
            srv.removeTcpRelay(relay.client_socket, loop);
        }
        allocator.destroy(data);
        return .disarm;
    };

    const tcp_client_write_data = allocator.create(ClientWriteData) catch |e| {
        std.debug.print("TCP could not allocate client write completion {}\n", .{e});
        srv.removeTcpRelay(relay.client_socket, loop);
        allocator.destroy(data);
        return .disarm;
    };
    tcp_client_write_data.* = ClientWriteData{
        .server = srv,
        .ciphertext = undefined,
        .completion = undefined,
        .write_queue_node = ClientWriteQueue.Node{
            .data = tcp_client_write_data,
        },
    };
    const ciphertext_len = relay.write(read_len, &tcp_client_write_data.ciphertext);

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
    relay.client_writes += 1;
    relay.client_write_queue.append(&tcp_client_write_data.write_queue_node);
    if (relay.client_write_queue.len == 1) {
        loop.add(&tcp_client_write_data.completion);
    }

    return .rearm;
}

fn tcpClientWriteCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const data = @as(*ClientWriteData, @ptrCast(@alignCast(ud.?)));
    const srv = data.server;
    const client_socket = comp.op.write.fd;
    const allocator = srv.allocator;
    defer allocator.destroy(data);

    const relay_opt = srv.tcp_relays.get(client_socket);
    if (relay_opt == null) {
        std.debug.print("TCP relay not found in client write callback\n", .{});
        return .disarm;
    }
    const relay = relay_opt.?;

    _ = relay.client_write_queue.popFirst();

    const write_len = result.write catch |e| {
        std.debug.print("TCP client write error {}\n", .{e});
        srv.removeTcpRelay(client_socket, loop);
        return .disarm;
    };

    const data_len = comp.op.write.buffer.slice.len;
    const remaining_len = data_len - write_len;
    if (remaining_len > 0) {
        std.debug.print("TCP partial client write: {} {}\n", .{ write_len, data_len });
        const tcp_client_write_data = allocator.create(ClientWriteData) catch |e| {
            std.debug.print("Could not allocate TCP partial client write {}\n", .{e});
            srv.removeTcpRelay(client_socket, loop);
            return .disarm;
        };
        tcp_client_write_data.* = ClientWriteData{
            .server = srv,
            .ciphertext = undefined,
            .completion = undefined,
            .write_queue_node = ClientWriteQueue.Node{
                .data = tcp_client_write_data,
            },
        };
        @memcpy(tcp_client_write_data.ciphertext[0..remaining_len], data.ciphertext[write_len..data_len]);
        tcp_client_write_data.completion = .{
            .op = .{
                .write = .{
                    .fd = relay.client_socket,
                    .buffer = .{
                        .slice = tcp_client_write_data.ciphertext[0..remaining_len],
                    },
                },
            },
            .callback = tcpClientWriteCallback,
            .userdata = tcp_client_write_data,
        };
        relay.client_writes += 1;
        relay.client_write_queue.prepend(&tcp_client_write_data.write_queue_node);
    }

    if (relay.client_write_queue.len != 0) {
        const next_write = relay.client_write_queue.first.?;
        loop.add(&next_write.data.completion);
    }

    relay.onClientWrite(loop);
    return .disarm;
}
