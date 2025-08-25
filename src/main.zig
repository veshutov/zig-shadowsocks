const std = @import("std");
const net = std.net;
const posix = std.posix;

const xev = @import("xev");

pub fn main() !void {
    const address = try net.Address.parseIp("127.0.0.1", 8086);

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();
    const gpa = general_purpose_allocator.allocator();

    // start TCP server
    const tcp_listener = try posix.socket(address.any.family, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    defer posix.close(tcp_listener);
    try posix.setsockopt(tcp_listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(tcp_listener, &address.any, address.getOsSockLen());
    const backlog = 128;
    try posix.listen(tcp_listener, backlog);
    std.debug.print("TCP server started on {}\n", .{address});

    const tcp_accept_data = try gpa.create(TcpAcceptData);
    defer gpa.destroy(tcp_accept_data);
    tcp_accept_data.* = TcpAcceptData{
        .allocator = gpa,
        .completion = .{
            .op = .{
                .accept = .{ .socket = tcp_listener },
            },
            .userdata = tcp_accept_data,
            .callback = tcpAcceptCallback,
        },
    };
    loop.add(&tcp_accept_data.completion);

    // start UDP server
    const udp_socket = try posix.socket(address.any.family, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    defer posix.close(udp_socket);
    try posix.setsockopt(udp_socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(udp_socket, &address.any, address.getOsSockLen());
    std.debug.print("UDP server started on {}\n", .{address});

    const udp_recv_data = try gpa.create(UdpRecvData);
    defer gpa.destroy(udp_recv_data);
    udp_recv_data.* = UdpRecvData{
        .allocator = gpa,
        .buffer = undefined,
        .completion = .{
            .op = .{
                .recvfrom = .{
                    .fd = udp_socket,
                    .buffer = .{
                        .slice = &udp_recv_data.buffer,
                    },
                },
            },
            .userdata = udp_recv_data,
            .callback = udpRecvCallback,
        },
    };
    loop.add(&udp_recv_data.completion);

    try loop.run(.until_done);
}

const TcpAcceptData = struct {
    allocator: std.mem.Allocator,
    completion: xev.Completion,
};

fn tcpAcceptCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const accept_data = @as(*TcpAcceptData, @ptrCast(@alignCast(ud.?)));
    const allocator = accept_data.allocator;

    const socket = result.accept catch |err| {
        std.log.err("TCP accept failed: {}", .{err});
        return .disarm;
    };
    const client_address = net.Address.initPosix(@alignCast(&comp.op.accept.addr));
    std.debug.print("TCP {} connected\n", .{client_address});

    const read_data = allocator.create(TcpReadData) catch |e| {
        std.debug.print("TCP allocation error {}\n", .{e});
        posix.close(socket);
        return .disarm;
    };
    read_data.* = TcpReadData{
        .allocator = allocator,
        .buffer = undefined,
        .client_address = client_address,
        .completion = .{
            .op = .{
                .read = .{
                    .fd = socket,
                    .buffer = .{
                        .slice = &read_data.buffer,
                    },
                },
            },
            .callback = tcpReadCallback,
            .userdata = read_data,
        },
    };
    loop.add(&read_data.completion);

    return .rearm;
}

const TcpReadData = struct {
    allocator: std.mem.Allocator,
    buffer: [128]u8,
    client_address: net.Address,
    completion: xev.Completion,
};

fn tcpReadCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const read_data = @as(*TcpReadData, @ptrCast(@alignCast(ud.?)));
    const read = comp.op.read;
    const socket = read.fd;
    const allocator = read_data.allocator;

    const read_len = result.read catch {
        std.debug.print("TCP {} disconnected\n", .{read_data.client_address});
        posix.close(socket);
        allocator.destroy(read_data);
        return .disarm;
    };
    std.debug.print("TCP read {} bytes\n", .{read_len});

    // schedule write
    const write_data = allocator.create(TcpWriteData) catch |e| {
        std.debug.print("TCP allocation error {}\n", .{e});
        posix.close(socket);
        allocator.destroy(read_data);
        return .disarm;
    };
    write_data.* = TcpWriteData{
        .allocator = allocator,
        .buffer = undefined,
        .completion = .{
            .op = .{
                .write = .{
                    .fd = socket,
                    .buffer = .{
                        .slice = write_data.buffer[0..read_len],
                    },
                },
            },
            .userdata = write_data,
            .callback = tcpWriteCallback,
        },
    };
    @memcpy(write_data.buffer[0..read_len], read.buffer.slice[0..read_len]);
    loop.add(&write_data.completion);

    // schedule next read
    return .rearm;
}

const TcpWriteData = struct {
    allocator: std.mem.Allocator,
    buffer: [128]u8,
    completion: xev.Completion,
};

fn tcpWriteCallback(
    ud: ?*anyopaque,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const write_data = @as(*TcpWriteData, @ptrCast(@alignCast(ud.?)));
    const allocator = write_data.allocator;
    defer allocator.destroy(write_data);

    const write_len = result.write catch |e| {
        std.debug.print("TCP write error {}\n", .{e});
        return .disarm;
    };

    std.debug.print("TCP write {} bytes\n", .{write_len});
    return .disarm;
}

const UdpRecvData = struct {
    allocator: std.mem.Allocator,
    buffer: [128]u8,
    completion: xev.Completion,
};

fn udpRecvCallback(
    ud: ?*anyopaque,
    loop: *xev.Loop,
    comp: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const recv_data = @as(*UdpRecvData, @ptrCast(@alignCast(ud.?)));
    const allocator = recv_data.allocator;

    const read_len = result.recvfrom catch |e| {
        std.debug.print("UDP read error {}\n", .{e});
        return .disarm;
    };
    std.debug.print("UDP read {} bytes\n", .{read_len});

    const recvfrom = comp.op.recvfrom;
    const socket = recvfrom.fd;
    const client_address = net.Address.initPosix(@alignCast(&recvfrom.addr));

    // schedule write
    const sendto_data = allocator.create(UdpSendtoData) catch |e| {
        std.debug.print("UDP allocation error {}\n", .{e});
        return .disarm;
    };
    sendto_data.* = UdpSendtoData{
        .allocator = allocator,
        .buffer = undefined,
        .completion = .{
            .op = .{
                .sendto = .{
                    .fd = socket,
                    .addr = client_address,
                    .buffer = .{
                        .slice = sendto_data.buffer[0..read_len],
                    },
                },
            },
            .userdata = sendto_data,
            .callback = udpSendtoCallback,
        },
    };
    @memcpy(sendto_data.buffer[0..read_len], recvfrom.buffer.slice[0..read_len]);
    loop.add(&sendto_data.completion);

    // schedule next read
    return .rearm;
}

const UdpSendtoData = struct {
    allocator: std.mem.Allocator,
    buffer: [128]u8,
    completion: xev.Completion,
};

fn udpSendtoCallback(
    ud: ?*anyopaque,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const sendto_data = @as(*UdpSendtoData, @ptrCast(@alignCast(ud.?)));
    const allocator = sendto_data.allocator;
    defer allocator.destroy(sendto_data);

    const write_len = result.sendto catch |e| {
        std.debug.print("UDP write error {}\n", .{e});
        return .disarm;
    };

    std.debug.print("UDP write {} bytes\n", .{write_len});
    return .disarm;
}
