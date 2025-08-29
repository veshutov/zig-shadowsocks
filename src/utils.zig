const std = @import("std");
const net = std.net;

pub fn parseAddress(payload: []const u8) !net.Address {
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

            // Use std.net.getAddressList for DNS resolution
            const allocator = std.heap.page_allocator;
            const domain_str = allocator.dupe(u8, domain) catch return error.OutOfMemory;
            defer allocator.free(domain_str);

            const address_list = std.net.getAddressList(allocator, domain_str, port) catch {
                std.log.err("TCP failed to resolve domain: {s}", .{domain});
                return error.DomainResolutionFailed;
            };
            defer address_list.deinit();

            for (address_list.addrs) |addr| {
                if (addr.any.family == std.posix.AF.INET) {
                    return addr;
                }
            }
            if (address_list.addrs.len > 0) {
                const resolved_addr = address_list.addrs[0];
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