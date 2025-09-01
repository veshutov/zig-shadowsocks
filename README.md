# Shadowzig
Shadowsocks TCP server implementation using event loop

Not for production use:
- does not handle partial writes to target website
- blocking dns resolution
- blocking connect to target website call

Still works for most cases.