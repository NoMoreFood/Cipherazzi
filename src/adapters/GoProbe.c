#include <gum/guminterceptor.h>
#include <stdint.h>

typedef struct
{
    volatile int state;
    uintptr_t goroutine, depth, connection;
    uint64_t started;
} Call;

typedef struct
{
    volatile int state;
    uint32_t kind;
    uint64_t values[16];
    uint8_t local_ip[16], remote_ip[16];
    char name[256], alpn[256];
    uint32_t certificate_lengths[16];
    uint8_t certificates[1048576];
} Packet;

typedef struct
{
    volatile int state;
    uintptr_t connection;
    uint64_t started, local_port, remote_port, local_size, remote_size;
    uint8_t local_ip[16], remote_ip[16];
} QuicEndpoint;

typedef struct
{
    volatile int dropped;
    Call calls[4096];
    uintptr_t seen[4096];
    QuicEndpoint quic[4096];
    Packet packets[64];
} Output;

extern Output output;

static int claim(volatile int *value, int expected, int desired)
{
    int previous;
    __asm__ volatile("lock; cmpxchgl %2, %1" : "=a"(previous), "+m"(*value)
        : "r"(desired), "0"(expected) : "memory");
    return previous == expected;
}

static int seen(uintptr_t connection, int remove)
{
    unsigned hash = (unsigned)(connection >> 4) & 4095;
    for (unsigned attempt = 0; attempt < 32; ++attempt)
    {
        uintptr_t *available = 0, expected = 0;
        for (unsigned index = 0; index < 4096; ++index)
        {
            uintptr_t *slot = &output.seen[(hash + index) & 4095], current = *slot;
            if (current == connection)
            {
                if (remove) *slot = 1;
                return 1;
            }
            if (current <= 1 && !available)
            {
                available = slot;
                expected = current;
            }
            if (!current) break;
        }
        if (remove) return 0;
        if (!available) break;
        uintptr_t previous;
        __asm__ volatile("lock; cmpxchgq %2, %1" : "=a"(previous), "+m"(*available)
            : "r"(connection), "0"(expected) : "memory");
        if (previous == expected) return 0;
    }
    output.dropped = 1;
    return 1;
}

static uint64_t timestamp(void)
{
    volatile uint32_t *clock = (volatile uint32_t *)0x7ffe0014;
    uint32_t high, low;
    do
    {
        high = clock[1];
        low = clock[0];
    } while (high != clock[2]);
    return ((uint64_t)high << 32) | low;
}

static uintptr_t pointer(uintptr_t address)
{
    return *(uintptr_t *)address;
}

static int copy_string(uintptr_t address, char *destination, unsigned limit)
{
    uintptr_t size = pointer(address + 8), source = pointer(address);
    if (size > limit || (!source && size)) return 0;
    for (unsigned index = 0; index < size; ++index) destination[index] = ((char *)source)[index];
    return (int)size;
}

static int endpoint(uintptr_t address, uintptr_t expected, unsigned ip_offset, unsigned port_offset,
    uint8_t *ip, uint64_t *port, uint64_t *size)
{
    uintptr_t table = pointer(address), value = pointer(address + 8);
    if (!table || !value || pointer(table + 8) != expected) return 0;
    uintptr_t bytes = pointer(value + ip_offset), count = pointer(value + ip_offset + 8);
    uintptr_t number = pointer(value + port_offset);
    if (!bytes || (count != 4 && count != 16) || !number || number > 65535) return 0;
    unsigned specified = 0;
    for (unsigned index = 0; index < count; ++index)
    {
        ip[index] = ((uint8_t *)bytes)[index];
        specified |= ip[index];
    }
    if (!specified) return 0;
    *size = count;
    *port = number;
    return 1;
}

static void quic_endpoint(uintptr_t connection)
{
    uintptr_t crypto = pointer(connection + QUIC_CRYPTO), sender = pointer(connection + QUIC_SOCKET);
    if (!crypto || !sender || pointer(crypto + 8) != QUIC_CRYPTO_TYPE ||
        pointer(sender + 8) != QUIC_SOCKET_TYPE) return;
    crypto = pointer(connection + QUIC_CRYPTO + 8);
    sender = pointer(connection + QUIC_SOCKET + 8);
    if (!crypto || !sender) return;
    uintptr_t tls = pointer(crypto + QUIC_TLS);
    if (!tls) return;
    tls = pointer(tls + QUIC_INNER);
    uintptr_t remote = pointer(sender + QUIC_REMOTE);
    if (!tls || !remote) return;
    uint64_t now = timestamp();
    unsigned hash = (unsigned)(tls >> 4) & 4095;
    for (unsigned index = 0; index < 4096; ++index)
    {
        QuicEndpoint *entry = &output.quic[(hash + index) & 4095];
        if (entry->state == 2 && (entry->connection == tls || now - entry->started > 1200000000))
            claim(&entry->state, 2, 0);
        if (!claim(&entry->state, 0, 1)) continue;
        entry->connection = tls;
        entry->started = now;
        if (endpoint(sender + QUIC_LOCAL, UDP_ADDRESS_TYPE, UDP_IP, UDP_PORT,
                entry->local_ip, &entry->local_port, &entry->local_size) &&
            endpoint(remote + QUIC_REMOTE_ADDRESS, UDP_ADDRESS_TYPE, UDP_IP, UDP_PORT,
                entry->remote_ip, &entry->remote_port, &entry->remote_size)) entry->state = 2;
        else entry->state = 0;
        seen(tls, 1);
        return;
    }
    output.dropped = 1;
}

static void snapshot(uintptr_t connection, uint64_t started, int success, int observation)
{
    Packet *packet = 0;
    for (unsigned index = 0; index < 64; ++index)
        if (claim(&output.packets[index].state, 0, 1))
        {
            packet = &output.packets[index];
            break;
        }
    if (!packet)
    {
        output.dropped = 1;
        return;
    }
    for (unsigned index = 0; index < 16; ++index) packet->values[index] = 0;
    packet->kind = observation ? 2 : 1;
    packet->values[0] = connection;
    packet->values[1] = started;
    packet->values[2] = timestamp();
    uint64_t flags = success ? 1 : 0;
    if (pointer(connection + TLS_QUIC)) flags |= 2;
    if (success && pointer(connection + TLS_VERIFIED_CHAINS + 8)) flags |= 4;
    if (*(uint8_t *)(connection + TLS_CLIENT)) flags |= 32;
    if (success && *(uint8_t *)(connection + TLS_RESUMED)) flags |= 64;
    uintptr_t certificates = connection + TLS_CERTIFICATES;
    uintptr_t error = connection + TLS_ERROR;
    for (unsigned depth = 0; !success && depth < 4; ++depth)
    {
        uintptr_t table = pointer(error), value = pointer(error + 8);
        if (!table || !value) break;
        uintptr_t type = pointer(table + 8);
        if (CERTIFICATE_ERROR_TYPE && type == CERTIFICATE_ERROR_TYPE)
        {
            flags |= 8;
            certificates = value + CERTIFICATE_ERROR_CHAIN;
            break;
        }
        if (WRAP_ERROR_TYPE && type == WRAP_ERROR_TYPE) error = value + WRAP_ERROR;
        else if (WRAP_ERRORS_TYPE && type == WRAP_ERRORS_TYPE && pointer(value + WRAP_ERRORS + 8))
            error = pointer(value + WRAP_ERRORS);
        else break;
    }
    packet->values[4] = *(uint16_t *)(connection + TLS_VERSION);
    packet->values[5] = *(uint16_t *)(connection + TLS_CIPHER);
    packet->values[6] = TLS_GROUP >= 0 ? *(uint16_t *)(connection + TLS_GROUP) : 0;
    packet->values[7] = TLS_SIGNATURE >= 0 ? *(uint16_t *)(connection + TLS_SIGNATURE) : 0;
    packet->values[10] = copy_string(connection + TLS_NAME, packet->name, 253);
    packet->values[11] = copy_string(connection + TLS_ALPN, packet->alpn, 255);
    uintptr_t table = pointer(connection + TLS_SOCKET), socket = pointer(connection + TLS_SOCKET + 8);
    if (table && socket && pointer(table + 8) == TCP_CONNECTION_TYPE)
    {
        uintptr_t fd = pointer(socket + TCP_FD);
        if (fd && endpoint(fd + FD_LOCAL, TCP_ADDRESS_TYPE, TCP_IP, TCP_PORT,
                packet->local_ip, &packet->values[8], &packet->values[14]) &&
            endpoint(fd + FD_REMOTE, TCP_ADDRESS_TYPE, TCP_IP, TCP_PORT,
                packet->remote_ip, &packet->values[9], &packet->values[15])) flags |= 16;
    }
    if (flags & 2)
    {
        unsigned hash = (unsigned)(connection >> 4) & 4095;
        for (unsigned index = 0; index < 4096; ++index)
        {
            const QuicEndpoint *entry = &output.quic[(hash + index) & 4095];
            if (entry->state != 2 || entry->connection != connection) continue;
            for (unsigned offset = 0; offset < 16; ++offset)
            {
                packet->local_ip[offset] = entry->local_ip[offset];
                packet->remote_ip[offset] = entry->remote_ip[offset];
            }
            packet->values[8] = entry->local_port;
            packet->values[9] = entry->remote_port;
            packet->values[14] = entry->local_size;
            packet->values[15] = entry->remote_size;
            flags |= 16;
            break;
        }
    }
    packet->values[3] = flags;
    uintptr_t count = pointer(certificates + 8), list = pointer(certificates);
    unsigned total = 0;
    if (count > 16 || (count && !list)) count = 0;
    for (unsigned index = 0; index < count; ++index)
    {
        uintptr_t certificate = pointer(list + index * 8);
        if (!certificate) break;
        uintptr_t size = pointer(certificate + CERTIFICATE_RAW + 8), bytes = pointer(certificate + CERTIFICATE_RAW);
        if (!bytes || !size || size > 262144 || size > 1048576 - total) break;
        packet->certificate_lengths[index] = (uint32_t)size;
        for (unsigned offset = 0; offset < size; ++offset)
            packet->certificates[total + offset] = ((uint8_t *)bytes)[offset];
        total += (unsigned)size;
        ++packet->values[12];
    }
    packet->state = 2;
}

void observe(GumInvocationContext *invocation)
{
    GumCpuContext *registers = invocation->cpu_context;
    const unsigned *site = gum_invocation_context_get_listener_function_data(invocation);
    uintptr_t connection = registers->rax;
    if (site[0] == 4)
    {
        quic_endpoint(connection);
        return;
    }
    if (site[0] == 3)
    {
        seen(connection, 1);
        return;
    }
    uint64_t now = timestamp();
    uintptr_t goroutine = registers->r14;
    uintptr_t depth = pointer(goroutine + 8) - (registers->rsp + site[1]);
    unsigned hash = (unsigned)((goroutine >> 8) ^ depth) & 4095;
    if (site[0] == 1)
    {
        if (*(uint32_t *)(connection + TLS_COMPLETE))
        {
            if (!seen(connection, 0)) snapshot(connection, now, 1, 1);
            return;
        }
        for (unsigned index = 0; index < 4096; ++index)
        {
            Call *call = &output.calls[(hash + index) & 4095];
            if (call->state == 2 && call->goroutine == goroutine && call->depth == depth) return;
            if (call->state == 2 && now - call->started > 1200000000) claim(&call->state, 2, 0);
            if (claim(&call->state, 0, 1))
            {
                call->goroutine = goroutine;
                call->depth = depth;
                call->connection = connection;
                call->started = now;
                call->state = 2;
                return;
            }
        }
        output.dropped = 1;
        return;
    }
    for (unsigned index = 0; index < 4096; ++index)
    {
        Call *call = &output.calls[(hash + index) & 4095];
        if (call->state != 2 || call->goroutine != goroutine || call->depth != depth ||
            !claim(&call->state, 2, 1)) continue;
        connection = call->connection;
        if (!seen(connection, 0))
            snapshot(connection, call->started, registers->rax == 0 &&
                *(uint32_t *)(connection + TLS_COMPLETE) == 1, 0);
        call->state = 0;
        return;
    }
}

Packet *packets(void) { return output.packets; }
unsigned packet_size(void) { return sizeof(Packet); }
unsigned output_size(void) { return sizeof(Output); }
