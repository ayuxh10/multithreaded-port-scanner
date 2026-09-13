/*
 * Simple TCP Connect Port Scanner
 * Windows / Winsock2 / MinGW
 *
 * Compile:
 *   gcc scanner.c -o scanner.exe -lws2_32
 *
 * Usage:
 *   scanner.exe <target_ip_or_host> <start_port> <end_port>
 *
 * Example:
 *   scanner.exe 127.0.0.1 1 1024
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define TIMEOUT_MS      800
#define MAX_THREADS     40

typedef struct {
    const char *name;
    int port;
} ServiceEntry;

static ServiceEntry known_services[] = {
    { "FTP",    21 },
    { "SSH",    22 },
    { "Telnet", 23 },
    { "SMTP",   25 },
    { "DNS",    53 },
    { "HTTP",   80 },
    { "POP3",   110 },
    { "IMAP",   143 },
    { "HTTPS",  443 },
    { "SMB",    445 },
    { "RDP",    3389 },
    { "MySQL",  3306 },
    { "RDP-Alt",5900 },
    { "HTTP-Alt", 8080 },
    { NULL, 0 }
};

/* shared scan state */
typedef struct {
    const char *target_ip;
    volatile LONG next_port;   /* next port to claim, incremented atomically */
    int end_port;
    CRITICAL_SECTION print_lock;
} ScanContext;

static const char *lookup_service(int port) {
    int i;
    for (i = 0; known_services[i].name != NULL; i++) {
        if (known_services[i].port == port) {
            return known_services[i].name;
        }
    }
    return "unknown";
}

/* Attempts a non-blocking connect with a short timeout.
 * Returns 1 if the port is open, 0 otherwise. */
static int scan_port(const char *ip, int port) {
    SOCKET sock;
    struct sockaddr_in addr;
    u_long mode = 1; /* non-blocking */
    fd_set write_set;
    struct timeval tv;
    int result;
    int open = 0;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return 0;
    }

    ioctlsocket(sock, FIONBIO, &mode);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);

    tv.tv_sec = 0;
    tv.tv_usec = TIMEOUT_MS * 1000;

    result = select(0, NULL, &write_set, NULL, &tv);

#ifdef SCANNER_DEBUG
    printf("[debug] port %d: select() returned %d, WSAGetLastError=%d\n",
           port, result, WSAGetLastError());
#endif

    if (result > 0 && FD_ISSET(sock, &write_set)) {
        int err = 0;
        int err_len = sizeof(err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &err_len) == 0) {
#ifdef SCANNER_DEBUG
            printf("[debug] port %d: SO_ERROR = %d\n", port, err);
#endif
            if (err == 0) {
                open = 1;
            }
        }
    } else if (result == SOCKET_ERROR) {
#ifdef SCANNER_DEBUG
        printf("[debug] port %d: select() failed, WSAGetLastError=%d\n",
               port, WSAGetLastError());
#endif
    }

    closesocket(sock);
    return open;
}

/* Worker thread: pulls ports from the shared counter until exhausted */
static DWORD WINAPI worker_thread(LPVOID param) {
    ScanContext *ctx = (ScanContext *)param;
    LONG port;

    for (;;) {
        port = InterlockedIncrement(&ctx->next_port);
        if (port > ctx->end_port) {
            break;
        }

        if (scan_port(ctx->target_ip, (int)port)) {
            EnterCriticalSection(&ctx->print_lock);
            printf("Port %-5d open  (%s)\n", (int)port, lookup_service((int)port));
            fflush(stdout);
            LeaveCriticalSection(&ctx->print_lock);
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    WSADATA wsa;
    ScanContext ctx;
    HANDLE threads[MAX_THREADS];
    int thread_count;
    int start_port, end_port;
    int i;
    struct addrinfo hints, *res;
    char resolved_ip[INET_ADDRSTRLEN];

    if (argc != 4) {
        printf("Usage: %s <target_ip_or_host> <start_port> <end_port>\n", argv[0]);
        return 1;
    }

    start_port = atoi(argv[2]);
    end_port = atoi(argv[3]);

    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        printf("Invalid port range. Use values between 1 and 65535.\n");
        return 1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    /* Resolve hostname to an IPv4 address (works for raw IPs too) */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(argv[1], NULL, &hints, &res) != 0) {
        printf("Could not resolve host: %s\n", argv[1]);
        WSACleanup();
        return 1;
    }

    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
               resolved_ip, sizeof(resolved_ip));
    freeaddrinfo(res);

    printf("Scanning %s (%s) ports %d-%d ...\n\n", argv[1], resolved_ip, start_port, end_port);

    ctx.target_ip = resolved_ip;
    ctx.next_port = start_port - 1; /* InterlockedIncrement will bring it to start_port first */
    ctx.end_port = end_port;
    InitializeCriticalSection(&ctx.print_lock);

    thread_count = MAX_THREADS;
    if ((end_port - start_port + 1) < thread_count) {
        thread_count = end_port - start_port + 1;
    }

    for (i = 0; i < thread_count; i++) {
        threads[i] = CreateThread(NULL, 0, worker_thread, &ctx, 0, NULL);
    }

    WaitForMultipleObjects(thread_count, threads, TRUE, INFINITE);

    for (i = 0; i < thread_count; i++) {
        CloseHandle(threads[i]);
    }

    DeleteCriticalSection(&ctx.print_lock);

    printf("\nScan complete.\n");

    WSACleanup();
    return 0;
}

