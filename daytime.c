/* 
 * daytime.c: a simple network service based on lwIP and mini-os
 * 
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 */

#include <os.h>
#include <xmalloc.h>
#include <console.h>
#include <netfront.h>
#include <lwip/api.h>

static char message[29];

static struct thread *_me = NULL;
static int _stop_requested = 0;

#define CONFIG_NOXS_TEST
#ifdef CONFIG_NOXS_TEST
#define HOST_IP    0x0a060601
#define HOST_PORT  5000

static void send_udp(void *bytes, unsigned int bytes_num)
{
    struct netconn *conn;
    struct netbuf *buf;
    char *data;
    struct ip_addr dstipaddr = { htonl(HOST_IP) };
    err_t rc;

    conn = netconn_new(NETCONN_UDP);
    rc = netconn_connect(conn, &dstipaddr, HOST_PORT);
    if (rc != ERR_OK) {
        tprintk("Failed to connect: %i\n", rc);
        goto out_close;
    }

    buf = netbuf_new();
    data = netbuf_alloc(buf, bytes_num);
    memcpy(data, bytes, bytes_num);

    rc = netconn_send(conn, buf);
    if (rc != ERR_OK) {
        tprintk("Failed to send: %i\n", rc);
    }

    netbuf_delete(buf);

/*out_disconnect:*/
    rc = netconn_disconnect(conn);
    if (rc != ERR_OK) {
        tprintk("Error disconnecting: %i\n", rc);
    }

out_close:
    rc = netconn_delete(conn);
    if (rc != ERR_OK) {
        tprintk("Error deleting connection: %i\n", rc);
    }
}
#endif

void run_server(void *p)
{
    struct ip_addr listenaddr = { 0 };
    struct netconn *listener;
    struct netconn *session;
    struct timeval tv;
    err_t rc;

    _me = get_current();

#if 0
    /* Networking is started by call_main in main.c */
    start_networking();
#endif

    if (0) {
        struct ip_addr ipaddr = { htonl(0x0a000001) };
        struct ip_addr netmask = { htonl(0xff000000) };
        struct ip_addr gw = { 0 };
        networking_set_addr(&ipaddr, &netmask, &gw);
    }

#ifdef CONFIG_NOXS_TEST
    {
        gettimeofday(&tv, NULL);
        sprintf(message, "%lu.%6.6lu", tv.tv_sec, tv.tv_usec);
        send_udp(message, strlen(message));
    }
#endif

    tprintk("Opening connection\n");

    listener = netconn_new(NETCONN_TCP);
    tprintk("Connection at %p\n", listener);

    rc = netconn_bind(listener, &listenaddr, 13);
    if (rc != ERR_OK) {
        tprintk("Failed to bind connection: %i\n", rc);
        return;
    }

    rc = netconn_listen(listener);
    if (rc != ERR_OK) {
        tprintk("Failed to listen on connection: %i\n", rc);
        return;
    }

    while (!_stop_requested) {
        rc = netconn_accept(listener, &session);
        if (session == NULL) 
            continue;

        gettimeofday(&tv, NULL);
        sprintf(message, "%20lu.%6.6lu\n", tv.tv_sec, tv.tv_usec);
        (void) netconn_write(session, message, strlen(message), NETCONN_COPY);
        (void) netconn_disconnect(session);
        (void) netconn_delete(session);
    }
}


#if 0
int app_main(start_info_t *si)
{
    create_thread("server", run_server, NULL);
    return 0;
}
#endif

void stop_server()
{
    _stop_requested = 1;
    wake(_me);
}
