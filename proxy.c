#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libev/ev.h>
#include "ringbuf.h"
#include "md5.h"
#include "rbtree.h"
#include "smart_list.h"


#define GLOBAL_BLACK_LIST    "ip_blacklist.txt"
#define GLOBAL_WHITE_LIST    "ip_whitelist.txt"


#define ERR ( strerror( errno ) )
#define BUFSIZE   1024
#define CONN_TIMEOUT  10
#define LIMIT_TIMEOUT  10
#define TCP_BUF_LEN  1048576


char log_file[100];
int  port;
char remote_ip[20];
int  remote_port;
int  speed_limit = 0;
int  lsnfd;

int  conn_cnt = 0;

char priv_blacklist_file[50];
char priv_whitelist_file[50];

char global_blacklist_sum[32+1];
char priv_blacklist_sum[32+1];

char global_whitelist_sum[32+1];
char priv_whitelist_sum[32+1];

int  use_blacklist = 0;
int  use_whitelist = 0;


typedef struct{
    int cli_fd;
    int srv_fd;
    int connected;
    int limit_start;
    int bytes;
    int suspend;
    
    ev_io local_read_ctx;
    ev_io local_write_ctx;
    ev_io remote_read_ctx;
    ev_io remote_write_ctx;
    ev_timer timer;
    
    char local_buf[sizeof(ring_buffer_head)+BUFSIZE];
    char remote_buf[sizeof(ring_buffer_head)+BUFSIZE];
    void* prev;
    void* next;
}session_ctx;

int setnonblocking(int fd);

int get_host_ip( const char* host, char* ip );

int tcp_accept( int lsnfd, char* ip, int* port );

int write_log( char* fmt, ... );

int tcp_listen( char* ip, int port );

int file_exist( char* name );

int hex2asc( char* hex, int len, char* buf, int buflen );
char* strtrim(char* str);

session_ctx* session_list = NULL;

void accept_cb( struct ev_loop* loop, ev_io* rw, int revents );

void cli_read_cb( struct ev_loop* loop, ev_io* rw, int revents );
void cli_write_cb( struct ev_loop* loop, ev_io* rw, int revents );

void srv_read_cb( struct ev_loop* loop, ev_io* rw, int revents );
void srv_write_cb( struct ev_loop* loop, ev_io* rw, int revents );

void timer_cb( struct ev_loop* loop, ev_timer* w, int revents );
void sig_cb( struct ev_loop* loop, ev_signal* w, int revents );
void load_access_contrl_cb( struct ev_loop* loop, ev_timer* w, int revents );

void close_session( struct ev_loop* loop, session_ctx* ctx );

int check_ip( char* ip );

void load_blacklist();
void load_whitelist();

void free_ip_proc( rbnode* node );

rbtree black_list;
rbtree white_list;

smart_list ip_list;

typedef struct{
    rbtree _;
    char ip[16];
} node_ip;

int  ip_node_cmp (  rbnode* node1, rbnode* node2 );
int  ip_value_cmp( void* value, rbnode* node2    );
void ip_node_swap( rbnode* node1, rbnode* node2  );

int init_access_ctrl();

int main( int argc, char* argv[] )
{
    struct ev_loop* loop;
    struct ev_io io;
    ev_signal sigint;
    ev_signal sigterm;
    ev_timer timer;
    
    
    if( argc < 4 || argc > 5 )
    {
        printf( "usage:proxy port server port [limit]\n" );
        return 1;
    }
    
    if( argc == 5 )
    {
        speed_limit = atoi( argv[4] ) * 1024;
    }
    
    port = atoi( argv[1] );
    
    
    sprintf( log_file, "proxy_%d.log", port );
    
    if( init_access_ctrl() )
    {
        printf( "init access control failed!\n" );
        write_log( "[ERR] init access control failed!" );
        return 1;
    }
    
    load_blacklist();
    load_whitelist();
    
    if( get_host_ip( argv[2], remote_ip ) )
    {
        printf( "resolve server ip failed!\n" );
        write_log( "[ERR] resolve server ip failed!" );
        return 1;
    }
    
    remote_port = atoi( argv[3] );
    
    lsnfd = tcp_listen( NULL, port );
    if( lsnfd == -1 )
    {
        printf( "tcp listen failed! err:%s\n", ERR );
        write_log( "[ERR] tcp listen failed! err:%s", ERR );
        return 1;
    }
    
    loop = ev_default_loop( 0 );
    if( !loop )
    {
        printf( "create event loop failed!\n" );
        write_log( "[ERR] create event loop failed!" );
        return 1;
    }
    
    
    
    ev_io_init( &io, accept_cb, lsnfd, EV_READ );
    ev_io_start( loop, &io );
    
    ev_timer_init( &timer, load_access_contrl_cb, 10, 10 );
    ev_timer_start( loop, &timer );
    
    write_log( "proxy startup ok! pid:%d", getpid() );
    
    
    signal( SIGPIPE, SIG_IGN );
    ev_signal_init( &sigint, sig_cb,  SIGINT );
    ev_signal_init( &sigterm, sig_cb, SIGTERM );
    
    ev_signal_start( loop, &sigint );
    ev_signal_start( loop, &sigterm );
    ev_run( loop, 0 );
    
    write_log( "[WRN] proxy stop!" );
    
    //free( loop );
    
    return 0;
    
}

void load_access_contrl_cb( struct ev_loop* loop, ev_timer* w, int revents )
{
    load_blacklist();
    load_whitelist();
}

void timer_cb( struct ev_loop* loop, ev_timer* w, int revents )
{
    session_ctx* ctx;
    
    ctx = w->data;
    if( ctx->connected == 0 )
    {
        write_log( "[ERR] connect to server timeout!" );
        ev_timer_stop( loop, w );
        close_session( loop, ctx );
    }
    else
    {
        if( ctx->limit_start == 0 )
        {
            ev_timer_stop( loop, w );
            ev_timer_set( w, 1, 1 );
            ev_timer_start( loop, w );
            ctx->limit_start = 1;
            ctx->bytes = 0;
        }
        else
        {
            ctx->bytes = 0;
            if( ctx->suspend )
            {
                //write_log( "resume!" );
                ev_io_start( loop, &ctx->remote_read_ctx );
                ctx->suspend = 0;
            }
        }
    }
    
    
}



void accept_cb( struct ev_loop* loop, ev_io* rw, int revents )
{
    char ip[20];
    int clifd;
    int cliport;
    int srvfd;
    int ret;
    int bufsize;
    session_ctx* ctx;
    rbnode* n;
    struct linger linger;
    
    linger.l_onoff = 1;
    linger.l_linger = 1;
    
    
    
    clifd = tcp_accept( lsnfd, ip, &cliport );
    if( clifd == -1 )
    {
        write_log( "[ERR] tcp accept failed! err:%s", ERR );
        return;
    }
    
    write_log( "new connection: %s:%d", ip, cliport );
    
    if( use_whitelist )
    {
        n = rbtree_find( &white_list, ip );
        if( !n )
        {
            write_log( "[WRN] client '%s' denied by white list!", ip );
            close( clifd );
            return;
        }
    }
    else
    {
        if( use_blacklist )
        {
            n = rbtree_find( &black_list, ip );
            if( n )
            {
                write_log( "[WRN] client '%s' denied by black list!", ip );
                close( clifd );
                return;
            }
        }
    }
    
    

    
    
    
    bufsize = TCP_BUF_LEN;
    if( setsockopt( clifd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize) ) )
        write_log( "[WRN] set socket send buf failed! errno:%d, err:%s", errno, strerror( errno ) );

    setnonblocking( clifd );
    
    //setsockopt( clifd, SOL_SOCKET, SO_LINGER, (void*)&linger, sizeof(linger) );
    
    ctx   = malloc( sizeof( session_ctx ) );
 
    
    if( !ctx  )
    {
        write_log( "[ERR] malloc failed!" );
        close( clifd );
        return;
    }
    
    ring_buffer_init( ctx->local_buf, BUFSIZE );
    ring_buffer_init( ctx->remote_buf, BUFSIZE );
    
    //ctx->prev = NULL;
    //ctx->next = session_list;
    ctx->connected = 0;
    ctx->limit_start = 0;
    ctx->bytes = 0;
    ctx->suspend = 0;
    
    
    struct sockaddr_in addr;
    socklen_t addrlen;

    srvfd = socket( AF_INET, SOCK_STREAM, 0 );
    if( srvfd == -1 )
    {
        write_log( "[ERR] create socket failed! err:%s", ERR );
        close( clifd );
        free( ctx );
        return ;
    }
    
    setnonblocking( srvfd );
    
    //setsockopt( srvfd, SOL_SOCKET, SO_LINGER, (void*)&linger, sizeof(linger) );
    
    addr.sin_family = AF_INET;
    addr.sin_port   = htons( remote_port );
    addr.sin_addr.s_addr = inet_addr(remote_ip);
    
    addrlen = sizeof(addr);
    
    ret = connect( srvfd, (struct sockaddr*)&addr, addrlen );
    if( ret && errno != EINPROGRESS )
    {
        write_log( "[ERR] connect to remote failed! err:%s", ERR );
        close( clifd );
        close( srvfd );
        free( ctx );
        return ;
    }

    conn_cnt ++;
    
    ev_io_init( &ctx->local_read_ctx, cli_read_cb, clifd, EV_READ );
    ev_io_init( &ctx->local_write_ctx, cli_write_cb, clifd, EV_WRITE );
    
    ev_io_init( &ctx->remote_read_ctx, srv_read_cb, srvfd, EV_READ );
    ev_io_init( &ctx->remote_write_ctx, srv_write_cb, srvfd, EV_WRITE );
    
    ev_timer_init( &ctx->timer, timer_cb, CONN_TIMEOUT, 0 );
    
    //write_log( "clifd: %d, srvfd:%d", clifd, srvfd );
    
    ctx->cli_fd = clifd;
    ctx->srv_fd = srvfd;
    ctx->local_read_ctx.data   = ctx;
    ctx->local_write_ctx.data  = ctx;
    ctx->remote_read_ctx.data  = ctx;
    ctx->remote_write_ctx.data = ctx;
    ctx->timer.data = ctx;
    
    ev_io_start( loop, &ctx->remote_write_ctx );
    
    ev_timer_start( loop, &ctx->timer );
    
}

void cli_read_cb( struct ev_loop* loop, ev_io* rw, int revents )
{
    char buf[BUFSIZE];
    int rc;
    int len;
    session_ctx* ctx;
    
    ctx = rw->data;
    
    
    rc = read( rw->fd, buf, sizeof(buf) );
    if( rc <= 0 )
    {
        close_session( loop, ctx );
        return;
    }
    
    
    len = rc;
    rc = write( ctx->srv_fd, buf, len );
    if( rc <= 0 )
    {
        
        close_session( loop, ctx );
        return;
    }
    
    if( rc != len )
    {
        //write_log( "[TIP] srv data write failed! %d bytes left, cli fd:%d", len - rc, rw->fd );
        ring_buffer_write( ctx->remote_buf, buf + rc, len - rc );
        ev_io_stop( loop, &ctx->local_read_ctx );
        ev_io_start( loop, &ctx->remote_write_ctx );
    }
    
        
    
}

void cli_write_cb( struct ev_loop* loop, ev_io* rw, int revents )
{
    session_ctx* ctx;
    
    char buf[BUFSIZE];
    int size;
    int rc;
    
    ctx = rw->data;
    size = sizeof( buf );
    
    ring_buffer_peek( ctx->local_buf, buf, &size );
    
    //write_log( "write data to cli fd %d, peek %d bytes from ringbuffer", rw->fd, size );
    
    rc = write( rw->fd, buf, size );
    if( rc <= 0 )
    {
        close_session( loop, ctx );
        return;
    }
    
    ring_buffer_inc( ctx->local_buf, rc );
    if( rc == size ) /* send compelete */
    {
        //write_log( "write buffer client fd %d ok!", rw->fd );
        if( speed_limit && ctx->suspend )
            ;
        else
            ev_io_start( loop, &ctx->remote_read_ctx );
        ev_io_stop( loop, &ctx->local_write_ctx );
    }

    
}


void srv_read_cb( struct ev_loop* loop, ev_io* rw, int revents )
{
    char buf[BUFSIZE];
    int rc;
    int len;
    session_ctx* ctx;
    
    ctx = rw->data;
    
    //write_log( "server data arrived"  );
    
    rc = read( rw->fd, buf, sizeof(buf) );
    if( rc <= 0 )
    {
        close_session( loop, ctx );
        return;
    }
    
    len = rc;
    if( speed_limit )
    {
        ctx->bytes += len;
        if( ctx->limit_start && ctx->bytes >= speed_limit )
        {
            //write_log( "suspend! bytes:%d", ctx->bytes );
            ev_io_stop( loop, &ctx->remote_read_ctx );
            ctx->suspend = 1;
        }
    }
    
    
    rc = write( ctx->cli_fd, buf, len );
    if( rc <= 0 )
    {
        close_session( loop, ctx );
        return;
    }

    if( rc != len )
    {
        //write_log( "[TIP] cli fd %d data write failed! %d bytes left, ", ctx->cli_fd, len - rc );
        ring_buffer_write( ctx->local_buf, buf + rc, len - rc );

            
        ev_io_stop( loop, &ctx->remote_read_ctx );
        ev_io_start( loop, &ctx->local_write_ctx );
        
    }
}

void srv_write_cb( struct ev_loop* loop, ev_io* rw, int revents )
{
    session_ctx* ctx;
    int opt;
    int size;
    int rc;
    char buf[BUFSIZE];
    socklen_t len;
    ctx = rw->data;
    
    if( ctx->connected == 0 )
    {
        len = sizeof(int);
        getsockopt( rw->fd, SOL_SOCKET, SO_ERROR, &opt, &len );
        if( opt ) /* connect to remote server failed */
        {
            write_log( "[ERR] connect to remote server failed! err:%s", strerror( opt ) );
            //ev_timer_stop( loop, &ctx->timer );
            close_session( loop, ctx );
            return;
        }
        
        ev_io_start( loop, &ctx->local_read_ctx );
        ev_io_start( loop, &ctx->remote_read_ctx );
        ev_io_stop( loop, &ctx->remote_write_ctx );
        
        ev_timer_stop( loop, &ctx->timer );
        
        ctx->connected = 1;
        if( speed_limit )
        {
            ev_timer_set( &ctx->timer, LIMIT_TIMEOUT, 0 );
            ev_timer_start( loop, &ctx->timer );           
        }
        
        //write_log( "connect to server ok." );
        
    }
    else
    {
    
        size = sizeof( buf );
        
        ring_buffer_peek( ctx->remote_buf, buf, &size );
        
        rc = write( rw->fd, buf, size );
        if( rc <= 0 )
        {
            close_session( loop, ctx );
            return;
        }
        
        ring_buffer_inc( ctx->remote_buf, rc );
        if( rc == size ) /* send compelete */
        {
            ev_io_start( loop, &ctx->local_read_ctx );
            ev_io_stop( loop, &ctx->remote_write_ctx );
            
        }
        
        
    }
    
    
    
    
}


int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int get_host_ip( const char* host, char* ip )
{
    struct hostent* ent;
    char* addr;
    unsigned char b1,b2,b3,b4;

     ent = gethostbyname( host );
    if( ent == NULL )
        return -1;
    addr = *ent->h_addr_list;
    if( !addr )
        return -1;
    b1 = addr[0];
    b2 = addr[1];
    b3 = addr[2];
    b4 = addr[3];

    sprintf( ip, "%d.%d.%d.%d", b1, b2, b3, b4 );
    return 0;
}

int tcp_accept( int lsnfd, char* ip, int* port )
{
    struct sockaddr_in addr;
    socklen_t len;
    int clifd;

    len=sizeof(addr);
    clifd=accept(lsnfd,(struct sockaddr*) &addr,&len);
    if(clifd==-1)
        return -1;
    
    
    len=sizeof(addr);
    
    *port=ntohs(addr.sin_port);
    sprintf(ip,"%s",inet_ntoa(addr.sin_addr));
    return clifd;
}

int write_log( char* fmt, ... )
{
    FILE* f;
    time_t t;
    struct tm* tm;
    va_list  ap;
    //struct timeval tmv;

    f = fopen( log_file, "a" );
    if( f == NULL )
        return -1;
    
    t = time( 0 );
    //gettimeofday( &tmv, NULL );
    
    tm = localtime( &t );
    
    if( *fmt )
    {
        va_start( ap, fmt );
        //fprintf(f,"[%02d-%02d %02d:%02d:%02d.%03d]  ",tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,tmv.tv_usec / 1000 );
        fprintf( f, "[%02d-%02d %02d:%02d:%02d]  ", tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec );
        vfprintf( f, fmt, ap);
        fprintf( f, "\n" );
        va_end( ap );
    }
    
    fclose( f );
    return 0;
}


int tcp_listen( char* ip, int port )
{
/* ip 表示绑定在哪个ip 上，如果为NULL,表示绑定在所有ip 上，
如果不为null,则绑定在指定ip地址上: 
函数调用成功返回 socket fd, 否则返回 -1  */

    int fd;
    struct sockaddr_in addr;

    fd = socket( AF_INET, SOCK_STREAM, 0 );
    if( fd == -1 )
    {
        return -1;
    }

    int reuse=1;
    setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse) );
    
    addr.sin_family = AF_INET;
    addr.sin_port   = htons( port );

    if(ip == NULL || ip[0] == '*' )
    {
        addr.sin_addr.s_addr = INADDR_ANY;
        if( bind( fd, (struct sockaddr*)&addr, sizeof(addr) ) == -1 )
        {
            close( fd );
            return -1;
        }
    }
    else /*绑定ip  */
    {
        addr.sin_addr.s_addr = inet_addr(ip);
        if( bind( fd, (struct sockaddr*)&addr, sizeof(addr) ) == -1 )
        {
            close( fd );
            return -1;
        }
    }

    if( listen( fd, 5 ) == -1 )
    {
        close( fd );
        return -1;
    }

    return fd;

}

void sig_cb( struct ev_loop* loop, ev_signal* w, int revents )
{
    ev_break (loop, EVBREAK_ALL);
    
}

void close_session( struct ev_loop* loop, session_ctx* ctx )
{
    
    conn_cnt--;
    
    if( conn_cnt == 0 )
        write_log( "all connection closed." );
    else
        write_log( "session closed." );
    ev_io_stop( loop, &ctx->local_read_ctx );
    ev_io_stop( loop, &ctx->local_write_ctx );
    ev_io_stop( loop, &ctx->remote_read_ctx );
    ev_io_stop( loop, &ctx->remote_write_ctx );
    
    ev_timer_stop( loop, &ctx->timer );
    
    close( ctx->cli_fd );
    close( ctx->srv_fd );
    free( ctx );
    return;
    
}

int file_exist( char* name )
{
    int ret;
    
    ret = access( name, F_OK );
    if( ret == 0 )
        return 1;
    else
        return 0;
}

int hex2asc( char* hex, int len, char* buf, int buflen )
{
    char bits[] = "0123456789abcdef";
    
    unsigned char u;
    int i;

    if( buflen < len * 2 )
        return -1;
    buf[len*2]=0;
    
    for( i = 0; i < len; i++ )
    {
        u = hex[i];
        
        buf[i*2+0] = bits[ u >> 4 ];
        buf[i*2+1] = bits[ u & 0x0f ];
    }
    
    return 0;
    
}

char* strtrim(char* str)
{
    int idx;
    idx = strlen(str)-1;
    
    while( idx >= 0 && ( str[idx]== ' ' || str[idx]== '\r' || str[idx]== '\n' || str[idx]== '\t' ) )
    {
        str[idx]=0;
        idx --;
    }
    
    return str;
    
}

void load_blacklist()
{
    unsigned char sum[16];
    char ip[16];
    char line[100];
    char auth[32+1];
    FILE* f;
    rbnode* n;
    node_ip* node;
    
    
    use_blacklist = 0;
    int changed = 0;
    
    if( file_exist( GLOBAL_BLACK_LIST ) )
    {
        use_blacklist = 1;
        md5_file( GLOBAL_BLACK_LIST, sum );
        hex2asc( (char*)sum, 16, auth, sizeof( auth ) );
        
        if( strcmp( global_blacklist_sum, auth ) )
            changed = 1;
        strcpy( global_blacklist_sum, auth );
    }
    else
    {
        if( strlen( global_blacklist_sum ) > 0 )
            changed = 1;
        global_blacklist_sum[0] = 0;
    }
    
    if( file_exist( priv_blacklist_file ) )
    {
        use_blacklist = 1;
        md5_file( priv_blacklist_file, sum );
        hex2asc( (char*)sum, 16, auth, sizeof( auth ) );
        
        if( strcmp( priv_blacklist_sum, auth ) )
            changed = 1;
        strcpy( priv_blacklist_sum, auth );
    }
    else
    {
        if( strlen( priv_blacklist_sum ) > 0 )
            changed = 1;
        priv_blacklist_sum[0] = 0;
    }
    
    if( changed )
    {
        write_log( "load ip black list.." );
        rbtree_free( &black_list, free_ip_proc );
        
        f = fopen( GLOBAL_BLACK_LIST, "r" );
        if( f )
        {
            while( fgets( line, sizeof(line), f ) )
            {
                strtrim( line );
                if( check_ip( line ) )
                {
                    write_log( "[TIP] invalid ip:%s", line );
                    continue;
                }
                
                n = rbtree_find( &black_list, line );
                if( !n )
                {
                    node = smart_list_pop_back( &ip_list );
                    if( node == NULL )
                    {
                        node = malloc( sizeof( node_ip ) );
                        if( node == NULL )
                        {
                            write_log( "[WRN] malloc memory failed for ip node!" );
                            continue;
                        }
                    }
                    
                    write_log( "add ip '%s' to balck list.", line );
                    snprintf( node->ip, sizeof(ip), "%s", line );
                    rbtree_insert( &black_list, (rbnode*)node );
                    
                }
            }
            
            fclose( f );
        }
        

        f = fopen( priv_blacklist_file, "r" );
        if( f )
        {
            while( fgets( line, sizeof(line), f ) )
            {
                strtrim( line );
                if( check_ip( line ) )
                {
                    write_log( "[TIP] invalid ip:%s", line );
                    continue;
                }
                
                n = rbtree_find( &black_list, line );
                if( !n )
                {
                    node = smart_list_pop_back( &ip_list );
                    if( node == NULL )
                    {
                        node = malloc( sizeof( node_ip ) );
                        if( node == NULL )
                        {
                            write_log( "[WRN] malloc memory failed for ip node!" );
                            continue;
                        }
                    }
                    
                    write_log( "add ip '%s' to balck list.", line );
                    snprintf( node->ip, sizeof(ip), "%s", line );
                    rbtree_insert( &black_list, (rbnode*)node );
                    
                }
            }
            
            fclose( f );
        }
        
    }
    
    
    
}

void load_whitelist()
{
    unsigned char sum[16];
    char ip[16];
    char line[100];
    char auth[32+1];
    FILE* f;
    rbnode* n;
    node_ip* node;
    
    
    use_whitelist = 0;
    int changed = 0;
    
    if( file_exist( GLOBAL_WHITE_LIST ) )
    {
        use_whitelist = 1;
        md5_file( GLOBAL_WHITE_LIST, sum );
        hex2asc( (char*)sum, 16, auth, sizeof( auth ) );
        
        if( strcmp( global_whitelist_sum, auth ) )
            changed = 1;
        strcpy( global_whitelist_sum, auth );
    }
    else
    {
        if( strlen( global_whitelist_sum ) > 0 )
            changed = 1;
        global_whitelist_sum[0] = 0;
    }
    
    if( file_exist( priv_whitelist_file ) )
    {
        use_whitelist = 1;
        md5_file( priv_whitelist_file, sum );
        hex2asc( (char*)sum, 16, auth, sizeof( auth ) );
        
        if( strcmp( priv_whitelist_sum, auth ) )
            changed = 1;
        strcpy( priv_whitelist_sum, auth );
    }
    else
    {
        if( strlen( priv_whitelist_sum ) > 0 )
            changed = 1;
        priv_whitelist_sum[0] = 0;
        
    }
    
    if( changed )
    {
        write_log( "load ip white list.." );
        rbtree_free( &white_list, free_ip_proc );
        
        f = fopen( GLOBAL_WHITE_LIST, "r" );
        if( f )
        {
            while( fgets( line, sizeof(line), f ) )
            {
                strtrim( line );
                if( check_ip( line ) )
                {
                    write_log( "[TIP] invalid ip:%s", line );
                    continue;
                }
                
                n = rbtree_find( &white_list, line );
                if( !n )
                {
                    node = smart_list_pop_back( &ip_list );
                    if( node == NULL )
                    {
                        node = malloc( sizeof( node_ip ) );
                        if( node == NULL )
                        {
                            write_log( "[WRN] malloc memory failed for ip node!" );
                            continue;
                        }
                    }
                    
                    write_log( "add ip '%s' to white list.", line );
                    snprintf( node->ip, sizeof(ip), "%s", line );
                    rbtree_insert( &white_list, (rbnode*)node );
                    
                }
            }
            
            fclose( f );
        }
        

        f = fopen( priv_whitelist_file, "r" );
        if( f )
        {
            while( fgets( line, sizeof(line), f ) )
            {
                strtrim( line );
                if( check_ip( line ) )
                {
                    write_log( "[TIP] invalid ip:%s", line );
                    continue;
                }
                
                n = rbtree_find( &white_list, line );
                if( !n )
                {
                    node = smart_list_pop_back( &ip_list );
                    if( node == NULL )
                    {
                        node = malloc( sizeof( node_ip ) );
                        if( node == NULL )
                        {
                            write_log( "[WRN] malloc memory failed for ip node!" );
                            continue;
                        }
                    }
                    
                    write_log( "add ip '%s' to white list.", line );
                    snprintf( node->ip, sizeof(ip), "%s", line );
                    rbtree_insert( &white_list, (rbnode*)node );
                    
                }
            }
            
            fclose( f );
        }
        
    }
    
    
    
}


int  ip_node_cmp ( rbnode* node1, rbnode* node2 )
{
    node_ip *n1, *n2;
    
    n1 = (node_ip*)node1;
    n2 = (node_ip*)node2;
    
    return strcmp( n1->ip, n2->ip );

}

int  ip_value_cmp( void* value, rbnode* node )
{
    char* ip;
    node_ip* n;
    
    ip = value;
    n = (node_ip*)node;
    
    return strcmp( ip, n->ip );
}

void ip_node_swap( rbnode* node1, rbnode* node2  )
{
    node_ip *n1, *n2;
    char ip[16];
    
    n1 = (node_ip*)node1;
    n2 = (node_ip*)node2;
    
    strcpy( ip, n1->ip );
    strcpy( n1->ip, n2->ip );
    strcpy( n2->ip, ip );
    
}


int check_ip( char* ip )
{
    int len;
    char* p;
    int i;
    int dot_cnt = 0;
    char* dot[3];
    char buf[16];
    int val;
    
    len = strlen( ip );
    
    if( len < 7 || len > 15 )
        return -1;
    
    strcpy( buf, ip );
    
    p = buf;
    for( i = 0; i < len; i++ )
    {
        switch( p[i] )
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                break;
            
            case '.':
                if( dot_cnt >= 3)
                    return -1;
                dot[dot_cnt] = p+i;
                dot_cnt ++;
                break;
            
            default:
                return -1;
        }
    }

    if( dot_cnt != 3 )
        return -1;
    
    p = buf;
    dot[0][0] = 0;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;

    p = dot[0]+1;
    dot[1][0] = 0;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;

    p = dot[1]+1;
    dot[2][0] = 0;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;

    p = dot[2]+1;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;
    
    return 0;
    
}

int init_access_ctrl()
{
    rbnode node;
    int prev_offset;
    int next_offset;
    node_ip* ip;
    
    int i;
    
    snprintf( priv_blacklist_file, sizeof(priv_blacklist_file), "ip_blacklist_%d.txt", port );
    snprintf( priv_whitelist_file, sizeof(priv_whitelist_file), "ip_whitelist_%d.txt", port );
    
    rbtree_init( &black_list, ip_node_cmp, ip_value_cmp, ip_node_swap );
    rbtree_init( &white_list, ip_node_cmp, ip_value_cmp, ip_node_swap );
    
    prev_offset = (void*)&node.left  - (void*)&node;
    next_offset = (void*)&node.right - (void*)&node;
    smart_list_init( &ip_list, prev_offset, next_offset );
    
    global_blacklist_sum[0] = 0;
    priv_blacklist_sum[0] = 0;

    global_whitelist_sum[0] = 0;
    priv_whitelist_sum[0] = 0;
    
    for( i = 0; i < 100; i++ )
    {
        ip = malloc( sizeof(node_ip) );
        if( !ip )
            return -1;
        smart_list_push_back( &ip_list, (void*)ip );
    }
    
    return 0;
    
}

void free_ip_proc( rbnode* node )
{
    void* p = node;
    smart_list_push_back( &ip_list, p );
}

