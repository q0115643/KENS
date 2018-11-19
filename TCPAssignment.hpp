/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>
#include <E/E_TimeUtil.hpp>


#define LOCALPORT_MIN 32768
#define LOCALPORT_MAX 61000
#define SYN_FLAG 0x02
#define ACK_FLAG 0x10
#define FIN_FLAG 0x01
#define DEFAULT_WINDOW_SIZE 51200
#define DEFAULT_HDL_RESERVED 5 << 4
#define MSL 60  // 60second
#define MSS 512 // maximum segment size
#define PROTO_TCP 6
#define DEFAULT_SYN_TIMEOUT 100



namespace E
{
    enum STATE
    {
        CLOSED, LISTEN, ESTABLISHED, SYN_SENT, CLOSE_WAIT, LAST_ACK, FIN_WAIT_1, FIN_WAIT_2, TIMED_WAIT, CLOSING,
        SYN_RE
    };
    struct Waiting_State
    {
        UUID wakeup_ID;
        struct sockaddr *wakeup_addr;
        socklen_t *wakeup_addrlen;
        int count;
    };
    struct Timer_State
    {
        int pid;
        int socketfd;
        STATE state; 
        struct Global_Context* pending_context = NULL;
    };
    struct Read_State
    {
        UUID wakeup_ID;
        void* buffer;
        uint32_t count;
    };
    struct Send_Info
    {
        uint32_t seq_num;
        uint32_t expected_ack_num;
        Packet* packet;
    };
	struct Global_Context
	{
		int pid;
		int socketfd;
		in_addr_t src_addr;
		in_port_t src_port;
		bool bound;
        in_addr_t dest_addr;
        in_port_t dest_port;
        STATE state = CLOSED;
        unsigned int backlog;
        uint32_t seq_num = 0;
        uint32_t ack_num = 0;
        Waiting_State waiting_state;
        bool waiting = false;
        std::list<struct Global_Context> pending_list;
        std::list<struct Global_Context> established_list;
        uint16_t window = 0;
        int sent_bytes = 0;
        std::list<Packet*> waiting_writes;
        std::list<struct Read_State> waiting_reads;
        std::list<uint8_t> read_buffer;
        bool timer_running = false;
        UUID timer_key;
        std::list<struct Send_Info> send_buffer;
        uint32_t max_acked = 0;
	};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::list<struct Global_Context> context_list;
    std::list<int> bound_local_ports;

private:
	virtual void timerCallback(void* payload) final;
	/* syscall */
	void syscall_socket(UUID syscallUUID, int pid, int type, int protocol);
	void syscall_close(UUID syscallUUID, int pid, int socketfd);
    void syscall_connect(UUID syscallUUID, int pid, int socketfd, struct sockaddr *addr, socklen_t addrlen);
    void syscall_listen(UUID syscallUUID, int pid, int socketfd, int backlog);
    void syscall_accept(UUID syscallUUID, int pid, int listenfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_bind(UUID syscallUUID, int pid, int socketfd, struct sockaddr *myaddr, socklen_t addrlen);
	void syscall_getsockname(UUID syscallUUID, int pid, int socketfd, struct sockaddr *myaddr, socklen_t *addrlen);
    void syscall_getpeername(UUID syscallUUID, int pid, int socketfd, struct sockaddr *addr, socklen_t *addrlen);
    void syscall_read(UUID syscallUUID, int pid, int socketfd, void *buf, unsigned count);
    void syscall_write(UUID syscallUUID, int pid, int socketfd, const void *buf, unsigned count);
    /* help functions */
    std::list<struct Global_Context>::iterator find_pid_fd(int pid, int socketfd);
    std::list<struct Global_Context>::iterator find_pid_fd_bound(int pid, int socketfd);
    std::list<struct Global_Context>::iterator find_invalid_bind(int pid, int socketfd, in_addr_t src_addr, in_port_t src_port);
    std::list<struct Global_Context>::iterator find_connected_pair(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port);
    std::list<struct Global_Context>::iterator find_free_pair(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port, bool* found);
    bool error_if_none(UUID syscallUUID, std::list<struct Global_Context>::iterator it);
    bool error_if_exist(UUID syscallUUID, std::list<struct Global_Context>::iterator it);
    bool error_if_not_bound(UUID syscallUUID, std::list<struct Global_Context>::iterator it);
    bool error_if_state_diff(UUID syscallUUID, std::list<struct Global_Context>::iterator it, E::STATE state);
    int get_random_port();
    void free_local_port(int port);
    Packet* write_packet(int8_t flag, uint32_t seq_num, uint32_t ack_num, in_port_t src_port, in_port_t dest_port, in_addr_t src_addr, in_addr_t dest_addr, uint16_t window=51200, uint32_t payload_size=0, uint8_t* payload=NULL);
    uint16_t get_checksum(Packet* packet, in_addr_t src_addr, in_addr_t dest_addr, uint32_t payload_size);
public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

/************************
 ** for search classes **
 ************************/

class invalidBind
{
    int pid;
    int socketfd;
    in_addr_t src_addr;
    in_port_t src_port;

public:
    invalidBind(int pid, int socketfd, in_addr_t src_addr, in_port_t src_port)
    {
        this->pid = pid;
        this->socketfd = socketfd;
        this->src_addr = src_addr;
        this->src_port = src_port;
    }
    bool operator() (struct Global_Context& context)
    {
      return (context.bound && this->pid == context.pid && this->socketfd == context.socketfd) ||
                 (this->src_port == context.src_port &&
                   (this->src_addr == context.src_addr || this->src_addr == INADDR_ANY || context.src_addr == INADDR_ANY)
                 );
    }
};

class samePidSockFD
{
    int pid;
    int socketfd;

public:
    samePidSockFD(int pid, int socketfd)
    {
        this->pid = pid;
        this->socketfd = socketfd;
    }
    bool operator() (struct Global_Context& context)
    {
        return this->pid == context.pid && this->socketfd == context.socketfd;
    }
};

class findConnectedPair
{
    in_addr_t src_addr;
    in_port_t src_port;
    in_addr_t dest_addr;
    in_port_t dest_port;

public:
    findConnectedPair(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port)
    {
        this->src_addr = src_addr;
        this->src_port = src_port;
        this->dest_addr = dest_addr;
        this->dest_port = dest_port;
    }
    bool operator() (struct Global_Context& context)
    {
        return this->src_port == context.src_port && this->dest_port == context.dest_port &&
                    (this->src_addr == context.src_addr || context.src_addr == INADDR_ANY) &&
                    this->dest_addr == context.dest_addr;
    }
};
class findFreePair
{
    in_addr_t src_addr;
    in_port_t src_port;

public:
    findFreePair(in_addr_t src_addr, in_port_t src_port)
    {
        this->src_addr = src_addr;
        this->src_port = src_port;
    }
    bool operator() (struct Global_Context& context)
    {
        return this->src_port == context.src_port &&
                    (this->src_addr == context.src_addr || this->src_addr == INADDR_ANY || context.src_addr == INADDR_ANY);
    }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
