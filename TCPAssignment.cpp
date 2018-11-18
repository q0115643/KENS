/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

//#define DEBUG

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol)
{
	/* createFileDescriptor
	 * Create a file descriptor for a certain process.
	 * The created file descriptor is automatically bound to the domain and protocol of this module.
	 */
	int socketfd = this->createFileDescriptor(pid);
	// add in socket info list
	struct Global_Context context;
	context.pid = pid;
	context.socketfd = socketfd;
	context.bound = false;
	context.seq_num = 0;
	this->context_list.push_back(context);
	/*
	 * Unblocks a blocked system call with return value.
	 */
	this->returnSystemCall(syscallUUID, socketfd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socketfd)
{
#ifdef DEBUG
	printf("SYSCALL_CLOSE()\n");
#endif
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd); // 음..
	if(this->error_if_none(syscallUUID, it)) return; // accept보다 close가 먼저 불릴 일은 없음.
	// client는
	// ESTAB 일 때 FIN 보내고 FIN_WAIT_1 상태로 변화
	// server면
	// CLOSE_WAIT 일 때 FIN packet 보내고 LAST_ACK 상태로 변화
	// 나머지는 바로 종료
	Packet *fin_packet;
	uint8_t fin_flag;
	uint32_t seq_num;
	// state 기준으로 나누면 안됨. server한테 close가 먼저 불리고 fin이 올 수가 있음
	// 그럼 그 server는 ESTAB 상태에서 fin보다 close를 먼저 받고 client마냥 작동해버림.
	// global context에 bool 하나 넣어 보자. (적어도 ESTAB까지는 가니까 그리로 바꿀 때 true로 만들기)
	// ESTAB가 server면 기다려야됨... FIN받고 CLOSE_WAIT 될 때까지
	if(it->state == E::ESTABLISHED || it->state == E::CLOSE_WAIT)
	{
		fin_flag = FIN_FLAG;
		seq_num = it->seq_num++;
		fin_packet = this->write_packet(fin_flag, seq_num, 0, it->src_port, it->dest_port, it->src_addr, it->dest_addr);
  	if(it->state == E::ESTABLISHED)
  	{
#ifdef DEBUG
				printf("FIN_WAIT_1으로 상태를 바꿈\n");
#endif
				it->state = E::FIN_WAIT_1;
  	}
  	else 	// CLOSE_WAIT
  	{
#ifdef DEBUG
			printf("LAST_ACK으로 상태를 바꿈\n");
#endif
  		it->state = E::LAST_ACK;
  	}
		it->waiting_state.wakeup_ID = syscallUUID;
#ifdef DEBUG
		printf("FIN 패킷을 보냄\n");
#endif
		this->sendPacket("IPv4", fin_packet);
		return;
	}
	else
	{
#ifdef DEBUG
		//printf("close에서 estab, close_wait이 아닌 게 꺼짐\n");
#endif
		this->context_list.erase(it);
		this->removeFileDescriptor(pid, socketfd);
		this->returnSystemCall(syscallUUID, 0);
	}
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int socketfd, struct sockaddr *addr, socklen_t addrlen)
{
	in_addr_t serv_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	in_port_t serv_port = ((struct sockaddr_in *)addr)->sin_port;
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	if(!it->bound)
	{
		// implicit binding
		in_addr_t local_addr;
		int index = this->getHost()->getRoutingTable((uint8_t *)&serv_addr);	// get index from Routing Table by server address
		this->getHost()->getIPAddr((uint8_t *)&local_addr, index);	// put address value in local_addr
		it->src_addr = local_addr;
		it->src_port = this->get_random_port();
		it->bound = true;
	}
	uint32_t seq_num = it->seq_num++;
	uint32_t ack_num = 0;
	uint8_t syn_flag = SYN_FLAG;
	// send SYN, 14 byte Ether header + 20 byte Ipv4 header + 20 byte TCP header
	Packet *syn_packet = this->write_packet(syn_flag, seq_num, ack_num, it->src_port, serv_port, it->src_addr, serv_addr);
	it->dest_addr = serv_addr;
	it->dest_port = serv_port;
	it->state = E::SYN_SENT;
	// remember UUID for returnSystemCall(syscallUUID, 0) in packetArrived()
	it->waiting_state.wakeup_ID = syscallUUID;
	// send SYN
#ifdef DEBUG
	printf("SYN 패킷을 보냄\n");
#endif
	this->sendPacket("IPv4", syn_packet);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int socketfd, int backlog)
{
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	if(this->error_if_not_bound(syscallUUID, it)) return;
	it->state = E::LISTEN;
	it->backlog = (unsigned int)backlog;
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int listenfd, struct sockaddr *addr, socklen_t *addrlen)
{
#ifdef DEBUG
	printf("SYSCALL_ACCEPT()\n");
#endif
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, listenfd);
	if(this->error_if_none(syscallUUID, it)) return;
	if(this->error_if_state_diff(syscallUUID, it, E::LISTEN)) return;
	if(it->established_list.empty())
	{
		it->waiting_state.wakeup_ID = syscallUUID;
		it->waiting_state.wakeup_addr = addr;
		it->waiting_state.wakeup_addrlen = addrlen;
		it->waiting = true;
		return;
	}
	// listen으로 된 것들 중 connect와 악수 완료인 것이 있는 경우.
	int newfd = this->createFileDescriptor(pid);
	struct Global_Context established_context = it->established_list.front();
	it->established_list.pop_front();
	established_context.pid = pid;
	established_context.socketfd = newfd;
	((struct sockaddr_in *) addr)->sin_family = AF_INET;
	((struct sockaddr_in *) addr)->sin_addr.s_addr = established_context.dest_addr;
	((struct sockaddr_in *) addr)->sin_port = established_context.dest_port;
	this->context_list.push_back(established_context);
	this->returnSystemCall(syscallUUID, newfd);
}

/* bind() gives the socket socketfd the local address myaddr. (we assume there are only IPv4 addresses => AF_INET, sockaddr_in) */ 
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socketfd, struct sockaddr *myaddr, socklen_t addrlen)
{
	in_addr_t src_addr = ((struct sockaddr_in *)myaddr)->sin_addr.s_addr;
	in_port_t src_port = ((struct sockaddr_in *)myaddr)->sin_port;
	std::list<struct Global_Context>::iterator it;
	it = this->find_invalid_bind(pid, socketfd, src_addr, src_port);
	// if invalid
	if(this->error_if_exist(syscallUUID, it)) return;
	// bind current pid, socketfd to ip address and port number and push to the global context list
	std::list<struct Global_Context>::iterator it2;
	it2 = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it2)) return;
	it2->src_addr = src_addr;
	it2->src_port = src_port;
	it2->bound = true;
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socketfd, struct sockaddr *myaddr, socklen_t *addrlen)
{
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd);
	// there is no appropriate
	if(this->error_if_none(syscallUUID, it)) return;
	((struct sockaddr_in *) myaddr)->sin_family = AF_INET;
	((struct sockaddr_in *) myaddr)->sin_addr.s_addr = it->src_addr;
	((struct sockaddr_in *) myaddr)->sin_port = it->src_port;
	*addrlen = sizeof(struct sockaddr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int socketfd, struct sockaddr *addr, socklen_t *addrlen)
{
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	((struct sockaddr_in *) addr)->sin_family = AF_INET;
	((struct sockaddr_in *) addr)->sin_addr.s_addr = it->dest_addr;
	((struct sockaddr_in *) addr)->sin_port = it->dest_port;
	*addrlen = sizeof (struct sockaddr);
	this->returnSystemCall(syscallUUID, 0);
}

/******************
 **	read & write **
 ******************/
/*
void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int socketfd, void *buf, int count)
{
	// data 올 때까지 block
	// pending read()가 있으면 data 전달하고 return
	// data 받았는데 pending read() 없으면 data buffer에 넣어둠
	// buffer 빈공간합 == my window size
	// ACK packet에 쓰기
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	if(it->state != E::ESTABLISHED)
	{
#ifdef DEBUG
		printf("ESTAB 아닌데 write해서 에러\n");
#endif
		this->returnSystemCall(syscallUUID, -1);
    return;
	}

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int socketfd, void *buf, int count)
{
	// internal buffer 만들어서 ACK 안 온 것들 가지고 있어야함
	// internal buffer가 full이면 write을 block해놔야함
	// 	buffer에 공간 생기면 풀어주기
	// Sum(total_unacked_bytes) 는 peer의 window size(rwnd)보다 작아야함 => 얘네는 이미 보낸 애들 말하는 거임.
	std::list<struct Global_Context>::iterator it;
	uint8_t ack_flag = ACK_FLAG;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	if(it->state != E::ESTABLISHED)
	{
#ifdef DEBUG
		printf("ESTAB 아닌데 write해서 에러\n");
#endif
		this->returnSystemCall(syscallUUID, -1);
    return;
	}
	// uint16_t window = it->window;
	int sending_count = 0;
	// packet들 만들어 놓고 it->waiting_queue에 넣기
	int rest = count;
	int send_idx = 0;
#ifdef DEBUG
	printf("쓰라고 한 count %d, ", count);
	printf("window 크기 %u\n", it->window);
#endif
	while(rest)
	{
		if(rest > MSS)
			sending_count = MSS;
		else
			sending_count = rest;
#ifdef DEBUG
		printf("저장하는 바이트 수 %d\n", sending_count);
#endif
		Packet *waiting_packet = this->allocatePacket(54 + sending_count);
		struct TCP_Header *wait_tcp_header = (struct TCP_Header *) malloc (sizeof (struct TCP_Header));
		wait_tcp_header->window = htons(51200);
		wait_tcp_header->headerLen_reservedField = DEFAULT_HDL_RESERVED;
		wait_tcp_header->urgent_pointer = 0;
		waiting_packet->writeData(14+12, &it->src_addr, 4);
		waiting_packet->writeData(14+16, &it->dest_addr, 4);
		wait_tcp_header->flags = ack_flag;
		wait_tcp_header->seq_num = htonl(this->transfer_base);
		wait_tcp_header->ack_num = htonl(this->rand_seq_num);
		wait_tcp_header->src_port = it->src_port;
		wait_tcp_header->dest_port = it->dest_port;
		wait_tcp_header->checksum = 0;
		uint16_t checksum = NetworkUtil::tcp_sum(it->src_addr, it->dest_addr, (uint8_t *)wait_tcp_header, 20+sending_count);
		checksum = ~checksum;
		if (checksum == 0xFFFF) checksum = 0;
		waiting_packet->writeData(14+20, wait_tcp_header, 20);
		waiting_packet->writeData(54, (void*)((char*)buf + send_idx), sending_count);
		it->waiting_queue.push_back(waiting_packet);
		this->transfer_base += sending_count;
		rest -= sending_count;
	}
	while(it->sent_bytes < it->window && !it->waiting_queue.empty())
	{
#ifdef DEBUG
		printf("sent_bytes %d, it->window %u\n", it->sent_bytes, it->window);
#endif
		Packet *data_packet = it->waiting_queue.front();
		it->waiting_queue.pop_front();
		int payload_size = data_packet->getSize()-54;
#ifdef DEBUG
		printf("보내는 패킷 사이즈 %d\n", payload_size);
#endif
		it->sent_bytes += payload_size;
		this->sendPacket("IPv4", data_packet);
		//this->freePacket(data_packet);
		if(it->waiting_queue.empty())
		{
#ifdef DEBUG
			printf("리턴해버림 %d\n", count);
#endif
			returnSystemCall(syscallUUID, count);
			return;
		}
	}
	it->waiting_state.wakeup_ID = syscallUUID;
	it->waiting_state.count = count;
#ifdef DEBUG
	printf("블락시킴\n");
#endif
}
*/

/***********************************
 **	packetArrived & timerCallback **
 ***********************************/	

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	// swap src and dest on read
	in_addr_t src_addr;
	in_addr_t dest_addr;
	uint8_t rcv_flags;
	uint32_t rcv_seq_num;
	uint32_t rcv_ack_num;
	in_port_t src_port;
	in_port_t dest_port;
	uint16_t rcv_window;
	uint32_t payload_size = packet->getSize()-54;
	packet->readData(14+12, &dest_addr, 4);
	packet->readData(14+16, &src_addr, 4);	// addr 바꿔서 읽기
	// get TCP Header
	packet->readData(14+20+0, &dest_port,2);
	packet->readData(14+20+2, &src_port,2);	// port 바꿔서 읽기
	packet->readData(14+20+4, &rcv_seq_num,4);
	packet->readData(14+20+8, &rcv_ack_num, 4);
	packet->readData(14+20+13, &rcv_flags, 1);
	packet->readData(14+20+14, &rcv_window, 2);
	this->freePacket(packet);
	rcv_seq_num = ntohl(rcv_seq_num);
	rcv_ack_num = ntohl(rcv_ack_num);
	rcv_window = ntohs(rcv_window);
	bool SYN = bool(rcv_flags & SYN_FLAG);
	bool ACK = bool(rcv_flags & ACK_FLAG);
	bool FIN = bool(rcv_flags & FIN_FLAG);
#ifdef DEBUG
	printf("packetArrived: 도착한 패킷은 ");
	if(SYN) printf("SYN ");
	if(ACK) printf("ACK ");
	if(FIN) printf("FIN ");
	printf("\n");
#endif
	// dest_addr == context->rmt_addr, src_addr == context->src_addr, port도, 그런 context를 찾아 와야 함
	std::list<struct Global_Context>::iterator it;
	std::list<struct Global_Context>::iterator estab_it;
	bool found = true;
	it = this->find_connected_pair(src_addr, src_port, dest_addr, dest_port);
	if(it==this->context_list.end())
	{
		it = this->find_free_pair(src_addr, src_port, dest_addr, dest_port, &found); // established list까지 뒤졌음.
	}
	if(!it->window) it->window = rcv_window;
	STATE state = E::CLOSED;
	if(found) state = it->state;
	else printf("\t\t\t\t\t****패킷이 왔는데 받을 소켓을 찾지 못함*****\n");
#ifdef DEBUG
	printf("받은 socket의 state는 ");
#endif
	switch(state)
	{
		case E::LISTEN:	// server가 받은 것, SYN 받았으면 SYN, ACK 보내고 SYN_RCVD로 바꾸기, context pending_list로 넣기
#ifdef DEBUG
			printf("LISTEN\n");
#endif
			if(SYN)
			{
				if(it->pending_list.size() >= it->backlog) break;
				uint8_t syn_ack_flag = SYN_FLAG | ACK_FLAG;
				// adjust new packet and write
				Packet* syn_ack_packet = this->write_packet(syn_ack_flag, it->seq_num, rcv_seq_num+1, src_port, dest_port, src_addr, dest_addr);
  			// new context to put in pending_list
  			struct Global_Context new_context;
  			// pid, socketfd는 accept될 때 저장됨
  			new_context.src_addr = src_addr;
  			new_context.src_port = src_port;
  			new_context.bound = true;
  			new_context.dest_addr = dest_addr;
  			new_context.dest_port = dest_port;
  			new_context.seq_num = ++it->seq_num;
  			it->pending_list.push_back(new_context);
  			// send packet
#ifdef DEBUG
				printf("SYN ACK 패킷을 보냄\n");
#endif
  			this->sendPacket("IPv4", syn_ack_packet);
			}
			else if(ACK)
			{
				// SYN_RCVD context는 pending_list 안에 있다. 찾아 봐야함
				std::list<struct Global_Context>::iterator it2;
				for (it2 = it->pending_list.begin(); it2 != it->pending_list.end(); it2++)
				{
					if (it2->seq_num == rcv_ack_num) break;	// 전달받은 ack_num의 -1한 값이 해당 seq_num 이어야 함
				}
				if(it2 != it->pending_list.end())
				{
					struct Global_Context new_context;
					new_context = *it2;
					it->pending_list.erase(it2);
					new_context.state = E::ESTABLISHED;
					it->established_list.push_back(new_context);
				}
				else
				{
					printf("\t\t\t\t\t****Pending List에서 소켓을 찾지 못함*****\n");
				}
				if(it->waiting)
				{
					// wakeup blocked states for accept
					it->waiting = false;
					if(!it->established_list.empty())
					{
						struct Global_Context established_context = it->established_list.front();
						it->established_list.pop_front();
						int newfd = this->createFileDescriptor(it->pid);
						established_context.pid = it->pid;
						established_context.socketfd = newfd;
						struct sockaddr *addr_woke = it->waiting_state.wakeup_addr;
						((struct sockaddr_in *) addr_woke)->sin_family = AF_INET;
						((struct sockaddr_in *) addr_woke)->sin_addr.s_addr = established_context.dest_addr;
						((struct sockaddr_in *) addr_woke)->sin_port = established_context.dest_port;
						this->context_list.push_back(established_context);
						this->returnSystemCall(it->waiting_state.wakeup_ID, newfd);
					}
				}
			}
			break;
		case E::SYN_SENT:
#ifdef DEBUG
			printf("SYN_SENT\n");
#endif
			if(SYN && ACK)
			{
				if(rcv_ack_num != it->seq_num)
				{
#ifdef DEBUG
					printf("***********ack 숫자가 보낸 거랑 달라서 리턴해버림.\n");
#endif
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
				uint8_t ack_flag = ACK_FLAG;
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, rcv_seq_num+1, src_port, dest_port, src_addr, dest_addr);
#ifdef DEBUG
				printf("ESTABLISHED으로 상태를 바꿈\n");
#endif
  			it->state = E::ESTABLISHED; // 얘는 client
#ifdef DEBUG
				printf("ACK 패킷을 보냄\n");
#endif
  			this->sendPacket("IPv4", ack_packet);
				this->returnSystemCall(it->waiting_state.wakeup_ID, 0);
			}
			break;
		case E::ESTABLISHED:
#ifdef DEBUG
			printf("ESTABLISHED\n");
#endif
			if(FIN)	// server 가 FIN 받고 ACK 보내고 CLOSE_WAIT 으로 변경
			{
				uint8_t ack_flag = ACK_FLAG;
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, rcv_seq_num+1, src_port, dest_port, src_addr, dest_addr);
#ifdef DEBUG
				printf("CLOSE_WAIT으로 상태를 바꿈\n");
#endif
  			it->state = E::CLOSE_WAIT;
#ifdef DEBUG
				printf("ACK 패킷을 보냄\n");
#endif
  			this->sendPacket("IPv4", ack_packet);
			}
			/*
			if(ACK)
			{
				// data transfer
				// read로 ACK 온 거임
				if(payload_size == 0)
				{	
					it->sent_bytes -= MSS;
					while(it->sent_bytes < it->window && !it->waiting_queue.empty())
					{
						Packet *data_packet = it->waiting_queue.front();
						it->waiting_queue.pop_front();
						int payload_size1 = data_packet->getSize()-54;
						it->sent_bytes += payload_size1;
						this->sendPacket("IPv4", data_packet);
						//this->freePacket(data_packet);
						if(it->waiting_queue.empty())
						{
							returnSystemCall(it->waiting_state.wakeup_ID, it->waiting_state.count);
							return;
						}
					}
				}
			}
			*/
			break;
		case E::FIN_WAIT_1:
#ifdef DEBUG
			printf("FIN_WAIT_1\n");
#endif
			if(ACK)
			{	
				if(rcv_ack_num != it->seq_num)
				{
#ifdef DEBUG
					printf("***********ack 숫자가 보낸 거랑 달라서 리턴해버림.\n");
#endif
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
#ifdef DEBUG
				printf("FIN_WAIT_2으로 상태를 바꿈\n");
#endif
				it->state = E::FIN_WAIT_2;
			}
			if(FIN)	// 1.ACK&&FIN  2.FIN 	둘다 ACK 을 보내지만, 1은 TIMED_WAIT, 2는 CLOSING
			{
				uint8_t ack_flag = ACK_FLAG;
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, rcv_seq_num+1, src_port, dest_port, src_addr, dest_addr);
#ifdef DEBUG
				printf("ACK 패킷을 보냄\n");
#endif
  			this->sendPacket("IPv4", ack_packet);
				if(it->state == E::FIN_WAIT_1)
				{
#ifdef DEBUG
					printf("CLOSING으로 상태를 바꿈\n");
#endif
					it->state = CLOSING;
				}
				else if(it->state == E::FIN_WAIT_2)
				{
#ifdef DEBUG
					printf("TIMED_WAIT으로 상태를 바꿈\n");
#endif
					it->state = TIMED_WAIT;
					// timer?
					struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
					timer_state->pid = it->pid;
					timer_state->socketfd = it->socketfd;
					this->removeFileDescriptor(it->pid, it->socketfd);	// socket 먼저 닫음
					this->addTimer((void *)timer_state, TimeUtil::makeTime(MSL, TimeUtil::MSEC));
				}
			}
			break;
		case E::LAST_ACK:
#ifdef DEBUG
			printf("LAST_ACK\n");
#endif
			if(ACK)
			{
				if(rcv_ack_num != it->seq_num)
				{
#ifdef DEBUG
					printf("***********ack 숫자가 보낸 거랑 달라서 리턴해버림.\n");
#endif
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
				this->removeFileDescriptor(it->pid, it->socketfd);
				UUID syscallUUID = it->waiting_state.wakeup_ID;
				this->context_list.erase(it);
				this->returnSystemCall(syscallUUID, 0);
			}
			break;
		case E::FIN_WAIT_2:
#ifdef DEBUG
			printf("FIN_WAIT_2\n");
#endif
			if(FIN)	// client 가 FIN 받고 ACK 보내고 TIMED_WAIT 으로 변경
			{
				uint8_t ack_flag = ACK_FLAG;
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, rcv_seq_num+1, src_port, dest_port, src_addr, dest_addr);
#ifdef DEBUG
				printf("ACK 패킷을 보냄\n");
#endif
  			this->sendPacket("IPv4", ack_packet);
#ifdef DEBUG
				printf("TIMED_WAIT으로 상태를 바꿈\n");
#endif
  			it->state = E::TIMED_WAIT;
  			// timer?
  			struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
				timer_state->pid = it->pid;
				timer_state->socketfd = it->socketfd;
				this->removeFileDescriptor(it->pid, it->socketfd);	// socket 먼저 닫음
				this->addTimer((void *)timer_state, TimeUtil::makeTime(MSL, TimeUtil::MSEC));
			}
			break;
		case E::CLOSING:
#ifdef DEBUG
			printf("CLOSING\n");
#endif
			if(ACK)
			{
				if(rcv_ack_num != it->seq_num)
				{
#ifdef DEBUG
					printf("***********ack 숫자가 보낸 거랑 달라서 리턴해버림.\n");
#endif
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
#ifdef DEBUG
				printf("TIMED_WAIT으로 상태를 바꿈\n");
#endif
				it->state = E::TIMED_WAIT;
				// timer?
				struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
				timer_state->pid = it->pid;
				timer_state->socketfd = it->socketfd;
				this->removeFileDescriptor(it->pid, it->socketfd);	// socket 먼저 닫음
				this->addTimer((void *)timer_state, TimeUtil::makeTime(MSL, TimeUtil::MSEC));
			}
			break;
		case E::TIMED_WAIT:
#ifdef DEBUG
			printf("TIMED_WAIT\n");
#endif
			if(FIN)	// client 가 FIN 받고 ACK 보내고 기다렸다가 CLOSE
			{
				// timer 여기서는? ㄴㄴ 어짜피 여기서 close 안 일어나고 timerCallback에서만 close됨
				// 여기서는 fin이 또 오는거니까 ack이 안 갔다고 가정하고 다시 보냄
				uint8_t ack_flag = ACK_FLAG;
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, rcv_seq_num+1, src_port, dest_port, src_addr, dest_addr);
#ifdef DEBUG
				printf("ACK 패킷을 보냄\n");
#endif
  			this->sendPacket("IPv4", ack_packet);
			}
			break;
		default:
			break;
	}
}

void TCPAssignment::timerCallback(void* payload)
{
#ifdef DEBUG
	printf("timerCallback 걸림: ");
#endif
	// payload로 global context 찾아서 packet 보내는 handling
	struct Timer_State* timer_state = (struct Timer_State*) payload;
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(timer_state->pid, timer_state->socketfd);
	if(it->state == E::TIMED_WAIT)
	{
#ifdef DEBUG
		printf("TIMED_WAIT\n");
#endif
		free((struct Timer_State*)payload);
	 	UUID syscallUUID = it->waiting_state.wakeup_ID;
		this->context_list.erase(it);
		this->returnSystemCall(syscallUUID, 0);
	}
}


/********************
 **	help functions **
 ********************/									

std::list<struct Global_Context>::iterator TCPAssignment::find_pid_fd(int pid, int socketfd)
{
	std::list<struct Global_Context>::iterator it;
	it = std::find_if(this->context_list.begin(), this->context_list.end(), samePidSockFD(pid, socketfd));
	return it;
}
std::list<struct Global_Context>::iterator TCPAssignment::find_invalid_bind(int pid, int socketfd, in_addr_t src_addr, in_port_t src_port)
{
	std::list<struct Global_Context>::iterator it;
	it = std::find_if(this->context_list.begin(), this->context_list.end(), invalidBind(pid, socketfd, src_addr, src_port));
	return it;
}
std::list<struct Global_Context>::iterator TCPAssignment::find_connected_pair(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port)
{
	std::list<struct Global_Context>::iterator it;
	it = std::find_if(this->context_list.begin(), this->context_list.end(), findConnectedPair(src_addr, src_port, dest_addr, dest_port));
	return it;
}
std::list<struct Global_Context>::iterator TCPAssignment::find_free_pair(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port, bool* found)
{
	std::list<struct Global_Context>::iterator it;
	it = std::find_if(this->context_list.begin(), this->context_list.end(), findFreePair(src_addr, src_port));
	std::list<struct Global_Context>::iterator it2;
	if(it!=this->context_list.end())
	{
		for(it2 = it->established_list.begin(); it2!=it->established_list.end(); ++it2)
		{
			if(it2->src_addr == src_addr && it2->dest_port == dest_port && (it2->src_addr == src_addr || it2->src_addr == INADDR_ANY) && it2->dest_addr == dest_addr)
			{
				return it2;
			}
		}
	}
	if(it==this->context_list.end()) *found=false;
	return it;
}


bool TCPAssignment::error_if_none(UUID syscallUUID, std::list<struct Global_Context>::iterator it)
{
	if (it == this->context_list.end())
	{
		printf("\t\t\t\t\t****Context List에서 소켓을 찾지 못함*****\n");
		this->returnSystemCall(syscallUUID, -1);
		return true;
	}
	return false;
}

bool TCPAssignment::error_if_exist(UUID syscallUUID, std::list<struct Global_Context>::iterator it)
{
	if (it != this->context_list.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return true;
	}
	return false;
}

bool TCPAssignment::error_if_not_bound(UUID syscallUUID, std::list<struct Global_Context>::iterator it)
{
	if(!it->bound)
	{
		this->returnSystemCall(syscallUUID, -1);
		return true;
	}
	return false;
}

bool TCPAssignment::error_if_state_diff(UUID syscallUUID, std::list<struct Global_Context>::iterator it, E::STATE state)
{
	if(it->state != state)
	{
		this->returnSystemCall(syscallUUID, -1);
		return true;
	}
	return false;
}

int TCPAssignment::get_random_port()
{
	for(int i=LOCALPORT_MIN; i<LOCALPORT_MAX; i++)
	{
		std::list<int>::iterator it = std::find(this->bound_local_ports.begin(), this->bound_local_ports.end(), i);
		if(it == this->bound_local_ports.end())
		{
			this->bound_local_ports.push_back(i);
			return i;
		}
	}
	printf("How should I treat this error of Local Port filled...");
	return 0;
}

void TCPAssignment::free_local_port(int port)
{
	std::list<int>::iterator it = std::find(this->bound_local_ports.begin(), this->bound_local_ports.end(), port);
	if(it != this->bound_local_ports.end())
	{
		this->bound_local_ports.erase(it);
	}
}

Packet* TCPAssignment::write_packet(int8_t flag, uint32_t seq_num, uint32_t ack_num, in_port_t src_port, in_port_t dest_port, in_addr_t src_addr, in_addr_t dest_addr, uint16_t window_size, uint32_t payload_size, uint8_t* payload)
{
	uint8_t protocol = PROTO_TCP;
	uint8_t headerLen_reservedField = DEFAULT_HDL_RESERVED;
	uint16_t pk_window_size = htons(window_size);
	uint32_t pk_seq_num = htonl(seq_num);
	uint32_t pk_ack_num = htonl(ack_num);
	Packet *packet = this->allocatePacket(payload_size+54);
	packet->writeData(14+9, &protocol, 1);
	packet->writeData(14+12, &src_addr, 4);
	packet->writeData(14+16, &dest_addr, 4);
	packet->writeData(14+20+0, &src_port, 2);
	packet->writeData(14+20+2, &dest_port, 2);
	packet->writeData(14+20+4, &pk_seq_num, 4);
	packet->writeData(14+20+8, &pk_ack_num, 4);
	packet->writeData(14+20+12, &headerLen_reservedField, 1);
	packet->writeData(14+20+13, &flag, 1);
	packet->writeData(14+20+14, &pk_window_size, 2);
	if(payload_size > 0)
		packet->writeData(14+20+20, payload, payload_size);	
	// for Checksum
	uint8_t *temp = (uint8_t *)calloc(12+20+payload_size,1);
	uint16_t tcp_length = htons(payload_size+20);
	memcpy(temp, &src_addr, 4);
	memcpy(temp+4, &dest_addr, 4);
	memcpy(temp+9, &protocol, 1);
	memcpy(temp+10, &tcp_length, 2);
	//pseudo header
	packet->readData(14+20, temp+12, payload_size+20);
	//load tcp packet
	uint32_t sum = 0;
	uint16_t *pt = (uint16_t *)temp;
	for(unsigned int i=0; i<payload_size+32; i+=2){
		sum += *pt++;
		sum = (sum >> 16) + (sum & 0xffff);
	}
	uint16_t checksum = (uint16_t)(~sum); //1's complement
	packet->writeData(14+20+16, &checksum, 2); //reset checksum
	return packet;
}

}