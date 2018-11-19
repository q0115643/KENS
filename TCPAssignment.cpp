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
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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
	int socketfd = this->createFileDescriptor(pid);
	struct Global_Context context;
	context.pid = pid;
	context.socketfd = socketfd;
	context.bound = false;
	context.seq_num = 0;
	this->context_list.push_back(context);
	this->returnSystemCall(syscallUUID, socketfd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socketfd)
{
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	Packet *fin_packet;
	uint8_t fin_flag;
	uint32_t seq_num;
	if(it->state == E::ESTABLISHED || it->state == E::CLOSE_WAIT)
	{
		fin_flag = FIN_FLAG;
		seq_num = it->seq_num++;
		fin_packet = this->write_packet(fin_flag, seq_num, 0, it->src_port, it->dest_port, it->src_addr, it->dest_addr);
  	if(it->state == E::ESTABLISHED)
  	{
				it->state = E::FIN_WAIT_1;
  	}
  	else 	// CLOSE_WAIT
  	{
  		it->state = E::LAST_ACK;
  	}
		it->waiting_state.wakeup_ID = syscallUUID;
		this->sendPacket("IPv4", fin_packet);
		return;
	}
	else
	{
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
	uint8_t syn_flag = SYN_FLAG;
	// send SYN, 14 byte Ether header + 20 byte Ipv4 header + 20 byte TCP header
	Packet *syn_packet = this->write_packet(syn_flag, seq_num, 0, it->src_port, serv_port, it->src_addr, serv_addr);
	it->dest_addr = serv_addr;
	it->dest_port = serv_port;
	it->state = E::SYN_SENT;
	// remember UUID for returnSystemCall(syscallUUID, 0) in packetArrived()
	it->waiting_state.wakeup_ID = syscallUUID;
	// send SYN
	struct Send_Info send_info;
	send_info.seq_num = seq_num;
	send_info.expected_ack_num = seq_num+1;
	send_info.packet = syn_packet;
	it->send_buffer.push_back(send_info);
	if(!it->timer_running)
	{
		struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
		timer_state->pid = it->pid;
		timer_state->socketfd = it->socketfd;
		timer_state->state = SYN_RE;
		UUID timer_key = this->addTimer((void *)timer_state, TimeUtil::makeTime(DEFAULT_SYN_TIMEOUT, TimeUtil::MSEC));
		it->timer_running = true;
		it->timer_key = timer_key;
	}
	this->sendPacket("IPv4", this->clonePacket(syn_packet));
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

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int socketfd, void *buf, unsigned count)
{
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	if(it->state != E::ESTABLISHED)
	{
		printf("\t\t\t\t****ESTAB 아닌데 write해서 에러****\n");
		this->returnSystemCall(syscallUUID, -1);
    return;
	}
	if(it->read_buffer.empty())
	{
		struct Read_State read_state;
		read_state.wakeup_ID = syscallUUID;
		read_state.buffer = buf;
		read_state.count = count;
		it->waiting_reads.push_back(read_state);
		return; // 블락
	}
	// 아니면 위에서 만든 read 바로 수행
	int read_cnt = 0;
	while(!it->read_buffer.empty() && read_cnt < (int)count)
	{
		uint8_t c = it->read_buffer.front();
		memcpy(static_cast<unsigned char*>(buf)+read_cnt, &c, 1);
		it->read_buffer.pop_front();
		read_cnt++;
	}
	returnSystemCall(syscallUUID, read_cnt);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int socketfd, const void *buf, unsigned count)
{
	std::list<struct Global_Context>::iterator it;
	uint8_t ack_flag = ACK_FLAG;
	it = this->find_pid_fd(pid, socketfd);
	if(this->error_if_none(syscallUUID, it)) return;
	if(it->state != E::ESTABLISHED)
	{
		printf("\t\t\t\t****ESTAB 아닌데 write해서 에러****\n");
		this->returnSystemCall(syscallUUID, -1);
    return;
	}
	uint32_t sending_count = 0;
	// packet들 만들어 놓고 it->waiting_writes에 넣기
	int rest = count;
	uint32_t send_idx = 0;
	while(rest)
	{
		if(rest > MSS)
			sending_count = MSS;
		else
			sending_count = rest;
		uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
		uint8_t *partitioned_buf = (uint8_t *)calloc(MSS, 1);
		memcpy(partitioned_buf, (uint8_t*)buf+send_idx, sending_count);
		Packet *waiting_packet = this->write_packet(ack_flag, it->seq_num, it->ack_num, it->src_port, it->dest_port, it->src_addr, it->dest_addr, my_window, (uint32_t)sending_count, partitioned_buf);
		it->waiting_writes.push_back(waiting_packet);
		it->seq_num += sending_count;
		rest -= sending_count;
		send_idx += sending_count;
	}
	int next_size = it->waiting_writes.front()->getSize()-54;
	while(it->sent_bytes + next_size < (int)it->window && !it->waiting_writes.empty())
	{
		Packet *data_packet = it->waiting_writes.front();
		it->waiting_writes.pop_front();
		int payload_size = (int)data_packet->getSize()-54;
		this->sendPacket("IPv4", data_packet);
		it->sent_bytes += (int)payload_size;
	}
	it->waiting_state.wakeup_ID = syscallUUID;
	it->waiting_state.count = count;
}

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
	uint8_t* rcv_buffer;
	packet->readData(14+12, &dest_addr, 4);
	packet->readData(14+16, &src_addr, 4);	// addr 바꿔서 읽기
	// get TCP Header
	packet->readData(14+20+0, &dest_port,2);
	packet->readData(14+20+2, &src_port,2);	// port 바꿔서 읽기
	packet->readData(14+20+4, &rcv_seq_num,4);
	packet->readData(14+20+8, &rcv_ack_num, 4);
	packet->readData(14+20+13, &rcv_flags, 1);
	packet->readData(14+20+14, &rcv_window, 2);
	if(payload_size)
	{
		rcv_buffer = (uint8_t *)calloc(payload_size, 1);
		packet->readData(14+20+20, rcv_buffer, payload_size);
	}
	uint16_t rcv_checksum = get_checksum(packet, dest_addr, src_addr, payload_size);
	this->freePacket(packet);
	if(rcv_checksum)
	{
		//printf("\t\t\t\t****도착한 체크섬 틀림****\n");
		return;
	}
	rcv_seq_num = ntohl(rcv_seq_num);
	rcv_ack_num = ntohl(rcv_ack_num);
	rcv_window = ntohs(rcv_window);
	bool SYN = bool(rcv_flags & SYN_FLAG);
	bool ACK = bool(rcv_flags & ACK_FLAG);
	bool FIN = bool(rcv_flags & FIN_FLAG);
	// dest_addr == context->rmt_addr, src_addr == context->src_addr, port도, 그런 context를 찾아 와야 함
	std::list<struct Global_Context>::iterator it;
	std::list<struct Global_Context>::iterator estab_it;
	bool found = true;
	it = this->find_connected_pair(src_addr, src_port, dest_addr, dest_port);
	if(it==this->context_list.end())
	{
		it = this->find_free_pair(src_addr, src_port, dest_addr, dest_port, &found); // established list까지 뒤졌음.
	}
	STATE state = E::CLOSED;
	if(found)
	{
		state = it->state;
		it->window = rcv_window;
	}
	else printf("\t\t\t\t\t****패킷이 왔는데 받을 소켓을 찾지 못함*****\n");
	switch(state)
	{
		case E::LISTEN:	// server가 받은 것, SYN 받았으면 SYN, ACK 보내고 SYN_RCVD로 바꾸기, context pending_list로 넣기
			if(SYN)
			{
				if(it->pending_list.size() >= it->backlog) break;
				uint8_t syn_ack_flag = SYN_FLAG | ACK_FLAG;
				// adjust new packet and write
				it->ack_num = rcv_seq_num+1;
				uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
				Packet* syn_ack_packet = this->write_packet(syn_ack_flag, it->seq_num, it->ack_num, src_port, dest_port, src_addr, dest_addr, my_window);
  			// new context to put in pending_list
  			struct Global_Context new_context;
  			// pid, socketfd는 accept될 때 저장됨
  			new_context.src_addr = src_addr;
  			new_context.src_port = src_port;
  			new_context.bound = true;
  			new_context.dest_addr = dest_addr;
  			new_context.dest_port = dest_port;
  			new_context.seq_num = ++it->seq_num;
  			new_context.ack_num = it->ack_num;
  			new_context.window = it->window;
  			// send packet
  			struct Send_Info send_info;
				send_info.seq_num = it->seq_num-1;
				send_info.expected_ack_num = it->seq_num;
				send_info.packet = syn_ack_packet;
				new_context.send_buffer.push_back(send_info);
				struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
				timer_state->pid = it->pid;
				timer_state->socketfd = it->socketfd;
				timer_state->state = SYN_RE;
				timer_state->pending_context = &new_context;
				UUID timer_key = this->addTimer((void *)timer_state, TimeUtil::makeTime(DEFAULT_SYN_TIMEOUT, TimeUtil::MSEC));
				new_context.timer_key = timer_key;
				new_context.timer_running = true;
				it->pending_list.push_back(new_context);
				this->sendPacket("IPv4", this->clonePacket(syn_ack_packet));
			}
			else if(ACK)
			{
				// SYN_RCVD context는 pending_list 안에 있다. 찾아 봐야함
				std::list<struct Global_Context>::iterator it2;
				// 하나 찾아서 그거만 하면 안되고 작은것부터 찾은것까지 전부 해야함
				for (it2 = it->pending_list.begin(); it2 != it->pending_list.end(); it2++)
				{
					if (it2->seq_num == rcv_ack_num) break;
				}
				if(it2 != it->pending_list.end())
				{	// established_list에 넣어줌
					struct Global_Context new_context;
					new_context = *it2;
					it->pending_list.erase(it2);
					new_context.state = E::ESTABLISHED;
					new_context.max_acked = rcv_ack_num;
					if(new_context.timer_running)
					{
						new_context.timer_running = false;
						this->cancelTimer(new_context.timer_key);
						if(!new_context.send_buffer.empty())
							new_context.send_buffer.pop_front();
					}
					it->established_list.push_back(new_context);
				}
				else
				{
					printf("\t\t\t\t\t****Pending List에서 소켓을 찾지 못함*****\n");
					return;
				}
				it->max_acked = rcv_ack_num;
				if(it->timer_running)
				{
					it->timer_running = false;
					this->cancelTimer(it->timer_key);
					if(!it->send_buffer.empty())
						it->send_buffer.pop_front();
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
			if(SYN && ACK)
			{
				if(rcv_ack_num != it->seq_num)
				{
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
				it->max_acked = rcv_ack_num;
				if(it->timer_running)
				{
					it->timer_running = false;
					this->cancelTimer(it->timer_key);
					if(!it->send_buffer.empty())
						it->send_buffer.pop_front();
				}
				uint8_t ack_flag = ACK_FLAG;
				it->ack_num = rcv_seq_num+1;
				uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, it->ack_num, src_port, dest_port, src_addr, dest_addr, my_window);
  			it->state = E::ESTABLISHED; // 얘는 client
  			this->sendPacket("IPv4", ack_packet);
				this->returnSystemCall(it->waiting_state.wakeup_ID, 0);
			}
			break;
		case E::ESTABLISHED:
			if(FIN)	// server 가 FIN 받고 ACK 보내고 CLOSE_WAIT 으로 변경
			{
				uint8_t ack_flag = ACK_FLAG;
				it->ack_num = rcv_seq_num+1;
				uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, it->ack_num, src_port, dest_port, src_addr, dest_addr, my_window);
				while(!it->waiting_reads.empty()){
					struct Read_State read_state = it->waiting_reads.front();
					it->waiting_reads.pop_front();
					returnSystemCall(read_state.wakeup_ID, -1);
				}
  			it->state = E::CLOSE_WAIT;
  			this->sendPacket("IPv4", ack_packet);
			}
			if(ACK)
			{
				// data transfer
				if(payload_size == 0)
				{	// write에 대한 답변으로 ACK 온 거임
					it->sent_bytes -= MSS;
					if(it->sent_bytes < 0) it->sent_bytes = 0;
					int next_size = 0;
					if(!it->waiting_writes.empty()) next_size = it->waiting_writes.front()->getSize()-54;
					while(it->sent_bytes + next_size < (int)it->window && !it->waiting_writes.empty())
					{
						Packet *data_packet = it->waiting_writes.front();
						it->waiting_writes.pop_front();
						int waited_payload_size = data_packet->getSize()-54;
						this->sendPacket("IPv4", data_packet);
						it->sent_bytes += waited_payload_size;
						//this->freePacket(data_packet);
					}
					if(it->waiting_writes.empty() && it->sent_bytes==0)
					{
						returnSystemCall(it->waiting_state.wakeup_ID, it->waiting_state.count);
						return;
					}
				}
				else
				{	// 상대방의 write으로 보내진 data
					for(int i=0; i<(int)payload_size; i++)
					{
						it->read_buffer.push_back(rcv_buffer[i]);
					}
					free(rcv_buffer);
					struct Read_State* read_state;
					uint8_t c;
					int read_cnt;
					while(!it->waiting_reads.empty())
					{
						read_state = &it->waiting_reads.front();
						read_cnt = 0;
						while(!it->read_buffer.empty() && read_cnt<(int)read_state->count)
						{
							c = it->read_buffer.front();
							memcpy(static_cast<unsigned char*>(read_state->buffer)+read_cnt, &c, 1); // 여기서 에러
							it->read_buffer.pop_front();
							read_cnt++;
						}
						returnSystemCall(read_state->wakeup_ID, read_cnt);
						it->waiting_reads.pop_front();
					}
					uint8_t ack_flag = ACK_FLAG;
					it->ack_num = rcv_seq_num + payload_size;
					uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
					Packet *ack_packet = this->write_packet(ack_flag, it->seq_num, it->ack_num, it->src_port, it->dest_port, it->src_addr, it->dest_addr, my_window);
					this->sendPacket("IPv4", ack_packet);
				}
			}
			break;
		case E::FIN_WAIT_1:
			if(ACK)
			{	
				if(rcv_ack_num != it->seq_num)
				{
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
				it->state = E::FIN_WAIT_2;
			}
			if(FIN)	// 1.ACK&&FIN  2.FIN 	둘다 ACK 을 보내지만, 1은 TIMED_WAIT, 2는 CLOSING
			{
				uint8_t ack_flag = ACK_FLAG;
				it->ack_num = rcv_seq_num+1;
				uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, it->ack_num, src_port, dest_port, src_addr, dest_addr, my_window);
  			this->sendPacket("IPv4", ack_packet);
				if(it->state == E::FIN_WAIT_1)
				{
					it->state = CLOSING;
				}
				else if(it->state == E::FIN_WAIT_2)
				{
					it->state = TIMED_WAIT;
					// timer?
					struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
					timer_state->pid = it->pid;
					timer_state->socketfd = it->socketfd;
					timer_state->state = TIMED_WAIT;
					UUID timer_key = this->addTimer((void *)timer_state, TimeUtil::makeTime(MSL, TimeUtil::MSEC));
					it->timer_key = timer_key;
				}
			}
			break;
		case E::LAST_ACK:
			if(ACK)
			{
				if(rcv_ack_num != it->seq_num)
				{
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
				while(!it->waiting_reads.empty()){
					struct Read_State read_state = it->waiting_reads.front();
					it->waiting_reads.pop_front();
					returnSystemCall(read_state.wakeup_ID, -1);
				}
				UUID syscallUUID = it->waiting_state.wakeup_ID;
				this->context_list.erase(it);
				this->returnSystemCall(syscallUUID, 0);
			}
			break;
		case E::FIN_WAIT_2:
			if(FIN)	// client 가 FIN 받고 ACK 보내고 TIMED_WAIT 으로 변경
			{
				uint8_t ack_flag = ACK_FLAG;
				it->ack_num = rcv_seq_num+1;
				uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, it->ack_num, src_port, dest_port, src_addr, dest_addr, my_window);
  			this->sendPacket("IPv4", ack_packet);
  			it->state = E::TIMED_WAIT;
  			// timer?
  			struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
				timer_state->pid = it->pid;
				timer_state->socketfd = it->socketfd;
				timer_state->state = TIMED_WAIT;
				UUID timer_key = this->addTimer((void *)timer_state, TimeUtil::makeTime(MSL, TimeUtil::MSEC));
				it->timer_key = timer_key;

			}
			break;
		case E::CLOSING:
			if(ACK)
			{
				if(rcv_ack_num != it->seq_num)
				{
					this->returnSystemCall(it->waiting_state.wakeup_ID, -1);
					break;
				}
				it->state = E::TIMED_WAIT;
				// timer?
				struct Timer_State *timer_state = (struct Timer_State*)malloc(sizeof (struct Timer_State));
				timer_state->pid = it->pid;
				timer_state->socketfd = it->socketfd;
				timer_state->state = TIMED_WAIT;
				UUID timer_key = this->addTimer((void *)timer_state, TimeUtil::makeTime(MSL, TimeUtil::MSEC));
				it->timer_key = timer_key;
			}
			break;
		case E::TIMED_WAIT:
			if(FIN)	// client 가 FIN 받고 ACK 보내고 기다렸다가 CLOSE
			{
				// timer 여기서는? ㄴㄴ 어짜피 여기서 close 안 일어나고 timerCallback에서만 close됨
				// 여기서는 fin이 또 오는거니까 ack이 안 갔다고 가정하고 다시 보냄
				uint8_t ack_flag = ACK_FLAG;
				it->ack_num = rcv_seq_num+1;
				uint16_t my_window = DEFAULT_WINDOW_SIZE - (uint16_t)it->read_buffer.size();
				Packet* ack_packet = this->write_packet(ack_flag, it->seq_num, it->ack_num, src_port, dest_port, src_addr, dest_addr, my_window);
  			this->sendPacket("IPv4", ack_packet);
			}
			break;
		default:
			break;
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	// payload로 global context 찾아서 packet 보내는 handling
	struct Timer_State* timer_state = (struct Timer_State*) payload;
	std::list<struct Global_Context>::iterator it;
	it = this->find_pid_fd(timer_state->pid, timer_state->socketfd);
	if(it==this->context_list.end()) return;
	if(timer_state->state == E::TIMED_WAIT)
	{
		while(!it->waiting_reads.empty()){
			struct Read_State read_state = it->waiting_reads.front();
			it->waiting_reads.pop_front();
			returnSystemCall(read_state.wakeup_ID, -1);
		}
		free((struct Timer_State*)payload);
	 	UUID syscallUUID = it->waiting_state.wakeup_ID;
		this->context_list.erase(it);
		this->removeFileDescriptor(it->pid, it->socketfd);
		this->returnSystemCall(syscallUUID, 0);
	}
	else if(timer_state->state == E::SYN_RE)
	{
		if(!timer_state->pending_context)
		{
			if(!it->send_buffer.empty())
			{
				std::list<struct Send_Info>::iterator it2;
				for(it2 = it->send_buffer.begin(); it2!=it->send_buffer.end(); ++it2)
				{
					this->sendPacket("IPv4", this->clonePacket(it2->packet));
				}
				UUID timer_key = this->addTimer((void *)timer_state, TimeUtil::makeTime(DEFAULT_SYN_TIMEOUT, TimeUtil::MSEC));
				it->timer_key = timer_key;
			}
			else
			{
				it->timer_running = false;
			}
		}
		else
		{
			if(!it->send_buffer.empty())
			{
				std::list<struct Send_Info>::iterator it2;
				for(it2 = timer_state->pending_context->send_buffer.begin(); it2!=timer_state->pending_context->send_buffer.end(); ++it2)
				{
					this->sendPacket("IPv4", this->clonePacket(it2->packet));
				}
				timer_state->pending_context->timer_key = this->addTimer((void *)timer_state, TimeUtil::makeTime(DEFAULT_SYN_TIMEOUT, TimeUtil::MSEC));
			}
			else
			{
				timer_state->pending_context->timer_running = false;
			}
		}
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

Packet* TCPAssignment::write_packet(int8_t flag, uint32_t seq_num, uint32_t ack_num, in_port_t src_port, in_port_t dest_port, in_addr_t src_addr, in_addr_t dest_addr, uint16_t window, uint32_t payload_size, uint8_t* payload)
{
	uint8_t protocol = PROTO_TCP;
	uint8_t headerLen_reservedField = DEFAULT_HDL_RESERVED;
	uint16_t pk_window = htons(window);
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
	packet->writeData(14+20+14, &pk_window, 2);
	if(payload_size > 0)
		packet->writeData(14+20+20, payload, payload_size);	
	uint16_t checksum = get_checksum(packet, src_addr, dest_addr, payload_size);
	packet->writeData(14+20+16, &checksum, 2);
	return packet;
}

uint16_t TCPAssignment::get_checksum(Packet* packet, in_addr_t src_addr, in_addr_t dest_addr, uint32_t payload_size)
{
	uint8_t protocol = PROTO_TCP;
	uint8_t *temp = (uint8_t *)calloc(12+20+payload_size,1);
	uint16_t tcp_length = htons(payload_size+20);
	memcpy(temp, &src_addr, 4);
	memcpy(temp+4, &dest_addr, 4);
	memcpy(temp+9, &protocol, 1);
	memcpy(temp+10, &tcp_length, 2);
	packet->readData(14+20, temp+12, payload_size+20);
	uint32_t sum = 0;
	uint16_t *pt = (uint16_t *)temp;
	for(unsigned int i=0; i<payload_size+32; i+=2){
		sum += *pt++;
		sum = (sum >> 16) + (sum & 0xffff);
	}
	uint16_t checksum = (uint16_t)(~sum);
	free(temp);
	return checksum;
}

}
