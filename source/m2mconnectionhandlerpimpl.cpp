/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mbed-client-classic/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconnectionhandler.h"

#include "pal_network.h"

#include "eventOS_event.h"
#include "eventOS_scheduler.h"

#include "mbed-trace/mbed_trace.h"
#include "mbed.h"

#define TRACE_GROUP "mClt"

#ifdef MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE
#define MBED_CLIENT_EVENT_LOOP_SIZE MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE
#else
#define MBED_CLIENT_EVENT_LOOP_SIZE 1024
#endif

int8_t M2MConnectionHandlerPimpl::_tasklet_id = -1;

static MemoryPool<M2MConnectionHandlerPimpl::TaskIdentifier, MBED_CLIENT_EVENT_LOOP_SIZE/64> memory_pool;

// XXX: Single instance support for now until socket callback has support for context!!!!
static M2MConnectionHandlerPimpl* handler = NULL;

extern "C" void connection_tasklet_event_handler(arm_event_s *event)
{
    tr_debug("M2MConnectionHandlerPimpl::connection_tasklet_event_handler");
    M2MConnectionHandlerPimpl* pimpl = NULL;
    M2MConnectionHandlerPimpl::TaskIdentifier *task_id = NULL;

    if (event->event_type == M2MConnectionHandlerPimpl::ESocketSend) {
        task_id = (M2MConnectionHandlerPimpl::TaskIdentifier*)event->data_ptr;
        pimpl = (M2MConnectionHandlerPimpl*)(task_id->pimpl);
    }
    else {
    	pimpl = (M2MConnectionHandlerPimpl*)event->data_ptr;
    }

    if(pimpl) {
        eventOS_scheduler_set_active_tasklet(pimpl->connection_tasklet_handler());
    }

    switch (event->event_type) {
        case M2MConnectionHandlerPimpl::ESocketIdle:
            tr_debug("Connection Tasklet Generated");
            break;
        case M2MConnectionHandlerPimpl::ESocketReadytoRead:
            tr_debug("connection_tasklet_event_handler - ESocketReadytoRead");
            if(pimpl) {
                if(pimpl->is_handshake_ongoing()) {
                    pimpl->receive_handshake_handler();
                } else {
                    pimpl->receive_handler();
                }
            }
            break;
        case M2MConnectionHandlerPimpl::ESocketDnsHandler:
            tr_debug("connection_tasklet_event_handler - ESocketDnsHandler");
            if(pimpl) {
                pimpl->dns_handler();
            }
            break;
        case M2MConnectionHandlerPimpl::ESocketSend:
            tr_debug("connection_tasklet_event_handler - ESocketSend");
            if(pimpl && task_id) {
                pimpl->send_socket_data((uint8_t*)task_id->data_ptr,(uint16_t)event->event_data);
                if (task_id->data_ptr) {
                    free(task_id->data_ptr);
                }
            }
            break;
        default:
            break;
    }

    // Free the task identifier if we had it
    if (task_id) {
        memory_pool.free(task_id);
    }
}

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                     M2MConnectionSecurity* sec,
                                                     M2MInterface::BindingMode mode,
                                                     M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
 _use_secure_connection(false),
 _binding_mode(mode),
 _network_stack(stack),
 _socket(0),
 _is_handshaking(false),
 _listening(true),
 _server_type(M2MConnectionObserver::LWM2MServer),
 _server_port(0),
 _listen_port(0),
 _running(false)
{
    _address._address = _address_data.addressData;

    // XXX: Single instance support for now until socket callback has context support
    handler = this;

    pal_init();

    if (_network_stack != M2MInterface::LwIP_IPv4) {
        tr_error("ConnectionHandler: Unsupported network stack, only IPv4 is currently supported");
    }
    _running = true;
    tr_debug("M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl() - Initializing thread");
    eventOS_scheduler_mutex_wait();
    if (M2MConnectionHandlerPimpl::_tasklet_id == -1) {
        M2MConnectionHandlerPimpl::_tasklet_id = eventOS_event_handler_create(&connection_tasklet_event_handler, ESocketIdle);
    }
    eventOS_scheduler_mutex_release();
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    tr_debug("M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()");
    if (_socket) {
        pal_close(&_socket);
    }
    delete _security_impl;
    tr_debug("M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl() - OUT");
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    _listen_port = listen_port;
    return true;
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String& server_address,
                                                       const uint16_t server_port,
                                                       M2MConnectionObserver::ServerType server_type,
                                                       const M2MSecurity* security)
{
    tr_debug("M2MConnectionHandlerPimpl::resolve_server_address()");

    _security = security;
    _server_port = server_port;
    _server_type = server_type;
    _server_address = server_address;

    arm_event_s event;
    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketDnsHandler;
    event.data_ptr = this;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;
    return eventOS_event_send(&event) == 0 ? true : false;
}

void M2MConnectionHandlerPimpl::dns_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::dns_handler()");

    palStatus_t status;
    palNetInterfaceInfo_t interface_info;
    uint32_t interface_count;
    status = pal_getNumberOfNetInterfaces(&interface_count);
    if(PAL_SUCCESS != status ) {
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return;
    }
    if(interface_count <= 0) {
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return;
    }
    // We select the first available interface for mbed Client
    status =  pal_getNetInterfaceInfo(0, &interface_info);

    _address._address = (void*)interface_info.address.addressData;
    _address._length = interface_info.addressSize;
    _address._port = _server_port;
    _address._stack = _network_stack;

    palSocketLength_t _socket_address_len;

    if(PAL_SUCCESS != pal_getAddressInfo(_server_address.c_str(), &_socket_address, &_socket_address_len)){
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return;
    }
    palSetSockAddrPort(&_socket_address, _server_port);

    palIpV4Addr_t ipV4Addr;
    palGetSockAddrIPV4Addr(&_socket_address,ipV4Addr);
    tr_debug("IP Address %s",tr_array(ipV4Addr,4));

    close_socket();
    init_socket();

    if(is_tcp_connection()) {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
       tr_debug("resolve_server_address - Using TCP");
        if (pal_connect(_socket, &_socket_address, sizeof(_socket_address)) != PAL_SUCCESS) {
            _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
            return;
        }
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    }

    _running = true;

    if (_security) {
        if (_security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
            _security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk) {

            if( _security_impl != NULL ){
                _security_impl->reset();
                if (_security_impl->init(_security) == 0) {
                    _is_handshaking = true;
                    tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - connect DTLS");
                    if(_security_impl->start_connecting_non_blocking(_base) < 0 ){
                        tr_debug("M2MConnectionHandlerPimpl::dns_handler - handshake failed");
                        _is_handshaking = false;
                        _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR);
                        close_socket();
                        return;
                    }
                } else {
                    tr_error("M2MConnectionHandlerPimpl::resolve_server_address - init failed");
                    _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, false);
                    close_socket();
                    return;
                }
            } else {
                tr_error("M2MConnectionHandlerPimpl::dns_handler - sec is null");
                _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, false);
                close_socket();
                return;
            }
        }
    }
    if(!_is_handshaking) {
        enable_keepalive();
        _observer.address_ready(_address,
                                _server_type,
                                _address._port);
    }
}

void M2MConnectionHandlerPimpl::send_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::send_handler()");
    _observer.data_sent();
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                          uint16_t data_len,
                                          sn_nsdl_addr_s *address)
{
    tr_debug("M2MConnectionHandlerPimpl::send_data()");
    if (address == NULL || data == NULL) {
        return false;
    }

    uint8_t *buffer = (uint8_t*)malloc(data_len);
    if(!buffer) {
        return false;
    }

    TaskIdentifier* task = memory_pool.alloc();
    if (!task) {
        free(buffer);
        return false;
    }
    task->pimpl = this;
    memcpy(buffer, data, data_len);
    task->data_ptr = buffer;
    arm_event_s event;
    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketSend;
    event.data_ptr = task;
    event.event_data = data_len;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;

    if (eventOS_event_send(&event) == 0) {
    	return true;
    }

    // Event push failed, free task identifier and buffer
    free(buffer);
    memory_pool.free(task);
    return false;
}

void M2MConnectionHandlerPimpl::send_socket_data(uint8_t *data,
                                                 uint16_t data_len)
{
    bool success = false;
    if( _use_secure_connection ){
        if( _security_impl->send_message(data, data_len) > 0){
            success = true;
        }
    } else {
        int32_t ret = -1;
        if(is_tcp_connection()){
            //We need to "shim" the length in front
            uint16_t d_len = data_len+4;
            uint8_t* d = (uint8_t*)malloc(data_len+4);

            d[0] = (data_len >> 24 )& 0xff;
            d[1] = (data_len >> 16 )& 0xff;
            d[2] = (data_len >> 8 )& 0xff;
            d[3] = data_len & 0xff;
            memmove(d+4, data, data_len);
            size_t sent;
            pal_send(_socket, d, d_len, &sent);
            //ret = ((TCPSocket*)_socket)->send(d,d_len);
            free(d);
        }else {
            size_t sent;
            pal_sendTo(_socket, data, data_len, &_socket_address, sizeof(_socket_address), &sent);
            //ret = ((UDPSocket*)_socket)->sendto(*_socket_address,data, data_len);
        }
        if (ret > 0) {
            success = true;
        }
    }

    if (!success) {
        _observer.socket_error(M2MConnectionHandler::SOCKET_SEND_ERROR, true);
        close_socket();
    }
}

int8_t M2MConnectionHandlerPimpl::connection_tasklet_handler()
{
    return M2MConnectionHandlerPimpl::_tasklet_id;
}

// XXX: Static for single instance support for now until socket callback has context support
void M2MConnectionHandlerPimpl::socket_event()
{
    if (!handler) {
        return;
    }
    arm_event_s event;
    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketReadytoRead;
    event.data_ptr = handler;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;
    eventOS_event_send(&event);
}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    tr_debug("M2MConnectionHandlerPimpl::start_listening_for_data()");
    // Boolean return required for other platforms,
    // not needed in mbed OS Socket.
    _listening = true;
    _running = true;
    return _listening;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    tr_debug("M2MConnectionHandlerPimpl::stop_listening()");
    _listening = false;
    if(_security_impl) {
        _security_impl->reset();
    }
}

int M2MConnectionHandlerPimpl::send_to_socket(const unsigned char *buf, size_t len)
{
    tr_debug("send_to_socket len - %d", len);
    size_t sent_len = -1;
    palStatus_t status = PAL_ERR_GENERIC_FAILURE;
    if(is_tcp_connection()) {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
        status = pal_send(_socket, buf, len, &sent_len);
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    } else {
        status = pal_sendTo(_socket, buf, len, &_socket_address, sizeof(_socket_address), &sent_len);
    }
    if(status == PAL_SUCCESS){
        return sent_len;
    }
    return (-1);
}

int M2MConnectionHandlerPimpl::receive_from_socket(unsigned char *buf, size_t len)
{
    tr_debug("receive_from_socket");
    palSocketAddress_t address;
    palSocketLength_t address_len;

    size_t recv_len;
    palStatus_t status = PAL_ERR_GENERIC_FAILURE;
    if(is_tcp_connection()) {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
        status = pal_recv(_socket, buf, len, &recv_len);
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    } else {
        status = pal_receiveFrom(_socket, buf, len, &address, &address_len, &recv_len);
        tr_debug("pal_receiveFrom status %d",(int)status);
        tr_debug("pal_receiveFrom received length %d",(int)recv_len);
    }
    if(status == PAL_SUCCESS) {
        return recv_len;
    }
    else if(status == PAL_ERR_SOCKET_WOULD_BLOCK || status == (-65536)){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }
    else
    {
        tr_info("PAL Socket returned: %d", status);
    }
    return (-1);
}

void M2MConnectionHandlerPimpl::handle_connection_error(int error)
{
    tr_debug("M2MConnectionHandlerPimpl::handle_connection_error");
    _observer.socket_error(error);
}

void M2MConnectionHandlerPimpl::set_platform_network_handler(void *handler)
{
    tr_debug("M2MConnectionHandlerPimpl::set_platform_network_handler");
}

void M2MConnectionHandlerPimpl::receive_handshake_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler()");
    if( _is_handshaking ){
        int ret = _security_impl->continue_connecting();
        tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler() - ret %d", ret);
        if( ret == M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ ){ //We wait for next readable event
            tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler() - We wait for next readable event");
            return;
        } else if( ret == 0 ){
            _is_handshaking = false;
            _use_secure_connection = true;
            enable_keepalive();
            _observer.address_ready(_address,
                                    _server_type,
                                    _server_port);
        }else if( ret < 0 ){
            _is_handshaking = false;
            _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, true);
            close_socket();
        }
    }
}

bool M2MConnectionHandlerPimpl::is_handshake_ongoing()
{
    return _is_handshaking;
}

void M2MConnectionHandlerPimpl::receive_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::receive_handler()");
    memset(_recv_buffer, 0, 1024);
    size_t receive_length = sizeof(_recv_buffer);
    size_t received;

    if(_listening) {
        if( _use_secure_connection ){
            int rcv_size = _security_impl->read(_recv_buffer, receive_length);

            if(rcv_size >= 0){
                _observer.data_available((uint8_t*)_recv_buffer,
                                         rcv_size, _address);
            } else if (M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ != rcv_size) {
                _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                close_socket();
                return;
            }
        }else{
            int recv = -1;
            if(is_tcp_connection()){
                if (pal_recv(_socket, _recv_buffer, receive_length, &received) == PAL_SUCCESS) {
                    recv = received;
                }
                //recv = ((TCPSocket*)_socket)->recv(_recv_buffer, receive_length);
            }else{
                palSocketAddress_t fromAddress;
                palSocketLength_t fromLen = 0;
                if (pal_receiveFrom(_socket, _recv_buffer, receive_length, &fromAddress, &fromLen, &received) == PAL_SUCCESS) {
                    recv = received;
                }
                //recv = ((UDPSocket*)_socket)->recvfrom(NULL,_recv_buffer, receive_length);
            }
            if (recv > 0) {
                // Send data for processing.
                if(is_tcp_connection()){
                    //We need to "shim" out the length from the front
                    if( receive_length > 4 ){
                        uint64_t len = (_recv_buffer[0] << 24 & 0xFF000000) + (_recv_buffer[1] << 16 & 0xFF0000);
                        len += (_recv_buffer[2] << 8 & 0xFF00) + (_recv_buffer[3] & 0xFF);
                        if(len > 0) {
                            uint8_t* buf = (uint8_t*)malloc(len);
                            if(buf) {
                                memmove(buf, _recv_buffer+4, len);
                                // Observer for TCP plain mode
                                _observer.data_available(buf,len,_address);
                                free(buf);
                            }
                        }
                    }else{
                        _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                        close_socket();
                    }
                } else { // Observer for UDP plain mode
                    tr_debug("M2MConnectionHandlerPimpl::receive_handler - data received %d", recv);
                    _observer.data_available((uint8_t*)_recv_buffer,
                                             recv, _address);
                }
            } else if(NSAPI_ERROR_WOULD_BLOCK != recv) {
                // Socket error in receiving
                _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                close_socket();
            }
        }
    }
}

void M2MConnectionHandlerPimpl::claim_mutex()
{
    eventOS_scheduler_mutex_wait();
}

void M2MConnectionHandlerPimpl::release_mutex()
{
    eventOS_scheduler_mutex_release();
}

static palIpV4Addr_t interface_address4 = {0,0,0,0};
static palIpV6Addr_t interface_address6 = {0};
void M2MConnectionHandlerPimpl::init_socket()
{
    tr_debug("M2MConnectionHandlerPimpl::init_socket - IN");
    _is_handshaking = false;
    _running = true;
    palStatus_t status = PAL_ERR_GENERIC_FAILURE;
    palSocketAddress_t bind_address;
    palSocketDomain_t socket_domain = PAL_AF_UNSPEC;
    palSocketType_t socket_type = PAL_SOCK_DGRAM;;

    if (_network_stack == M2MInterface::LwIP_IPv4) {
        socket_domain = PAL_AF_INET;
        status = palSetSockAddrIPV4Addr(&bind_address, interface_address4);
    }
    else if (_network_stack == M2MInterface::LwIP_IPv6) {
        socket_domain = PAL_AF_INET6;
        status = palSetSockAddrIPV6Addr(&bind_address, interface_address6);
    }

    if (status != PAL_SUCCESS) {
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return;
    }

    status = palSetSockAddrPort(&bind_address, _listen_port);

    if (is_tcp_connection()) {
        tr_debug("M2MConnectionHandlerPimpl::init_socket - Using TCP");
        socket_type = PAL_SOCK_STREAM;
    }
    else {
        tr_debug("M2MConnectionHandlerPimpl::init_socket - Using UDP - port %d", _listen_port);
        socket_type = PAL_SOCK_DGRAM;
    }

    status = pal_asynchronousSocket(socket_domain, socket_type, true, 0, (palAsyncSocketCallback_t)M2MConnectionHandlerPimpl::socket_event, &_socket);
    if (status != PAL_SUCCESS) {
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return;
    }

    if (!is_tcp_connection()) {
        status = pal_bind(_socket, &bind_address, sizeof(bind_address));
        if (status != PAL_SUCCESS) {
            tr_debug("M2MConnectionHandlerPimpl::init_socket - bind failed!");
            pal_close(&_socket);
            _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
            return;
        }
    }

    tr_debug("M2MConnectionHandlerPimpl::init_socket - OUT");
}

bool M2MConnectionHandlerPimpl::is_tcp_connection()
{
    return _binding_mode == M2MInterface::TCP ||
            _binding_mode == M2MInterface::TCP_QUEUE ? true : false;
}

void M2MConnectionHandlerPimpl::close_socket()
{
    tr_debug("M2MConnectionHandlerPimpl::close_socket() - IN");
    if(_socket) {
        pal_close(&_socket);
       _running = false;
    }
    tr_debug("M2MConnectionHandlerPimpl::close_socket() - OUT");
}

void M2MConnectionHandlerPimpl::enable_keepalive()
{
#if MBED_CLIENT_TCP_KEEPALIVE_TIME
    if(is_tcp_connection() && _socket) {
        int keepalive = MBED_CLIENT_TCP_KEEPALIVE_TIME;
        int enable = 1;
        tr_debug("M2MConnectionHandlerPimpl::resolve_hostname - keepalive %d s\n", keepalive);

        if (PAL_SUCCESS != pal_setSocketOptions(_socket, PAL_SO_KEEPALIVE, &enable, sizeof(enable))) {
            tr_error("M2MConnectionHandlerPimpl::enable_keepalive - setsockopt fail to Set Keepalive\n");
        }
        /* XXX: THESE ARE UNSUPPORTED IN PAL ATM
        if(_socket->setsockopt(1,NSAPI_KEEPINTVL,&keepalive,sizeof(keepalive)) != 0) {
            tr_error("M2MConnectionHandlerPimpl::enable_keepalive - setsockopt fail to Set Keepalive TimeInterval\n");
        }
        if(_socket->setsockopt(1,NSAPI_KEEPIDLE,&keepalive,sizeof(keepalive)) != 0) {
            tr_error("M2MConnectionHandlerPimpl::enable_keepalive - setsockopt fail to Set Keepalive Time\n");
        }*/
    }
#endif
}
