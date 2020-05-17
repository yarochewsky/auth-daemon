/**
 * Commslib - Communications Library
 *
 * This is a collection of useful functions to send and receive
 * messages between clients and servers of our application.
 *
 * It conveniently wraps payloads in the msg objects we're sending
 * and receiving, with proper authentication using ancilliary data.
 *
 */

#ifndef COMMSLIB_H
#define COMMSLIB_H

#include <stdint.h>

/**
 * resolve_address: resolves a string socket path to an address
 *
 * @addr_path: string containing path
 * @addr: return parameter of resulting address
 *
 * @returns -1 on error, 0 otherwise
 *
**/
int resolve_address(char* addr_path, struct sockaddr_un* addr);

/**
 * setup_datagram_socket: sets up authenticated datagram socker bound to addr
 *
 * @returns fd of socker or -1 on error
 *
**/
int setup_datagram_socket(char *addr);

/**
 * send_msg: sends payload to addr, with properly formatted
 * control section (creds)
 *
 * @src_fd: bound fd to send message from (must be connected to destination)
 * @payload: message payload
 * @payload_len: size of payload in bytes
 * 
 * @returns -1 on error
**/
int send_msg(int src_fd, uint8_t* payload, size_t payload_len);

/**
 * connect_to_destination: connects src_fd to a destination address
 *
 * @src_fd: bound fd to connect from
 * @dst: address of destination
 *
 * @returns -1 on error, 0 otherwise
 *
**/
int connect_to_destination(int src_fd, struct sockaddr_un* dst);

/**
 * receive_msg: receive a msg into dst_fd
 *
 * @dst_fd: bound fd to receive message
 * @msg: return parameter to place received message
 *
 * @returns -1 on erorr or number of bytes received
 *
 * Clients are responsible for msg's resource release
**/
int receive_msg(int dst_fd, struct msghdr** msg);


/**
 * get_header_credentials: pulls the credentials from a msg header
 *
 * @hdr: message header
 *
 * @returns credentials struct pointer, or NULL if no credentials are present
 *
**/
struct ucred* get_header_credentials(struct msghdr* hdr);

#endif // COMMSLIB_H
