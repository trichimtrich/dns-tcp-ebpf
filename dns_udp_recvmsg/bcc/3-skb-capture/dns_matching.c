/*
 * dns_matching.c  Drop DNS packets requesting DNS name contained in hash map
 *    For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright (c) 2016 Rudi Floren.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 11-May-2016  Rudi Floren Created this.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

struct dns_hdr_t
{
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} BPF_PACKET_HEADER;

int dns_matching(struct __sk_buff *skb)
{
  u8 *cursor = 0;
  // Check of ethernet/IP frame.
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  if (ethernet->type == ETH_P_IP)
  {

    // Check for UDP.
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->nextp == IPPROTO_UDP)
    {
      // Check for Port 53, DNS packet.
      struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
      if (udp->sport == 53)
      {
        struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));

        // expect response
        if ((dns_hdr->flags >> 15) == 1 && dns_hdr->qdcount > 0)
          return -1;
      }
    }
  }
  // Drop the packet
  return 0;
}
