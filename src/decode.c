/* $Id$ */

/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "decode.h"
#include "barnyard2.h"
#include "debug.h"
#include "util.h"
#include "checksum.h"
#include "log.h"
#include "generators.h"
#include "bounds.h"
#include "strlcpyu.h"
#include "sf_iph.h"
#include "sfxhash.h"

extern uint32_t pcap_snaplen;

/* No great place to put this right now */
HttpUri UriBufs[URI_COUNT];
uint8_t DecodeBuffer[DECODE_BLEN];
#ifndef SUP_IP6
Packet *BsdPseudoPacket;
/* For the BSD fragmentation vulnerability */
SFXHASH *ipv6_frag_hash;
#endif

#ifdef SUP_IP6
IPH_API ip4 = 
    {
       ip4_ret_src,
       ip4_ret_dst,
       ip4_ret_tos,
       ip4_ret_ttl,
       ip4_ret_len,
       ip4_ret_id,
       ip4_ret_proto,
       ip4_ret_off,
       ip4_ret_ver,
       ip4_ret_hlen,

       orig_ip4_ret_src,
       orig_ip4_ret_dst,
       orig_ip4_ret_tos,
       orig_ip4_ret_ttl,
       orig_ip4_ret_len,
       orig_ip4_ret_id,
       orig_ip4_ret_proto,
       orig_ip4_ret_off,
       orig_ip4_ret_ver,
       orig_ip4_ret_hlen,
       IPH_API_V4
    };

IPH_API ip6 =
    {
       ip6_ret_src,
       ip6_ret_dst,
       ip6_ret_toc,
       ip6_ret_hops,
       ip6_ret_len,
       ip6_ret_id,
       ip6_ret_next,
       ip6_ret_off,
       ip6_ret_ver,
       ip6_ret_hlen,

       orig_ip6_ret_src,
       orig_ip6_ret_dst,
       orig_ip6_ret_toc,
       orig_ip6_ret_hops,
       orig_ip6_ret_len,
       orig_ip6_ret_id,
       orig_ip6_ret_next,
       orig_ip6_ret_off,
       orig_ip6_ret_ver,
       orig_ip6_ret_hlen,
       IPH_API_V6
    };
#endif

int DecodePacket(int linktype, Packet *p, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt)
{
	DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Decoding linktype %d\n",linktype););
    switch(linktype)
    {
		case DLT_EN10MB:        /* Ethernet */
            DecodeEthPkt(p, pkthdr, pkt);
            break;

#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            DecodeIEEE80211Pkt(p, pkthdr, pkt);
            break;
#endif
#ifdef DLT_ENC
        case DLT_ENC:           /* Encapsulated data */
            DecodeEncPkt(p, pkthdr, pkt);
            break;

#else
        case 13:
#endif /* DLT_ENC */
        case DLT_IEEE802:                /* Token Ring */
            DecodeTRPkt(p, pkthdr, pkt);
            break;

        case DLT_FDDI:                /* FDDI */
            DecodeFDDIPkt(p, pkthdr, pkt);
            break;

#ifdef DLT_CHDLC
        case DLT_CHDLC:              /* Cisco HDLC */
            DecodeChdlcPkt(p, pkthdr, pkt);
            break;
#endif

        case DLT_SLIP:                /* Serial Line Internet Protocol */
            if (BcOutputDataLink())
            {
                LogMessage("Second layer header parsing for this datalink "
                        "isn't implemented yet\n");

                barnyard2_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }
            DecodeSlipPkt(p, pkthdr, pkt);

            break;

        case DLT_PPP:                /* point-to-point protocol */
            if (BcOutputDataLink())
            {
                /* do we need ppp header showup? it's only 4 bytes anyway ;-) */
                LogMessage("Second layer header parsing for this datalink "
                        "isn't implemented yet\n");

                barnyard2_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }
            DecodePppPkt(p, pkthdr, pkt);
            break;

#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:         /* PPP with full HDLC header*/
            if (BcOutputDataLink())
            {
                /* do we need ppp header showup? it's only 4 bytes anyway ;-) */
                LogMessage("Second layer header parsing for this datalink "
                        "isn't implemented yet\n");
                
                barnyard2_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }
            DecodePppSerialPkt(p, pkthdr, pkt);
            break;
#endif

#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            DecodeLinuxSLLPkt(p, pkthdr, pkt);
            break;
#endif

#ifdef DLT_PFLOG
        case DLT_PFLOG:
            DecodePflog(p, pkthdr, pkt);
            break;
#endif

#ifdef DLT_OLDPFLOG
        case DLT_OLDPFLOG:
            DecodeOldPflog(p, pkthdr, pkt);
            break;
#endif

#ifdef DLT_LOOP
        case DLT_LOOP:
#endif
        case DLT_NULL:            /* loopback and stuff.. you wouldn't perform
                                   * intrusion detection on it, but it's ok for
                                   * testing. */
            if (BcOutputDataLink())
            {
                LogMessage("Data link layer header parsing for this network "
                        " type isn't implemented yet\n");

                barnyard2_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }
            DecodeNullPkt(p, pkthdr, pkt);
            break;

#ifdef DLT_RAW /* Not supported in some arch or older pcap
                * versions */
        case DLT_RAW:
#ifdef DLT_IPV4
        case DLT_IPV4:
#endif
#ifdef DLT_IPV6
        case DLT_IPV6:
#endif
            if (BcOutputDataLink())
            {
                LogMessage("There's no second layer header available for "
                        "this datalink\n");

                barnyard2_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }
            DecodeRawPkt(p, pkthdr, pkt);
            break;
#endif
            /*
             * you need the I4L modified version of libpcap to get this stuff
             * working
             */
#ifdef DLT_I4L_RAWIP
        case DLT_I4L_RAWIP:
            DecodeI4LRawIPPkt(p, pkthdr, pkt);
            break;
#endif

#ifdef DLT_I4L_IP
        case DLT_I4L_IP:
            DecodeEthPkt(p, pkthdr, pkt);
            break;
#endif

#ifdef DLT_I4L_CISCOHDLC
        case DLT_I4L_CISCOHDLC:
            DecodeI4LCiscoIPPkt(p, pkthdr, pkt);
            break;
#endif

        default:            /* oops, don't know how to handle this one */
            ErrorMessage("\nCannot handle data link type %d\n", linktype);
    }

    /* add linktype to this packet for per plugin tracking */
    p->linktype = linktype;

    return 0;
}

static INLINE void DecoderEvent(
    Packet *p, int gid, char *str, int event_flag, int drop_flag) 
{
//    if((runMode == MODE_IDS) && event_flag) 
//    {
//        SnortEventqAdd(GENERATOR_SNORT_DECODE, gid, 1, 
//                       DECODE_CLASS, 3, str, 0);
//        if ((InlineMode()) && drop_flag)
//        {
//            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Dropping bad packet\n"););
//            InlineDrop(p);
//        }
//    }
}

/*
 * Function: DecodeEthPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeEthPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      /* suprisingly, the length of the packet */
    uint32_t cap_len;      /* caplen value */
        
	pc.eth++;
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(pcap_snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len);
            );

    /* do a little validation */
    if(cap_len < ETHERNET_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < Ethernet header length!"
                         " (%d bytes)\n", p->pkth->caplen);
        }
        
        p->iph = NULL;
        pc.discards++;
        pc.ethdisc++;
        return;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = (EtherHdr *) pkt;

    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "%X:%X:%X:%X:%X:%X -> %X:%X:%X:%X:%X:%X\n", 
                p->eh->ether_src[0],
                p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
                p->eh->ether_src[4], p->eh->ether_src[5], p->eh->ether_dst[0],
                p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
                p->eh->ether_dst[4], p->eh->ether_dst[5]);
            );
    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "type:0x%X len:0x%X\n", 
                ntohs(p->eh->ether_type), p->pkth->len)
            );

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, 
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - ETHERNET_HEADER_LEN));
                    );

            DecodeIP(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);

            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_PPPoE_DISC:
        case ETHERNET_TYPE_PPPoE_SESS:
            DecodePPPoEPkt(p, pkthdr, pkt);
           return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            return; 

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);
            return; 
#ifdef MPLS
        case ETHERNET_TYPE_MPLS_MULTICAST:
// barnyard2 should not add additional events
//            if(!ScMplsMulticast())
//            {
//                //additional check for DecoderAlerts will be done now.
//            	queueDecoderEvent(GENERATOR_SNORT_DECODE, DECODE_BAD_MPLS, 1, DECODE_CLASS, 3, DECODE_MULTICAST_MPLS_STR, 0);            	
//            }
        case ETHERNET_TYPE_MPLS_UNICAST:
            {
                struct pcap_pkthdr pkthdrTmp;
                pkthdrTmp.caplen = pkthdr->caplen - ETHERNET_HEADER_LEN;
                pkthdrTmp.len = pkthdr->len - ETHERNET_HEADER_LEN;
                DecodeMPLS(p->pkt + ETHERNET_HEADER_LEN, &pkthdrTmp, p);
                return;
            }
#endif        
        default:
            pc.other++;
            return;
    }

    return;
}


#ifndef NO_NON_ETHER_DECODER
/*
 * Function: DecodeIEEE80211Pkt(Packet *, char *, struct pcap_pkthdr*, 
 *                               uint8_t*)
 *
 * Purpose: Decode those fun loving wireless LAN packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeIEEE80211Pkt(Packet * p, const struct pcap_pkthdr * pkthdr, 
                        const uint8_t * pkt)
{
    uint32_t pkt_len;      /* suprisingly, the length of the packet */
    uint32_t cap_len;      /* caplen value */
        
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if (pcap_snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < MINIMAL_IEEE80211_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < IEEE 802.11 header length! "
                         "(%d bytes)\n", p->pkth->caplen);
        }
        return;
    }
    /* lay the wireless structure over the packet data */
    p->wifih = (WifiHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n", *p->wifih->addr1, 
                *p->wifih->addr2););

    /* determine frame type */
    switch(p->wifih->frame_control & 0x00ff)
    {
        /* management frames */
        case WLAN_TYPE_MGMT_ASREQ:
        case WLAN_TYPE_MGMT_ASRES:
        case WLAN_TYPE_MGMT_REREQ:
        case WLAN_TYPE_MGMT_RERES:
        case WLAN_TYPE_MGMT_PRREQ:
        case WLAN_TYPE_MGMT_PRRES:
        case WLAN_TYPE_MGMT_BEACON:
        case WLAN_TYPE_MGMT_ATIM:
        case WLAN_TYPE_MGMT_DIS:
        case WLAN_TYPE_MGMT_AUTH:
        case WLAN_TYPE_MGMT_DEAUTH:
            pc.wifi_mgmt++;
            break;

            /* Control frames */
        case WLAN_TYPE_CONT_PS:
        case WLAN_TYPE_CONT_RTS:
        case WLAN_TYPE_CONT_CTS:
        case WLAN_TYPE_CONT_ACK:
        case WLAN_TYPE_CONT_CFE:
        case WLAN_TYPE_CONT_CFACK:
            pc.wifi_control++;
            break;
            /* Data packets without data */
        case WLAN_TYPE_DATA_NULL:
        case WLAN_TYPE_DATA_CFACK:
        case WLAN_TYPE_DATA_CFPL:
        case WLAN_TYPE_DATA_ACKPL:

            pc.wifi_data++;
            break;
        case WLAN_TYPE_DATA_DTCFACK:
        case WLAN_TYPE_DATA_DTCFPL:
        case WLAN_TYPE_DATA_DTACKPL:
        case WLAN_TYPE_DATA_DATA:
            pc.wifi_data++;

            if(cap_len < IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc))
            {
                if(BcLogVerbose())
                    ErrorMessage("Not enough data for EthLlc header\n");

               return;
            }

            p->ehllc = (EthLlc *) (pkt + IEEE802_11_DATA_HDR_LEN);

#ifdef DEBUG
            PrintNetData(stdout,(uint8_t *)  p->ehllc, sizeof(EthLlc));
            //ClearDumpBuf();

            printf("LLC Header:\n");
            printf("   DSAP: 0x%X\n", p->ehllc->dsap);
            printf("   SSAP: 0x%X\n", p->ehllc->ssap);
#endif

            if(p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP)
            {
                if(cap_len < IEEE802_11_DATA_HDR_LEN +
                   sizeof(EthLlc) + sizeof(EthLlcOther))
                {
                    if (BcLogVerbose())
                        ErrorMessage("Not enough data for EthLlcOther header\n");

                    return;
                }

                p->ehllcother = (EthLlcOther *) (pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc));
#ifdef DEBUG
                PrintNetData(stdout,(uint8_t *) p->ehllcother, sizeof(EthLlcOther));
                //ClearDumpBuf();
                printf("LLC Other Header:\n");
                printf("   CTRL: 0x%X\n", p->ehllcother->ctrl);
                printf("   ORG: 0x%02X%02X%02X\n", p->ehllcother->org_code[0], 
                        p->ehllcother->org_code[1], p->ehllcother->org_code[2]);
                printf("   PROTO: 0x%04X\n", ntohs(p->ehllcother->proto_id));
#endif

                switch(ntohs(p->ehllcother->proto_id))
                {
                    case ETHERNET_TYPE_IP:
                        DecodeIP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther), 
                                pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) - 
                                sizeof(EthLlcOther), p);
                        return;

                    case ETHERNET_TYPE_ARP:
                    case ETHERNET_TYPE_REVARP:
                        DecodeARP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther), 
                                pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                                sizeof(EthLlcOther), p);
                        return;
                    case ETHERNET_TYPE_EAPOL:
                        DecodeEapol(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther),
                                pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                                sizeof(EthLlcOther), p);
                        return;
                    case ETHERNET_TYPE_8021Q:
                        DecodeVlan(p->pkt + IEEE802_11_DATA_HDR_LEN , 
                                   cap_len - IEEE802_11_DATA_HDR_LEN , p);
                        return; 
                        
                    case ETHERNET_TYPE_IPV6:
                        DecodeIPV6(p->pkt + IEEE802_11_DATA_HDR_LEN, 
                                cap_len - IEEE802_11_DATA_HDR_LEN, p);
                        return;

                    default:
                        pc.other++;
                        return;
                }
            }
            break;
        default:
            pc.other++;
            break;
    }

    return;
}
#endif  //NO_NON_ETHER_DECODER

#ifdef MPLS
/*
 * check if reserved labels are used properly
 */
static int checkMplsHdr(uint32_t label, uint8_t exp, uint8_t bos, uint8_t ttl, Packet *p)
{
    int iRet = 0;
    switch(label)
    {
        case 0:
        case 2:
               /* check if this label is the bottom of the stack */
               if(bos)
               {
                   if ( label == 0 )
                       iRet = MPLS_PAYLOADTYPE_IPV4;
                   else if ( label == 2 )
                       iRet = MPLS_PAYLOADTYPE_IPV6;


                   /* when label == 2, IPv6 is expected; 
                    * when label == 0, IPv4 is expected */
                   break;
               }
#if 0
               /* This is valid per RFC 4182.  Just pop this label off, ignore it
                * and move on to the next one.
                */
               if (BcLogVerbose())
               {
                   if( !label )
                       ErrorMessage("Label value zero appears in nonbottom MPLS header\n");
                   else
                       ErrorMessage("Label value two appears in nonbottom MPLS header\n");
               }

               pc.discards++;
               p->iph = NULL;
#ifdef SUP_IP6
               p->family = NO_IP;
#endif
               return(-1);
#endif
               break;
        case 1:
               if(!bos) break;
	       
               if (BcLogVerbose())
               ErrorMessage("Label value one appears in bottom MPLS header\n");

               pc.discards++;
               p->iph = NULL;
#ifdef SUP_IP6
               p->family = NO_IP;
#endif
               iRet = MPLS_PAYLOADTYPE_ERROR;
               break;
	    	   	           
	    case 3:
               if (BcLogVerbose())
                   ErrorMessage("Label value three appears in MPLS header\n");

               pc.discards++;
               p->iph = NULL;
#ifdef SUP_IP6
               p->family = NO_IP;
#endif
               iRet = MPLS_PAYLOADTYPE_ERROR;
               break;
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
                if(BcLogVerbose())
                    ErrorMessage("Reserved label value appears in MPLS header\n");

                break;
        default:	
                break;
    }	
    if ( !iRet )
    {
        iRet = BcMplsPayloadType();
    }
    return iRet;
}

void DecodeMPLS(const uint8_t * pkt, struct pcap_pkthdr * pkthdr, Packet * p)
{
    uint32_t    *tmpMplsHdr;
    uint32_t    mpls_h;
    uint32_t    label;
    uint8_t     exp;
    uint8_t     bos = 0;
    uint8_t     ttl;
    uint8_t     chainLen = 0;
    int         iRet = 0;
	
    pc.mpls++;
//    UpdateMPLSStats(&sfBase, pkthdr->caplen);
    tmpMplsHdr = (uint32_t *) pkt;
    p->mpls = NULL;
    while (!bos) 
    {
        if(pkthdr->caplen < MPLS_HEADER_LEN)
        {
            if (BcLogVerbose())
                ErrorMessage("Not enough data to process an MPLS header\n");
   
            pc.discards++;
            p->iph = NULL;
#ifdef SUP_IP6
            p->family = NO_IP;
#endif
            return;
        }
    
        mpls_h  = ntohl(*tmpMplsHdr);
        ttl = (uint8_t)(mpls_h & 0x000000FF);
        mpls_h = mpls_h>>8;
        bos = (uint8_t)(mpls_h & 0x00000001);
        exp = (uint8_t)(mpls_h & 0x0000000E);
        label = (mpls_h>>4) & 0x000FFFFF;
        
        if((label<NUM_RESERVED_LABELS)&&((iRet = checkMplsHdr(label, exp, bos, ttl, p)) < 0))
            return;
              
        if( bos )
        {
            p->mplsHdr.label = label;
            p->mplsHdr.exp = exp;
            p->mplsHdr.bos = bos;
            p->mplsHdr.ttl = ttl;
            /**
            p->mpls = &(p->mplsHdr);
			**/
            p->mpls = tmpMplsHdr;
            if(!iRet)
            {
                iRet = BcMplsPayloadType();
            }
        }
        tmpMplsHdr++;
        pkthdr->caplen -= MPLS_HEADER_LEN;
        pkthdr->len -= MPLS_HEADER_LEN;
        if ((BcMplsStackDepth() != -1) && (chainLen++ >= BcMplsStackDepth()))
        {       	
            if (BcLogVerbose())
                ErrorMessage("MPLS header chain too long\n");

            pc.discards++;
            p->iph = NULL;
#ifdef SUP_IP6
            p->family = NO_IP;
#endif
            return;
        }
    }   /* while bos not 1, peel off more labels */
    
    switch (iRet)
    {
        case MPLS_PAYLOADTYPE_IPV4:
            DecodeIP((uint8_t *)tmpMplsHdr, pkthdr->caplen, p);
            break;

        case MPLS_PAYLOADTYPE_IPV6:
            DecodeIPV6((uint8_t *)tmpMplsHdr, pkthdr->caplen, p);
            break;
          
        case MPLS_PAYLOADTYPE_ETHERNET:
            DecodeEthOverMPLS(p, pkthdr, (uint8_t *)tmpMplsHdr);
            break;
     	
        default:
            break;   
    }

    return;
}

void DecodeEthOverMPLS(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      
    uint32_t cap_len;
        
    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */
    
    /* do a little validation */
    if(cap_len < ETHERNET_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < Ethernet header length!"
                         " (%d bytes)\n", p->pkth->caplen);
        }
        
        p->iph = NULL;
        pc.discards++;
        pc.ethdisc++;
        return;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = (EtherHdr *) pkt;

    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "%X   %X\n", 
                *p->eh->ether_src, *p->eh->ether_dst);
            );

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, 
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - ETHERNET_HEADER_LEN));
                    );

            DecodeIP(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);

            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_PPPoE_DISC:
        case ETHERNET_TYPE_PPPoE_SESS:
            DecodePPPoEPkt(p, pkthdr, pkt);
            return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(p->pkt + ETHERNET_HEADER_LEN, 
                    (cap_len - ETHERNET_HEADER_LEN), p);
            return; 

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + ETHERNET_HEADER_LEN, 
                    cap_len - ETHERNET_HEADER_LEN, p);
            return; 
        
        default:
            pc.other++;
            return;
    }

    return;
}
#endif

void DecodeVlan(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    pc.vlan++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_vlan++;
#endif

    if(len < sizeof(VlanTagHdr))
    {
        if (BcLogVerbose())
            ErrorMessage("Not enough data to process a vlan header\n");

        pc.discards++;
        p->iph = NULL;
#ifdef SUP_IP6
        p->family = NO_IP;
#endif
        return;
    }

    p->vh = (VlanTagHdr *) pkt;
    
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Vlan traffic:\n");
               DebugMessage(DEBUG_DECODE, "   Priority: %d(0x%X)\n", 
                            VTH_PRIORITY(p->vh), VTH_PRIORITY(p->vh));
               DebugMessage(DEBUG_DECODE, "   CFI: %d\n", VTH_CFI(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan ID: %d(0x%04X)\n", 
                            VTH_VLAN(p->vh), VTH_VLAN(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan Proto: 0x%04X\n", 
                            ntohs(p->vh->vth_proto));
               );

    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if(ntohs(p->vh->vth_proto) <= ETHERNET_MAX_LEN_ENCAP)
    {
        if(len < sizeof(VlanTagHdr) + sizeof(EthLlc))
        {
            if (BcLogVerbose())
            {
                ErrorMessage("Not enough data for EthLlc header");
            }

            pc.discards++;
            p->iph = NULL;
#ifdef SUP_IP6
            p->family = NO_IP;
#endif
            return;            
        }
        
        p->ehllc = (EthLlc *) (pkt + sizeof(VlanTagHdr));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "LLC Header:\n");
                DebugMessage(DEBUG_DECODE, "   DSAP: 0x%X\n", p->ehllc->dsap);
                DebugMessage(DEBUG_DECODE, "   SSAP: 0x%X\n", p->ehllc->ssap);
                );

        if(p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP)
        {
            if(len < sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther))
            {
                if (BcLogVerbose())
                {
                    ErrorMessage("Not enough data for VLAN header");
                }

                pc.discards++;
                p->iph = NULL;
#ifdef SUP_IP6
                p->family = NO_IP;
#endif

                return;            
            }

            p->ehllcother = (EthLlcOther *) (pkt + sizeof(VlanTagHdr) + sizeof(EthLlc));

            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "LLC Other Header:\n");
                    DebugMessage(DEBUG_DECODE, "   CTRL: 0x%X\n", 
                        p->ehllcother->ctrl);
                    DebugMessage(DEBUG_DECODE, "   ORG: 0x%02X%02X%02X\n", 
                        p->ehllcother->org_code[0], p->ehllcother->org_code[1], 
                        p->ehllcother->org_code[2]);
                    DebugMessage(DEBUG_DECODE, "   PROTO: 0x%04X\n", 
                        ntohs(p->ehllcother->proto_id));
                    );

            switch(ntohs(p->ehllcother->proto_id))
            {
                case ETHERNET_TYPE_IP:
                    DecodeIP(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther),
                             len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

                case ETHERNET_TYPE_ARP:
                case ETHERNET_TYPE_REVARP:
                    DecodeARP(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther),
                              len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

                case ETHERNET_TYPE_IPV6:
                    DecodeIPV6(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther), 
                               len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

                case ETHERNET_TYPE_8021Q:
                    pc.nested_vlan++;
                    DecodeVlan(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther),
                               len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

                case ETHERNET_TYPE_LOOP:
                    DecodeEthLoopback(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther),
                                      len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

#ifndef NO_NON_ETHER_DECODER
                case ETHERNET_TYPE_IPX:
                    DecodeIPX(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther),
                              len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther), p);
                    return;

                /* Add these after DecodePPPoEPkt() has been reimplemented */
                case ETHERNET_TYPE_PPPoE_DISC:
                case ETHERNET_TYPE_PPPoE_SESS:
	            {	
                        struct pcap_pkthdr pkthdrTmp;
                        pkthdrTmp.caplen = len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther);
                        pkthdrTmp.len = len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther);
                        DecodePPPoEPkt(p,&pkthdrTmp, p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther));
                        return;
                    }
#endif
#ifdef MPLS
                case ETHERNET_TYPE_MPLS_MULTICAST:
                case ETHERNET_TYPE_MPLS_UNICAST:
                    {
                        struct pcap_pkthdr pkthdrTmp;
                        pkthdrTmp.caplen = len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther);
                        pkthdrTmp.len = len - sizeof(VlanTagHdr) - sizeof(EthLlc) - sizeof(EthLlcOther);
                        DecodeMPLS(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther), &pkthdrTmp, p);
                        return;
                    }
#endif


                default:
                    pc.other++;
                    return;
            }
        }
    }
    else
    {
        switch(ntohs(p->vh->vth_proto))
        {
            case ETHERNET_TYPE_IP:
                DecodeIP(pkt + sizeof(VlanTagHdr), 
                         len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_ARP:
            case ETHERNET_TYPE_REVARP:
                DecodeARP(pkt + sizeof(VlanTagHdr), 
                          len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_IPV6:
                DecodeIPV6(pkt +sizeof(VlanTagHdr), 
                           len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_8021Q:
                pc.nested_vlan++;
                DecodeVlan(pkt + sizeof(VlanTagHdr), 
                           len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_LOOP:
                DecodeEthLoopback(pkt + sizeof(VlanTagHdr), 
                                  len - sizeof(VlanTagHdr), p);
                return;

#ifndef NO_NON_ETHER_DECODER
            case ETHERNET_TYPE_IPX:
                DecodeIPX(pkt + sizeof(VlanTagHdr), 
                           len - sizeof(VlanTagHdr), p);
                return;

#if 0
            /* Add these after DecodePPPoEPkt() has been reimplemented */
            case ETHERNET_TYPE_PPPoE_DISC:
            case ETHERNET_TYPE_PPPoE_SESS:
                DecodePPPoEPkt(pkt + sizeof(VlanTagHdr), 
                               len - sizeof(VlanTagHdr), p);
                return;
#endif
#endif

#ifdef MPLS
            case ETHERNET_TYPE_MPLS_MULTICAST:
            case ETHERNET_TYPE_MPLS_UNICAST:
                {
                    struct pcap_pkthdr pkthdrTmp;
                    pkthdrTmp.caplen = len - sizeof(VlanTagHdr);
                    pkthdrTmp.len = len - sizeof(VlanTagHdr);
                    DecodeMPLS(pkt + sizeof(VlanTagHdr), &pkthdrTmp, p);
                    return;
                }
#endif
            default:
                pc.other++;
                return;
        }
    }

    pc.other++;
    return;
}

#ifdef GIDS
#ifndef IPFW
/*
 * Function: DecodeIptablesPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decoding iptables.
 * 
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 * 
 */
void DecodeIptablesPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t len;
    uint32_t cap_len;

    pc.iptables++;
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DecodeIP(p->pkt, cap_len, p);

}
#else
/*
 * Function: DecodeIpfwPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decoding ipfw divert socket
 * 
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 * 
 */
void DecodeIpfwPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t len;
    uint32_t cap_len;
        
    pc.ipfw++;
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DecodeIP(p->pkt, cap_len, p);

}
#endif
#endif /* GIDS */


/*
 * Function: DecodeNullPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decoding on loopback devices.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeNullPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t len;
    uint32_t cap_len;

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"); );

    /* do a little validation */
    if(cap_len < NULL_HDRLEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("NULL header length < captured len! (%d bytes)\n",
                    cap_len);
        }

        return;
    }

    DecodeIP(p->pkt + NULL_HDRLEN, cap_len - NULL_HDRLEN, p);
}

#ifndef NO_NON_ETHER_DECODER
/*
 * Function: DecodeTRPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decode Token Ring packets!
 *
 * Arguments: p=> pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeTRPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      /* suprisingly, the length of the packet */
    uint32_t cap_len;      /* caplen value */
    uint32_t dataoff;      /* data offset is variable here */

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;


    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if (pcap_snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len,(unsigned long) pkt_len);
            );

    if(cap_len < sizeof(Trh_hdr))
    {
        if (BcLogVerbose())
            ErrorMessage("Captured data length < Token Ring header length! "
                         "(%d < %d bytes)\n", p->pkth->caplen, TR_HLEN);

        return;
    }

    /* lay the tokenring header structure over the packet data */
    p->trh = (Trh_hdr *) pkt;

    /*
     * according to rfc 1042:
     *
     *   The presence of a Routing Information Field is indicated by the Most
     *   Significant Bit (MSB) of the source address, called the Routing
     *   Information Indicator (RII).  If the RII equals zero, a RIF is
     *   not present.  If the RII equals 1, the RIF is present.
     *   ..
     *   However the MSB is already zeroed by this moment, so there's no
     *   real way to figure out whether RIF is presented in packet, so we are
     *   doing some tricks to find IPARP signature..
     */

    /*
     * first I assume that we have single-ring network with no RIF
     * information presented in frame
     */
    if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc)))
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < Token Ring header length! "
                         "(%d < %d bytes)\n", cap_len,
                         (sizeof(Trh_hdr) + sizeof(Trh_llc)));
        }
        
        return;
    }

    
    p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));

    if(p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP)
    {
        /*
         * DSAP != SSAP != 0xAA .. either we are having frame which doesn't
         * carry IP datagrams or has RIF information present. We assume
         * lattest ...
         */

        if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr)))
        {
            if (BcLogVerbose())
                ErrorMessage("Captured data length < Token Ring header length! "
                             "(%d < %d bytes)\n", cap_len,
                             (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr)));
            
            return;
        }
        
        p->trhmr = (Trh_mr *) (pkt + sizeof(Trh_hdr));

        
        if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc) +
                      sizeof(Trh_mr) + TRH_MR_LEN(p->trhmr)))
        {
            if (BcLogVerbose())
                ErrorMessage("Captured data length < Token Ring header length! "
                             "(%d < %d bytes)\n", cap_len,
                             (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr)));

            return;
        }
        
        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr));
        dataoff   = sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr) + sizeof(Trh_llc);

    }
    else
    {
        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));
        dataoff = sizeof(Trh_hdr) + sizeof(Trh_llc);
    }

    /*
     * ideally we would need to check both SSAP, DSAP, and protoid fields: IP
     * datagrams and ARP requests and replies are transmitted in standard
     * 802.2 LLC Type 1 Unnumbered Information format, control code 3, with
     * the DSAP and the SSAP fields of the 802.2 header set to 170, the
     * assigned global SAP value for SNAP [6].  The 24-bit Organization Code
     * in the SNAP is zero, and the remaining 16 bits are the EtherType from
     * Assigned Numbers [7] (IP = 2048, ARP = 2054). .. but we would check
     * SSAP and DSAP and assume this would be enough to trust.
     */
    if(p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP)
    {
        DEBUG_WRAP(
                   DebugMessage(DEBUG_DECODE, "DSAP and SSAP arent set to SNAP\n");
                );
        p->trhllc = NULL;
        return;
    }

    switch(htons(p->trhllc->ethertype))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding IP\n"););
            DecodeIP(p->pkt + dataoff, cap_len - dataoff, p);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "Decoding ARP\n");
                    );
            pc.arp++;

            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + dataoff, cap_len - dataoff, p);
            return; 

        default:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown network protocol: %d\n", 
                        htons(p->trhllc->ethertype)));
            pc.other++;
            return;
    }

    return;
}


/*
 * Function: DecodeFDDIPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Mainly taken from CyberPsycotic's Token Ring Code -worm5er
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeFDDIPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      /* length of the packet */
    uint32_t cap_len;      /* capture length variable */
    uint32_t dataoff = sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps);

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    pkt_len = pkthdr->len;
    cap_len = pkthdr->caplen;

    if (pcap_snaplen < pkt_len)
    {
        pkt_len = cap_len;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long) cap_len,(unsigned long) pkt_len);
            );

    /* Bounds checking (might not be right yet -worm5er) */
    if(p->pkth->caplen < dataoff)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < FDDI header length! "
                         "(%d %d bytes)\n", p->pkth->caplen, dataoff);
            return;
        }
    }
    /* let's put this in as the fddi header structure */
    p->fddihdr = (Fddi_hdr *) pkt;

    p->fddisaps = (Fddi_llc_saps *) (pkt + sizeof(Fddi_hdr));

    /* First we'll check and see if it's an IP/ARP Packet... */
    /* Then we check to see if it's a SNA packet */
    /*
     * Lastly we'll declare it none of the above and just slap something
     * generic on it to discard it with (I know that sucks, but heck we're
     * only looking for IP/ARP type packets currently...  -worm5er
     */
    if((p->fddisaps->dsap == FDDI_DSAP_IP) && (p->fddisaps->ssap == FDDI_SSAP_IP))
    {
        dataoff += sizeof(Fddi_llc_iparp);
        
        if(p->pkth->caplen < dataoff)
        {
            if (BcLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", p->pkth->caplen, dataoff);
                return;
            }
        }
            
        p->fddiiparp = (Fddi_llc_iparp *) (pkt + sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps));
    }
    else if((p->fddisaps->dsap == FDDI_DSAP_SNA) &&
            (p->fddisaps->ssap == FDDI_SSAP_SNA))
    {
        dataoff += sizeof(Fddi_llc_sna);

        if(p->pkth->caplen < dataoff)
        {
            if (BcLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", p->pkth->caplen, dataoff);
                return;
            }
        }
        
        p->fddisna = (Fddi_llc_sna *) (pkt + sizeof(Fddi_hdr) +
                                       sizeof(Fddi_llc_saps));
    }
    else
    {
        dataoff += sizeof(Fddi_llc_other);
        p->fddiother = (Fddi_llc_other *) (pkt + sizeof(Fddi_hdr) +
                sizeof(Fddi_llc_other));

        if(p->pkth->caplen < dataoff)
        {
            if (BcLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", p->pkth->caplen, dataoff);
                return;
            }
        }
    }

    /*
     * Now let's see if we actually care about the packet... If we don't,
     * throw it out!!!
     */
    if((p->fddisaps->dsap != FDDI_DSAP_IP) && 
            (p->fddisaps->ssap != FDDI_SSAP_IP))
    {
        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, 
                    "This FDDI Packet isn't an IP/ARP packet...\n");
                );
        return;
    }

    pkt_len -= dataoff;
    cap_len -= dataoff;

    switch(htons(p->fddiiparp->ethertype))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding IP\n"););
            DecodeIP(p->pkt + dataoff, cap_len, p);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding ARP\n"););
            pc.arp++;

            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + dataoff, cap_len, p);
            return; 


        default:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown network protocol: %d\n",
                        htons(p->fddiiparp->ethertype));
                    );
            pc.other++;

            return;
    }

    return;
}

/*
 * Function: DecodeLinuxSLLPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decode those fun loving LinuxSLL (linux cooked sockets) 
 *          packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
 
#ifdef DLT_LINUX_SLL 

void DecodeLinuxSLLPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      /* the length of the packet */
    uint32_t cap_len;      /* caplen value */

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if (pcap_snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < SLL_HDR_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < SLL header length (your "
                         "libpcap is broken?)! (%d bytes)\n", p->pkth->caplen);
        }
        return;
    }
    /* lay the ethernet structure over the packet data */
    p->sllh = (SLLHdr *) pkt;

    /* grab out the network type */
    switch(ntohs(p->sllh->sll_protocol))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - SLL_HDR_LEN)););

            DecodeIP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), p);
            return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), p);
            return;

        case LINUX_SLL_P_802_3:
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,
                        "Linux SLL P 802.3 is not supported.\n"););
            pc.other++;
            return;

        case LINUX_SLL_P_802_2:
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,
                        "Linux SLL P 802.2 is not supported.\n"););
            pc.other++;
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            return; 

        default:
            /* shouldn't go here unless pcap library changes again */
            /* should be a DECODE generated alert */
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,"(Unknown) %X is not supported. "
                        "(need tcpdump snapshots to test. Please contact us)\n",
                        p->sllh->sll_protocol););
            pc.other++;
            return;
    }

    return;
}

#endif /* DLT_LINUX_SLL */

/*
 * Function: DecodeOldPflog(Packet *, struct pcap_pkthdr *, uint8_t *)
 *
 * Purpose: Pass old pflog format device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodeOldPflog(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      /* suprisingly, the length of the packet */
    uint32_t cap_len;      /* caplen value */

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if (pcap_snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < PFLOG1_HDRLEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < Pflog header length! "
                    "(%d bytes)\n", p->pkth->caplen);
        }
        return;
    }

    /* lay the pf header structure over the packet data */
    p->pf1h = (Pflog1Hdr*)pkt;

    /*  get the network type - should only be AF_INET or AF_INET6 */
    switch(ntohl(p->pf1h->af))
    {
        case AF_INET:   /* IPv4 */
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be %lu "
                        "bytes\n", (unsigned long)(cap_len - PFLOG1_HDRLEN)););

            DecodeIP(p->pkt + PFLOG1_HDRLEN, cap_len - PFLOG1_HDRLEN, p);
            return;

#if defined(AF_INET6) || defined(SUP_IP6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + PFLOG1_HDRLEN, cap_len - PFLOG1_HDRLEN, p);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only 
             * pass IP and IP6 packets. -fleck 
             */
            pc.other++;
            return;
    }

    return;
}

/*
 * Function: DecodePflog(Packet *, struct pcap_pkthdr *, uint8_t *)
 *
 * Purpose: Pass pflog device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodePflog(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      /* suprisingly, the length of the packet */
    uint32_t cap_len;      /* caplen value */
    uint8_t af, pflen;
    uint32_t hlen;

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if (pcap_snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(p->pkth->caplen < PFLOG2_HDRMIN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < minimum Pflog length! "
                    "(%d < %d)\n", p->pkth->caplen, PFLOG2_HDRMIN);
        }
        return;
    }
    /* lay the pf header structure over the packet data */
    if ( *((uint8_t*)pkt) < PFLOG3_HDRMIN )
    {
        p->pf2h = (Pflog2Hdr*)pkt;
        pflen = p->pf2h->length;
        hlen = PFLOG2_HDRLEN;
        af = p->pf2h->af;
    }
    else
    {
        p->pf3h = (Pflog3Hdr*)pkt;
        pflen = p->pf3h->length;
        hlen = PFLOG3_HDRLEN;
        af = p->pf3h->af;
    }
    /* now that we know a little more, do a little more validation */
    if(p->pkth->caplen < hlen)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < Pflog header length! "
                    "(%d < %d)\n", p->pkth->caplen, hlen);
        }
        return;
    }
    /* note that the pflen may exclude the padding which is always present */
    if(pflen < hlen - PFLOG_PADLEN || pflen > hlen)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Bad Pflog header length! (%d bytes)\n", pflen);
        }

        return;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be "
                "%lu bytes\n", (unsigned long)(cap_len - hlen)););

    /* check the network type - should only be AF_INET or AF_INET6 */
    switch(af)
    {
        case AF_INET:   /* IPv4 */
            DecodeIP(p->pkt + hlen, cap_len - hlen, p);
            return;

#if defined(AF_INET6) || defined(SUP_IP6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + hlen, cap_len - hlen, p);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only 
             * pass IP and IP6 packets. -fleck 
             */
            pc.other++;
            return;
    }

    return;
}


/*
 * Function: DecodePPPoEPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 * see http://www.faqs.org/rfcs/rfc2516.html
 *
 */
void DecodePPPoEPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t pkt_len;      /* suprisingly, the length of the packet */
    uint32_t cap_len;      /* caplen value */
    const PPPoEHdr *ppppoep=NULL;
    //PPPoE_Tag *ppppoe_tag=0;
    //PPPoE_Tag tag;  /* needed to avoid alignment problems */

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if (pcap_snaplen < pkt_len)
        pkt_len = cap_len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n", 
                (unsigned long)cap_len, (unsigned long)pkt_len););

    /* do a little validation */
    if(cap_len < PPPOE_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < Ethernet header length! "
                         "(%d bytes)\n", p->pkth->caplen);
        }
        
        return;
    }

    /* XXX - MFR
     * This code breaks the decode model that Snort uses, we should 
     * reimplement it properly ASAP
     */
    /*
     * Not sure how long ago the above comment was added, but
     * it is now fixed.  It may or may not fall under the 'ASAP'
     * category.
     */

    /* lay the ethernet structure over the packet data */
    /* Don't need to do this.  It is already done in the decoding
     * of the ethernet header, which then calls this function for
     * PPP over Ethernet.
    p->eh = (EtherHdr *) pkt;
     */

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n", 
                *p->eh->ether_src, *p->eh->ether_dst););

    /* lay the PPP over ethernet structure over the packet data */
    ppppoep = p->pppoeh = (PPPoEHdr *)pkt;

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_PPPoE_DISC:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Discovery) "););
            break;

        case ETHERNET_TYPE_PPPoE_SESS:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Session) "););
            break;

        default:
            return;
    }

#ifdef DEBUG
    switch(ppppoep->code)
    {
        case PPPoE_CODE_PADI:
            /* The Host sends the PADI packet with the DESTINATION_ADDR set 
             * to the broadcast address.  The CODE field is set to 0x09 and
             * the SESSION_ID MUST be set to 0x0000.
             *
             * The PADI packet MUST contain exactly one TAG of TAG_TYPE 
             * Service-Name, indicating the service the Host is requesting, 
             * and any number of other TAG types.  An entire PADI packet 
             * (including the PPPoE header) MUST NOT exceed 1484 octets so 
             * as to leave sufficient room for a relay agent to add a 
             * Relay-Session-Id TAG.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Initiation (PADI)\n");
            break;

        case PPPoE_CODE_PADO:
            /* When the Access Concentrator receives a PADI that it can 
             * serve, it replies by sending a PADO packet.  The 
             * DESTINATION_ADDR is the unicast address of the Host that 
             * sent the PADI.  The CODE field is set to 0x07 and the 
             * SESSION_ID MUST be set to 0x0000.  
             * 
             * The PADO packet MUST contain one AC-Name TAG containing the 
             * Access Concentrator's name, a Service-Name TAG identical to 
             * the one in the PADI, and any number of other Service-Name 
             * TAGs indicating other services that the Access Concentrator 
             * offers.  If the Access Concentrator can not serve the PADI 
             * it MUST NOT respond with a PADO.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Offer (PADO)\n");
            break;

        case PPPoE_CODE_PADR:
            /* Since the PADI was broadcast, the Host may receive more than 
             * one PADO.  The Host looks through the PADO packets it receives 
             * and chooses one.  The choice can be based on the AC-Name or 
             * the Services offered.  The Host then sends one PADR packet 
             * to the Access Concentrator that it has chosen.  The 
             * DESTINATION_ADDR field is set to the unicast Ethernet address 
             * of the Access Concentrator that sent the PADO.  The CODE 
             * field is set to 0x19 and the SESSION_ID MUST be set to 0x0000.
             *
             * The PADR packet MUST contain exactly one TAG of TAG_TYPE 
             * Service-Name, indicating the service the Host is requesting, 
             * and any number of other TAG types.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Request (PADR)\n");
            break;

        case PPPoE_CODE_PADS:
            /* When the Access Concentrator receives a PADR packet, it 
             * prepares to begin a PPP session.  It generates a unique 
             * SESSION_ID for the PPPoE session and replies to the Host with 
             * a PADS packet.  The DESTINATION_ADDR field is the unicast 
             * Ethernet address of the Host that sent the PADR.  The CODE 
             * field is set to 0x65 and the SESSION_ID MUST be set to the 
             * unique value generated for this PPPoE session.
             *
             * The PADS packet contains exactly one TAG of TAG_TYPE 
             * Service-Name, indicating the service under which Access 
             * Concentrator has accepted the PPPoE session, and any number 
             * of other TAG types.
             *
             * If the Access Concentrator does not like the Service-Name in 
             * the PADR, then it MUST reply with a PADS containing a TAG of 
             * TAG_TYPE Service-Name-Error (and any number of other TAG 
             * types).  In this case the SESSION_ID MUST be set to 0x0000.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery "
                         "Session-confirmation (PADS)\n");
            break;

        case PPPoE_CODE_PADT:
            /* This packet may be sent anytime after a session is established 
             * to indicate that a PPPoE session has been terminated.  It may 
             * be sent by either the Host or the Access Concentrator.  The 
             * DESTINATION_ADDR field is a unicast Ethernet address, the 
             * CODE field is set to 0xa7 and the SESSION_ID MUST be set to 
             * indicate which session is to be terminated.  No TAGs are 
             * required.  
             *
             * When a PADT is received, no further PPP traffic is allowed to 
             * be sent using that session.  Even normal PPP termination 
             * packets MUST NOT be sent after sending or receiving a PADT.  
             * A PPP peer SHOULD use the PPP protocol itself to bring down a 
             * PPPoE session, but the PADT MAY be used when PPP can not be 
             * used.
             */ 
            DebugMessage(DEBUG_DECODE, "Active Discovery Terminate (PADT)\n");
            break;

        case PPPoE_CODE_SESS: 
            DebugMessage(DEBUG_DECODE, "Session Packet (SESS)\n");
            break;

        default:
            DebugMessage(DEBUG_DECODE, "(Unknown)\n");
            break;
    }
#endif

    if (ntohs(p->eh->ether_type) != ETHERNET_TYPE_PPPoE_DISC)
    {
        DecodePppPktEncapsulated(p, cap_len - PPPOE_HEADER_LEN, pkt + PPPOE_HEADER_LEN);
        return;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Returning early on PPPOE discovery packet\n"););
        return;
    }

#if 0 
    ppppoe_tag = (PPPoE_Tag *)(pkt + sizeof(PPPoEHdr));

    while (ppppoe_tag < (PPPoE_Tag *)(pkt + pkthdr->caplen))
    {
        if (((char*)(ppppoe_tag)+(sizeof(PPPoE_Tag)-1)) > (char*)(pkt + pkthdr->caplen))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Not enough data in packet for PPPOE Tag\n"););
            break;
        }

        /* no guarantee in PPPoE spec that ppppoe_tag is aligned at all... */
        memcpy(&tag, ppppoe_tag, sizeof(tag));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "\tPPPoE tag:\ntype: %04x length: %04x ", 
                    ntohs(tag.type), ntohs(tag.length)););

#ifdef DEBUG
        switch(ntohs(tag.type))
        {
            case PPPoE_TAG_END_OF_LIST:
                DebugMessage(DEBUG_DECODE, "(End of list)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME:
                DebugMessage(DEBUG_DECODE, "(Service name)\n\t");
                break;
            case PPPoE_TAG_AC_NAME:
                DebugMessage(DEBUG_DECODE, "(AC Name)\n\t");
                break;
            case PPPoE_TAG_HOST_UNIQ:
                DebugMessage(DEBUG_DECODE, "(Host Uniq)\n\t");
                break;
            case PPPoE_TAG_AC_COOKIE:
                DebugMessage(DEBUG_DECODE, "(AC Cookie)\n\t");
                break;
            case PPPoE_TAG_VENDOR_SPECIFIC:
                DebugMessage(DEBUG_DECODE, "(Vendor Specific)\n\t");
                break;
            case PPPoE_TAG_RELAY_SESSION_ID:
                DebugMessage(DEBUG_DECODE, "(Relay Session ID)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME_ERROR:
                DebugMessage(DEBUG_DECODE, "(Service Name Error)\n\t");
                break;
            case PPPoE_TAG_AC_SYSTEM_ERROR:
                DebugMessage(DEBUG_DECODE, "(AC System Error)\n\t");
                break;
            case PPPoE_TAG_GENERIC_ERROR:
                DebugMessage(DEBUG_DECODE, "(Generic Error)\n\t");
                break;
            default:
                DebugMessage(DEBUG_DECODE, "(Unknown)\n\t");
                break;
        }
#endif

        if (ntohs(tag.length) > 0)
        {
#ifdef DEBUG
            char *buf;
            int i;

            switch (ntohs(tag.type))
            {
                case PPPoE_TAG_SERVICE_NAME:
                case PPPoE_TAG_AC_NAME:
                case PPPoE_TAG_SERVICE_NAME_ERROR:
                case PPPoE_TAG_AC_SYSTEM_ERROR:
                case PPPoE_TAG_GENERIC_ERROR: * ascii data *
                    buf = (char *)SnortAlloc(ntohs(tag.length) + 1);
                    strlcpy(buf, (char *)(ppppoe_tag+1), ntohs(tag.length));
                    DebugMessage(DEBUG_DECODE, "data (UTF-8): %s\n", buf);
                    free(buf);
                    break;

                case PPPoE_TAG_HOST_UNIQ:
                case PPPoE_TAG_AC_COOKIE:
                case PPPoE_TAG_RELAY_SESSION_ID:
                    DebugMessage(DEBUG_DECODE, "data (bin): ");
                    for (i = 0; i < ntohs(tag.length); i++)
                        DebugMessage(DEBUG_DECODE,
                                "%02x", *(((unsigned char *)ppppoe_tag) + 
                                    sizeof(PPPoE_Tag) + i));
                    DebugMessage(DEBUG_DECODE, "\n");
                    break;

                default:
                    DebugMessage(DEBUG_DECODE, "unrecognized data\n");
                    break;
            }
#endif
        }

        ppppoe_tag = (PPPoE_Tag *)((char *)(ppppoe_tag+1)+ntohs(tag.length));
    }

#endif   /* #if 0 */

    return;
}
#endif  // NO_NON_ETHER_DECODER


/*
 * Function: DecodePppPktEncapsulated(Packet *, const uint32_t len, uint8_t*)
 *
 * Purpose: Decode PPP traffic (RFC1661 framing).
 *
 * Arguments: p => pointer to decoded packet struct 
 *            len => length of data to process
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPktEncapsulated(Packet * p, const uint32_t len, const uint8_t * pkt)
{
    static int had_vj = 0;
    uint16_t protocol;
    uint32_t hlen = 1; /* HEADER - try 1 then 2 */    
    
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "PPP Packet!\n"););

#ifdef WORDS_MUSTALIGN
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet with PPP header.  "
                            "PPP is only 1 or 2 bytes and will throw off "
                            "alignment on this architecture when decoding IP, "
                            "causing a bus error - stop decoding packet.\n"););

    p->data = pkt;
    p->dsize = (uint16_t)len;
    return;
#endif  /* WORDS_MUSTALIGN */

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ppp++;
#endif  /* GRE */

    /* do a little validation:
     * 
     */
    if(len < 2)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        return;
    }

    
    if(pkt[0] & 0x01)
    {
        /* Check for protocol compression rfc1661 section 5
         *
         */
        hlen = 1;
        protocol = pkt[0];
    }
    else
    {
        protocol = ntohs(*((uint16_t *)pkt));
        hlen = 2;
    }
    
    /* 
     * We only handle uncompressed packets. Handling VJ compression would mean
     * to implement a PPP state machine.
     */
    switch (protocol) 
    {
        case PPP_VJ_COMP:
            if (!had_vj)
                ErrorMessage("PPP link seems to use VJ compression, "
                        "cannot handle compressed packets!\n");
            had_vj = 1;
            break;
        case PPP_VJ_UCOMP:
            /* VJ compression modifies the protocol field. It must be set
             * to tcp (only TCP packets can be VJ compressed) */
            if(len < (hlen + IP_HEADER_LEN))
            {
                if (BcLogVerbose())
                    ErrorMessage("PPP VJ min packet length > captured len! "
                                 "(%d bytes)\n", len);
                return;
            }

            ((IPHdr *)(pkt + hlen))->ip_proto = IPPROTO_TCP;
            /* fall through */

        case PPP_IP:
            DecodeIP(pkt + hlen, len - hlen, p);
            break;

#ifndef NO_NON_ETHER_DECODER
        case PPP_IPX:
            DecodeIPX(pkt + hlen, len - hlen, p);
            break;
#endif
    }
}


/*
 * Function: DecodePppPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decode PPP traffic (either RFC1661 or RFC1662 framing).
 *          This really is intended to handle IPCP
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    int hlen = 0;

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if(p->pkth->caplen < 2)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        return;
    }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        /*
         * Check for full HDLC header (rfc1662 section 3.2)
         */
        hlen = 2;
    }

    DecodePppPktEncapsulated(p, p->pkth->caplen - hlen, p->pkt + hlen);

    return;
}

#ifndef NO_NON_ETHER_DECODER
/*
 * Function: DecodePppSerialPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decode Mixed PPP/CHDLC traffic. The PPP frames will always have the
 *          full HDLC header.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppSerialPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if(p->pkth->caplen < PPP_HDRLEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < PPP header length"
                         " (%d bytes)\n", p->pkth->caplen);
        }
        return;
    }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        DecodePppPktEncapsulated(p, p->pkth->caplen - 2, p->pkt + 2);
    } else {
        DecodeChdlcPkt(p, pkthdr, pkt);
    }

    return;
}


/*
 * Function: DecodeSlipPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decode SLIP traffic
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeSlipPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    uint32_t len;
    uint32_t cap_len;

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(cap_len < SLIP_HEADER_LEN)
    {
        ErrorMessage("SLIP header length < captured len! (%d bytes)\n",
                     cap_len);
        return;
    }

    DecodeIP(p->pkt + SLIP_HEADER_LEN, cap_len - SLIP_HEADER_LEN, p);
}
#endif  // NO_NON_ETHER_DECODER



/*
 * Function: DecodeRawPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeRawPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if (p->pkth->caplen > 0) {
        IP4Hdr *ip4h = (IP4Hdr *)pkt;
        IP6RawHdr *ip6h = (IP6RawHdr *)pkt;

        if (IP_VER(ip4h) == 4) {
            DecodeIP(pkt, p->pkth->caplen, p);
        } else if (((ip6h->ip6vfc & 0xf0) >> 4) == 6) {
            DecodeIPV6(pkt, p->pkth->caplen, p);
        }
    }

    return;
}



#ifndef NO_NON_ETHER_DECODER
/*
 * Function: DecodeI4LRawIPPkt(Packet *, char *, struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LRawIPPkt(Packet * p, const struct pcap_pkthdr * pkthdr, const uint8_t * pkt)
{
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->len < 2)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "What the hell is this?\n"););
        pc.other++;
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););
    DecodeIP(pkt + 2, p->pkth->len - 2, p);

    return;
}



/*
 * Function: DecodeI4LCiscoIPPkt(Packet *, char *, 
 *                               struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LCiscoIPPkt(Packet *p, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt)
{
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->len < 4)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "What the hell is this?\n"););
        pc.other++;
        return;
    }


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    DecodeIP(pkt + 4, p->pkth->caplen - 4, p);

    return;
}

/*
 * Function: DecodeChdlcPkt(Packet *, char *, 
 *                               struct pcap_pkthdr*, uint8_t*)
 *
 * Purpose: Decodes Cisco HDLC encapsulated packets, f.ex. from SONET.
 *
 * Arguments: p => pointer to decoded packet struct 
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeChdlcPkt(Packet *p, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt)
{
    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->caplen < CHDLC_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < CHDLC header length"
                         " (%d bytes)\n", p->pkth->caplen);
        }
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if ((pkt[0] == CHDLC_ADDR_UNICAST || pkt[0] == CHDLC_ADDR_MULTICAST) &&
    		ntohs(*(uint16_t *)&pkt[2]) == ETHERNET_TYPE_IP)
    {
        DecodeIP(p->pkt + CHDLC_HEADER_LEN,
                 p->pkth->caplen - CHDLC_HEADER_LEN, p);
    } else {
        pc.other++;
    }

    return;
}
#endif  // NO_NON_ETHER_DECODER

/*
 * Some IP Header tests
 * Land Attack(same src/dst ip)
 * Loopback (src or dst in 127/8 block)
 * Modified: 2/22/05-man for High Endian Architecture.
 */
void IPHdrTestsv4( Packet * p )
{
#if 0
#ifdef WORDS_BIGENDIAN
    unsigned int ip4_ip = 0x7f000000;
#else
    unsigned int ip4_ip = 0x7f;
#endif 
#endif  /* #if 0 */

    /* Loopback traffic  - don't use htonl for speed reasons - 
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    if( (p->iph->ip_src.s_addr & 0xff000000) == 0x7f000000  || 
        (p->iph->ip_dst.s_addr & 0xff000000 ) == 0x7f000000 ) /* BE */
#else
    if( (p->iph->ip_src.s_addr & 0xff) == 0x7f || 
        (p->iph->ip_dst.s_addr & 0xff ) == 0x7f ) /* LE */
#endif
    {
    }
}

#ifdef DLT_ENC
/* see http://sourceforge.net/mailarchive/message.php?msg_id=1000380 */
/*
 * Function: DecodeEncPkt(Packet *, struct pcap_pkthdr *, uint8_t *)
 *
 * Purpose: Decapsulate packets of type DLT_ENC.
 *          XXX Are these always going to be IP in IP?
 *
 * Arguments: p => pointer to decoded packet struct
 *            pkthdr => pointer to the packet header
 *            pkt => pointer to the real live packet data
 */
void DecodeEncPkt(Packet *p, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt)
{
    struct enc_header *enc_h;

    pc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;

    if (p->pkth->caplen < ENC_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Captured data length < Encap header length!  (%d bytes)\n", p->pkth->caplen);
        }
        return;
    }

    enc_h = (struct enc_header *)p->pkt;
    if (enc_h->af == AF_INET)
    {
        DecodeIP(p->pkt + ENC_HEADER_LEN + IP_HEADER_LEN,
                 pkthdr->caplen - ENC_HEADER_LEN - IP_HEADER_LEN, p);
    }
    else
    {
        ErrorMessage("[!] WARNING: Unknown address family! (af: 0x%x)\n",
                enc_h->af);
    }
    return;
}
#endif /* DLT_ENC */

/*
 * Function: DecodeIP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 * Returns: void function
 */
void DecodeIP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    uint32_t hlen;   /* ip header length */
    uint16_t csum;   /* checksum */


    pc.ip++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ip++;
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(len < IP_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("IP header truncated! (%d bytes)\n", len);
        }
        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;

#ifdef SUP_IP6
        p->family = NO_IP;
#endif
        return;
    }

#ifdef GRE
#ifndef SUP_IP6
    if (p->iph != NULL)
#else
    if (p->family != NO_IP)
#endif  /* SUP_IP6 */
    {
        IPHdr *tmp = (IPHdr *)pkt;

        if (p->encapsulated ||
            ((tmp->ip_proto == IPPROTO_IPIP) || (tmp->ip_proto == IPPROTO_GRE))
#ifdef SUP_IP6
             || (tmp->ip_proto == IPPROTO_IPV6)
#endif
           )
        {
            DecoderAlertGRE(p, DECODE_GRE_MULTIPLE_ENCAPSULATION,
                            DECODE_GRE_MULTIPLE_ENCAPSULATION_STR,
                            pkt, len);
            return;
        }
        else
        {
            p->encapsulated = 1;
            p->outer_iph = p->iph;
            p->outer_ip_data = p->ip_data;
            p->outer_ip_dsize = p->ip_dsize;
        }
    }
#endif  /* GRE */

    /* lay the IP struct over the raw data */
    p->inner_iph = p->iph = (IPHdr *)pkt;

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(IP_VER(p->iph) != 4)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Not IPv4 datagram! "
                    "([ver: 0x%x][len: 0x%x])\n", 
                    IP_VER(p->iph), p->iph->ip_len);
        }

        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;

#ifdef SUP_IP6
        p->family = NO_IP;
#endif
        return;
    }

#ifdef SUP_IP6
    sfiph_build(p, p->iph, AF_INET);
#endif

//    p->ip_payload_len = p->iph->ip_len;
//    p->ip_payload_off = p->ip_payload_len + (int)pkt;

    /* set the IP datagram length */
    ip_len = ntohs(p->iph->ip_len);

    /* set the IP header length */
    hlen = IP_HLEN(p->iph) << 2;

    /* header length sanity check */
    if(hlen < IP_HEADER_LEN)
    {
#ifdef DEBUG
        if (BcLogVerbose())
            ErrorMessage("Bogus IP header length of %i bytes\n", 
                    hlen);
#endif

        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;
#ifdef SUP_IP6
        p->family = NO_IP;
#endif
        return;
    }

    if (ip_len != len)
    {
        if (ip_len > len) 
        {
#ifdef DEBUG
            if (BcLogVerbose())
                ErrorMessage("IP Len field is %d bytes bigger"
                        " than captured length.\n"
                        "    (ip.len: %lu, cap.len: %lu)\n",
                        ip_len - len, ip_len, len);
#endif

            p->iph = NULL;
            pc.discards++;
            pc.ipdisc++;
#ifdef SUP_IP6
            p->family = NO_IP;
#endif
            return;
        }
        else
        {
#ifdef DEBUG
            if (BcLogVerbose())
                ErrorMessage("IP Len field is %d bytes "
                        "smaller than captured length.\n"
                        "    (ip.len: %lu, cap.len: %lu)\n",
                        len - ip_len, ip_len, len);
#endif

        }
    }

    if(ip_len < hlen)
    {
        if(BcLogVerbose())
        {
            ErrorMessage("IP dgm len (%d bytes) < IP hdr "
                    "len (%d bytes), packet discarded\n", ip_len, hlen);
        }

        p->iph = NULL;
        pc.discards++;
        pc.ipdisc++;
#ifdef SUP_IP6
        p->family = NO_IP;
#endif        
        return;
    }


//    if (BcIpChecksums())
    {
        /* routers drop packets with bad IP checksums, we don't really 
         * need to check them (should make this a command line/config
         * option
         */
        csum = in_chksum_ip((u_short *)p->iph, hlen);

        if(csum)
        {
            p->csum_flags |= CSE_IP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad IP checksum\n"););
        }
#ifdef DEBUG
        else
        {
            DebugMessage(DEBUG_DECODE, "IP Checksum: OK\n");
        }
#endif /* DEBUG */
    }

    /* test for IP options */
    p->ip_options_len = (uint16_t)(hlen - IP_HEADER_LEN);

    if(p->ip_options_len > 0)
    {
        p->ip_options_data = pkt + IP_HEADER_LEN;
        DecodeIPOptions((pkt + IP_HEADER_LEN), p->ip_options_len, p);
    }
    else
    {
#ifdef GRE
        /* If delivery header for GRE encapsulated packet is IP and it 
         * had options, the packet's ip options will be refering to this
         * outer IP's options
         * Zero these options so they aren't associated with this inner IP
         * since p->iph will be pointing to this inner IP
         */
        if (p->encapsulated)
        {
            p->ip_options_data = NULL;
            p->ip_options_len = 0;
            memset(&(p->ip_options[0]), 0, sizeof(p->ip_options));
            p->ip_lastopt_bad = 0;
        }
#endif
        p->ip_option_count = 0;
    }

    /* set the real IP length for logging */
    p->actual_ip_len = (uint16_t) ip_len;

    /* set the remaining packet length */
    ip_len -= hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->iph->ip_off);

    /* 
     * get the values of the reserved, more 
     * fragments and don't fragment flags 
     */
    p->rf = (uint8_t)((p->frag_offset & 0x8000) >> 15);
    p->df = (uint8_t)((p->frag_offset & 0x4000) >> 14);
    p->mf = (uint8_t)((p->frag_offset & 0x2000) >> 13);

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if(p->frag_offset || p->mf)
    {
        /* set the packet fragment flag */
        p->frag_flag = 1;
        p->ip_frag_start = pkt + hlen;
        p->ip_frag_len = (uint16_t)ip_len;
        pc.frags++;
    } 
    else 
    {
        p->frag_flag = 0;
    }

    /* Set some convienience pointers */
    p->ip_data = pkt + hlen;
    p->ip_dsize = (u_short) ip_len;

    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset isn't 0 */
    if(!(p->frag_flag) || 
            (p->frag_flag && (p->frag_offset == 0) && 
            (p->iph->ip_proto == IPPROTO_UDP)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP header length: %lu\n", 
                    (unsigned long)hlen););

        switch(p->iph->ip_proto)
        {
            case IPPROTO_TCP:
                pc.tcp++;
                DecodeTCP(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;

            case IPPROTO_UDP:
                pc.udp++;
                DecodeUDP(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;

            case IPPROTO_ICMP:
                pc.icmp++;
                DecodeICMP(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;
            
#ifdef GRE
            case IPPROTO_IPV6:
                if (ip_len < 40)
                {
                    /* Insufficient size for IPv6 Header. */
                    /* This could be an attempt to exploit Linux kernel
                     * vulnerability, so log an alert */
//                    DecoderEvent(p, DECODE_IPV6_TUNNELED_IPV4_TRUNCATED,
//                                DECODE_IPV6_TUNNELED_IPV4_TRUNCATED_STR,
//                                pv.decoder_flags.decode_alerts,
//                                pv.decoder_flags.drop_alerts);
                }
                pc.ip4ip6++;
                DecodeIPV6(pkt + hlen, ip_len, p);
                return;

            case IPPROTO_GRE:
                pc.gre++;
                DecodeGRE(pkt + hlen, ip_len, p);
                //ClearDumpBuf();
                return;

            case IPPROTO_IPIP:
                pc.ip4ip4++;
                DecodeIP(pkt + hlen, ip_len, p);
                return;
#endif

            default:
                pc.other++;
                p->data = pkt + hlen;
                p->dsize = (u_short) ip_len;
                //ClearDumpBuf();
                return;
        }
    }
    else
    {
        /* set the payload pointer and payload size */
        p->data = pkt + hlen;
        p->dsize = (u_short) ip_len;
    }
}

/*
 * Function: DecodeTCP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => Pointer to packet decode struct
 *
 * Returns: void function
 */
void DecodeTCP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    struct pseudoheader6       /* pseudo header for TCP checksum calculations */
    {
        uint32_t sip[4], dip[4];   /* IP addr */
        uint8_t  zero;       /* checksum placeholder */
        uint8_t  protocol;   /* protocol number */
        uint16_t tcplen;     /* tcp packet length */
    };

    struct pseudoheader       /* pseudo header for TCP checksum calculations */
    {
        uint32_t sip, dip;   /* IP addr */
        uint8_t  zero;       /* checksum placeholder */
        uint8_t  protocol;   /* protocol number */
        uint16_t tcplen;     /* tcp packet length */
    };
    uint32_t hlen;            /* TCP header length */
    u_short csum;              /* checksum */
    struct pseudoheader ph;    /* pseudo header declaration */
#ifdef SUP_IP6
    struct pseudoheader6 ph6;    /* pseudo header declaration */
#endif


    if(len < TCP_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("TCP packet (len = %d) cannot contain "
                         "20 byte header\n", len);
        }

        p->tcph = NULL;
        pc.discards++;
        pc.tdisc++;

        return;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    p->tcph = (TCPHdr *) pkt;

    /* multiply the payload offset value by 4 */
    hlen = TCP_OFFSET(p->tcph) << 2;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "TCP th_off is %d, passed len is %lu\n", 
                TCP_OFFSET(p->tcph), (unsigned long)len););

    if(hlen < TCP_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("TCP Data Offset (%d) < hlen (%d) \n",
                         TCP_OFFSET(p->tcph), hlen);
        }

        p->tcph = NULL;
        pc.discards++;
        pc.tdisc++;

        return;
    }

    if(hlen > len)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("TCP Data Offset(%d) < longer than payload(%d)!\n",
                         TCP_OFFSET(p->tcph) << 2, len);
        }

        p->tcph = NULL;
        pc.discards++;
        pc.tdisc++;

        return;
    }

    /* stuff more data into the printout data struct */
    p->sp = ntohs(p->tcph->th_sport);
    p->dp = ntohs(p->tcph->th_dport);

//    if (BcTcpChecksums())
    {
#ifdef SUP_IP6
        if(IS_IP4(p)) 
        {
            ph.sip = *p->ip4h->ip_src.ip32;
            ph.dip = *p->ip4h->ip_dst.ip32;
#else
            ph.sip = (uint32_t)(p->iph->ip_src.s_addr);
            ph.dip = (uint32_t)(p->iph->ip_dst.s_addr);
#endif
            /* setup the pseudo header for checksum calculation */
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.tcplen = htons((u_short)len);
    
            /* if we're being "stateless" we probably don't care about the TCP 
             * checksum, but it's not bad to keep around for shits and giggles */
            /* calculate the checksum */
            csum = in_chksum_tcp((uint16_t *)&ph, (uint16_t *)(p->tcph), len);
#ifdef SUP_IP6
        } 
        /* IPv6 traffic */
        else
        {   
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.tcplen = htons((u_short)len);

            csum = in_chksum_tcp6((uint16_t *)&ph6, (uint16_t *)(p->tcph), len);
        }   
#endif
        
        if(csum)
        {
            p->csum_flags |= CSE_TCP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad TCP checksum\n",
                                    "0x%x versus 0x%x\n", csum,
                                    ntohs(p->tcph->th_sum)););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"TCP Checksum: OK\n"););
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "tcp header starts at: %p\n", p->tcph););


    /* if options are present, decode them */
    p->tcp_options_len = (uint16_t)(hlen - TCP_HEADER_LEN);
    
    if(p->tcp_options_len > 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%lu bytes of tcp options....\n", 
                    (unsigned long)(p->tcp_options_len)););

        p->tcp_options_data = pkt + TCP_HEADER_LEN;
        DecodeTCPOptions((uint8_t *) (pkt + TCP_HEADER_LEN), p->tcp_options_len, p);
    }
    else
    {
        p->tcp_option_count = 0;
    }

    /* set the data pointer and size */
    p->data = (uint8_t *) (pkt + hlen);

    if(hlen < len)
    {
        p->dsize = (u_short)(len - hlen);
    }
    else
    {
        p->dsize = 0;
    }

    /*  Drop packet if we ignore this port  */
//    if (BcIgnoreTcpPort(p->sp) || BcIgnoreTcpPort(p->dp))
//    {
//        /*  Ignore all preprocessors for this packet */
//        p->packet_flags |= PKT_IGNORE_PORT;
//    }

    p->proto_bits |= PROTO_BIT__TCP;
}


/*
 * Function: DecodeUDP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct  
 *
 * Returns: void function
 */
void DecodeUDP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    struct pseudoheader6
    {
        uint32_t sip[4], dip[4];
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t udplen;
    };

    struct pseudoheader 
    {
        uint32_t sip, dip;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t udplen;
    };
    u_short csum;
    uint16_t uhlen;
    struct pseudoheader ph;
#ifdef SUP_IP6
    struct pseudoheader6 ph6;
#endif
    u_char fragmented_udp_flag = 0;

    if(len < sizeof(UDPHdr))
    {
        if (BcLogVerbose())
            ErrorMessage("Truncated UDP header (%d bytes)\n", len);

        p->udph = NULL;
        pc.discards++;
        pc.udisc++;

        return;
    }

    /* set the ptr to the start of the UDP header */
    p->udph = (UDPHdr *) pkt;

    if (!p->frag_flag)
    {
        uhlen = ntohs(p->udph->uh_len);
    }
    else
    {
        if(IS_IP6(p))
        {
            uint16_t ip_len = ntohs(GET_IPH_LEN(p));
            /* subtract the distance from udp header to 1st ip6 extension */
            /* This gives the length of the UDP "payload", when fragmented */
            uhlen = ip_len - ((u_char *)p->udph - (u_char *)p->ip6_extensions[0].data);
        }
        else 
        {
            uint16_t ip_len = ntohs(GET_IPH_LEN(p));
            /* Don't forget, IP_HLEN is a word - multiply x 4 */       
            uhlen = ip_len - (GET_IPH_HLEN(p) * 4 );
        }
        fragmented_udp_flag = 1;
    }
    
    /* verify that the header len is a valid value */
    if(uhlen < UDP_HEADER_LEN)
    {
        if (BcLogVerbose())
            ErrorMessage("Invalid UDP Packet, length field < 8\n");
        
        p->udph = NULL;
        pc.udisc++;
        pc.discards++;

        return;
    }

    /* make sure there are enough bytes as designated by length field */
    if(len < uhlen)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Short UDP packet, length field > payload length\n");
        }

        p->udph = NULL;
        pc.discards++;
        pc.udisc++;

        return;
    } 
    else if(len > uhlen)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Long UDP packet, length field < payload length\n");
        }

        p->udph = NULL;
        pc.discards++;
        pc.udisc++;

        return;
    }

    /* fill in the printout data structs */
    p->sp = ntohs(p->udph->uh_sport);
    p->dp = ntohs(p->udph->uh_dport);

//    if (BcUdpChecksums())
    {
        /* look at the UDP checksum to make sure we've got a good packet */
#ifdef SUP_IP6
        if(IS_IP4(p)) 
        {
            ph.sip = *p->ip4h->ip_src.ip32;
            ph.dip = *p->ip4h->ip_dst.ip32;
#else
            ph.sip = (uint32_t)(p->iph->ip_src.s_addr);
            ph.dip = (uint32_t)(p->iph->ip_dst.s_addr);
#endif
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.udplen = p->udph->uh_len; 
            /* Don't do checksum calculation if
             * 1) Framented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && p->udph->uh_chk )
            {
                csum = in_chksum_udp((uint16_t *)&ph, 
                        (uint16_t *)(p->udph), uhlen); 
            }
            else
            {
                csum = 0;
            }
#ifdef SUP_IP6
        }
        else 
        {
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.udplen = htons((u_short)len);
            /* Don't do checksum calculation if
             * 1) Framented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && p->udph->uh_chk )
            {
                csum = in_chksum_udp6((uint16_t *)&ph6, 
                        (uint16_t *)(p->udph), uhlen); 
            }
            else if ( !p->udph->uh_chk )
            {
                csum = 1;
            }
            else
            {
                csum = 0;
            }
        }
#endif
        if(csum)
        {
            p->csum_flags |= CSE_UDP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad UDP Checksum\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP Checksum: OK\n"););
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP header starts at: %p\n", p->udph););

    p->data = (uint8_t *) (pkt + UDP_HEADER_LEN);
    
    /* length was validated up above */
    p->dsize = uhlen - UDP_HEADER_LEN; 

    /*  Drop packet if we ignore this port  */
//    if (BcIgnoreUdpPort(p->sp) || BcIgnoreUdpPort(p->dp))
//    {
//        /*  Ignore all preprocessors for this packet */
//        p->packet_flags |= PKT_IGNORE_PORT;
//    }

    p->proto_bits |= PROTO_BIT__UDP;
}



/*
 * Function: DecodeICMP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the decoded packet struct
 *
 * Returns: void function
 */
void DecodeICMP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    uint16_t csum;

    if(len < ICMP_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("WARNING: Truncated ICMP header "
                         "(%d bytes)\n", len);
        }
        
        p->icmph = NULL;
        pc.discards++;
        pc.icmpdisc++;

        return;
    }

    /* set the header ptr first */
    p->icmph = (ICMPHdr *) pkt;

    switch (p->icmph->type)
    {
        case ICMP_DEST_UNREACH:
        case ICMP_SOURCE_QUENCH:
        case ICMP_REDIRECT:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
        case ICMP_ROUTER_ADVERTISE:
        case ICMP_ROUTER_SOLICIT:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
            if (len < 8)
            {
                if (BcLogVerbose())
                {
                    ErrorMessage("Truncated ICMP header(%d bytes)\n", len);
                }

                p->icmph = NULL;
                pc.discards++;
                pc.icmpdisc++;
        
                return;
            }

            break;

        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
            if (len < 20)
            {
                if (BcLogVerbose())
                {
                    ErrorMessage("Truncated ICMP header(%d bytes)\n", len);
                }

                p->icmph = NULL;
                pc.discards++;
                pc.icmpdisc++;

                return;
            }

            break;

        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            if (len < 12)
            {
                if (BcLogVerbose())
                {
                    ErrorMessage("Truncated ICMP header(%d bytes)\n", len);
                }

                p->icmph = NULL;
                pc.discards++;
                pc.icmpdisc++;

                return;
            }

            break;
    }


//    if (BcIcmpChecksums())
    {
        csum = in_chksum_icmp((uint16_t *)p->icmph, len);

        if(csum)
        {
            p->csum_flags |= CSE_ICMP;

            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad ICMP Checksum\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
        }
    }

    p->dsize = (u_short)(len - ICMP_HEADER_LEN);
    p->data = pkt + ICMP_HEADER_LEN;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n", 
                p->icmph->code, p->icmph->type););

    switch(p->icmph->type)
    {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            /* setup the pkt id and seq numbers */
            p->dsize -= sizeof(struct idseq);   /* add the size of the 
                                                 * echo ext to the data
                                                 * ptr and subtract it 
                                                 * from the data size */
            p->data += sizeof(struct idseq);
            break;

        case ICMP_DEST_UNREACH:
        case ICMP_REDIRECT:
        case ICMP_SOURCE_QUENCH:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
            /* account for extra 4 bytes in header */
            p->dsize -= 4; 
            p->data += 4;

            DecodeICMPEmbeddedIP(p->data, p->dsize, p);

            break;
    }

    p->proto_bits |= PROTO_BIT__ICMP;
}

/*
 * Function: DecodeICMPEmbeddedIP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP header + 64 bits payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
void DecodeICMPEmbeddedIP(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    uint32_t hlen;             /* ip header length */
    uint16_t orig_frag_offset;

    /* do a little validation */
    if(len < IP_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("ICMP: IP short header (%d bytes)\n", len);
        }

#ifdef SUP_IP6
        p->orig_family = NO_IP;
#endif
        p->orig_iph = NULL;
        return;
    }

    /* lay the IP struct over the raw data */
#ifdef SUP_IP6
    sfiph_orig_build(p, pkt, AF_INET);
#endif
    p->orig_iph = (IPHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP: ip header"
                    " starts at: %p, length is %lu\n", p->orig_iph, 
                    (unsigned long) len););
    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if((GET_ORIG_IPH_VER(p) != 4) && !IS_IP6(p))
    {
        if (BcLogVerbose())
        {
            ErrorMessage("ICMP: not IPv4 datagram "
                         "([ver: 0x%x][len: 0x%x])\n", 
                         GET_ORIG_IPH_VER(p), GET_ORIG_IPH_LEN(p));

        }

#ifdef SUP_IP6
        p->orig_family = NO_IP;
#endif
        p->orig_iph = NULL;
        return;
    }

    /* set the IP datagram length */
    ip_len = ntohs(GET_ORIG_IPH_LEN(p));

    /* set the IP header length */
#ifdef SUP_IP6
    hlen = (p->orig_ip4h->ip_verhl & 0x0f) << 2;
#else
    hlen = IP_HLEN(p->orig_iph) << 2;
#endif

    if(len < hlen)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("ICMP: IP len (%d bytes) < "
                         "IP hdr len (%d bytes), packet discarded\n", ip_len, hlen);
        }

#ifdef SUP_IP6
        p->orig_family = NO_IP;
#endif
        p->orig_iph = NULL;
        return;
    }

    /* set the remaining packet length */
    ip_len = len - hlen;

    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
    orig_frag_offset &= 0x1FFF;

    if (orig_frag_offset == 0) 
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            if (BcLogVerbose())
            {
                ErrorMessage("ICMP: IP payload length < 64 bits\n");
            }

            return;
        }
        /* ICMP error packets could contain as much of original payload
         * as possible, but not exceed 576 bytes
         */
        else if (ntohs(GET_IPH_LEN(p)) > 576)
        {
            if (BcLogVerbose())
            {
                ErrorMessage("ICMP: ICMP error packet length > 576 bytes\n");
            }
        }
    }
    else
    {
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP Unreachable IP header length: "
                            "%lu\n", (unsigned long)hlen););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + hlen);

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (UDPHdr *)(pkt + hlen);

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + hlen);
            break;
    }

    return;
}

/*
 * Function: DecodeARP(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode ARP stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeARP(const uint8_t * pkt, uint32_t len, Packet * p)
{
    pc.arp++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_arp++;
#endif

    p->ah = (EtherARP *) pkt;

    if(len < sizeof(EtherARP))
    {
        if (BcLogVerbose())
            ErrorMessage("Truncated packet\n");

        pc.discards++;
        return;
    }

    p->proto_bits |= PROTO_BIT__ARP;
}

#ifndef NO_NON_ETHER_DECODER
/*
 * Function: DecodeEapol(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode 802.1x eapol stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapol(const uint8_t * pkt, uint32_t len, Packet * p)
{
    p->eplh = (EtherEapol *) pkt;
    pc.eapol++;
    if(len < sizeof(EtherEapol))
    {
        if (BcLogVerbose())
            ErrorMessage("Truncated packet\n");

        pc.discards++;
        return;
    }
    if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }    
    else if(p->eplh->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }
    return;
}

/*
 * Function: DecodeEapolKey(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode 1x key setup
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapolKey(const uint8_t * pkt, uint32_t len, Packet * p)
{
    p->eapolk = (EapolKey *) pkt;
    if(len < sizeof(EapolKey))
    {
        if(BcLogVerbose())
            ErrorMessage("Truncated packet\n");

        pc.discards++;
        return;
    }

    return;  
}

/*
 * Function: DecodeEAP(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Extensible Authentication Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEAP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    p->eaph = (EAPHdr *) pkt;
    if(len < sizeof(EAPHdr))
    {
        if (BcLogVerbose())
            printf("Truncated packet\n");

        pc.discards++;
        return;
    }
    if (p->eaph->code == EAP_CODE_REQUEST ||
            p->eaph->code == EAP_CODE_RESPONSE) {
        p->eaptype = pkt + sizeof(EAPHdr);
    }
    return;
}
#endif  // NO_NON_ETHER_DECODER

#ifdef SUP_IP6
/*
 * Function: DecodeICMPEmbeddedIP6(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP6 header + payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
void DecodeICMPEmbeddedIP6(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    uint32_t hlen;             /* ip header length */
    uint16_t orig_frag_offset;
    

    /* lay the IP struct over the raw data */
    IP6Hdr *ip6h = (IP6Hdr *) pkt;
    pc.embdip++;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP6: ip header"
                    " starts at: %p, length is %lu\n", ip6h, 
                    (unsigned long) len););

    /* do a little validation */
    if(len < IP6_HDR_LEN)
    {
        if (BcLogVerbose())
            ErrorMessage("ICMP6: IP short header (%d bytes)\n", len);

        pc.discards++;
        return;
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
// XXX-IPv6 double check this - checking version in IPv6 header
    if((ip6h->vcl & 0xf0) != 0x60)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("ICMP: not IPv6 datagram "
                         "([ver: 0x%x][len: 0x%x])\n", 
                        // XXX-IPv6 shouldn't the length be ntohs'ed?
                         (ip6h->vcl & 0x0f)>>4, ip6h->len);

        }

        pc.discards++;
        return;
    }

    /* set the IP datagram length */
    ip_len = ntohs(ip6h->len);

    /* set the IP header length */
    hlen = (ip6h->vcl & 0x0f ) << 2;

    if(len < hlen)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("ICMP6: IP6 len (%d bytes) < "
                         "IP6 hdr len (%d bytes), packet discarded\n", ip_len, hlen);
        }

        pc.discards++;
        return;
    }
#ifdef SUP_IP6
    sfiph_orig_build(p, pkt, AF_INET6);
#endif

    /* set the remaining packet length */
    ip_len = len - hlen;

    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
    orig_frag_offset &= 0x1FFF;

// XXX NOT YET IMPLEMENTED - fragments inside ICMP payload
#if 0
    if (orig_frag_offset == 0) 
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            if (BcLogVerbose())
            {
                ErrorMessage("ICMP6: IP6 payload length < 64 bits\n");
            }

            return;
        }
        /* ICMP6 error packets could contain as much of original payload
         * as possible, but not exceed the MTU
         */
#warning "MTU?"
        else if (ntohs(p->iph->ip_len) > 576)
        {
            if (BcLogVerbose())
            {
                ErrorMessage("ICMP: ICMP error packet length > 576 bytes\n");
            }
        }
    }
    else
    {
        return;
    }
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP6 Unreachable IP6 header length: "
                            "%lu\n", (unsigned long)hlen););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + hlen);

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (UDPHdr *)(pkt + hlen);

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + hlen);
            break;
    }

    return;
}

void DecodeICMP6(const uint8_t *pkt, uint32_t len, Packet *p)
{
    if(len < ICMP6_MIN_HEADER_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("WARNING: Truncated ICMP header "
                         "(%d bytes)\n", len);
        }
        
        pc.discards++;
        return;
    }
        
    p->icmph = (ICMPHdr*)pkt;
//    p->icmp6h = pkt;
//    p->icmph = (ICMPHdr*)p->icmp6h;
//    memcpy(&p->icmp6h, pkt, ICMP6_MIN_HEADER_LEN);
//    p->icmp6h.body = pkt + ICMP6_MIN_HEADER_LEN;  

    /* Do checksums */
    if(in_chksum_icmp6((uint16_t*)p->icmph, len))
    {
        p->csum_flags |= CSE_ICMP;

        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad ICMP Checksum\n"););
 
//        if(InlineMode() && (pv.checksums_drop & DO_ICMP_CHECKSUMS))
//        {     
//            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, 
//                        "Dropping packet with Bad ICMP checksum\n"););
//            InlineDrop(p);
//        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
    }

    
    p->dsize = (u_short)(len - ICMP6_MIN_HEADER_LEN); 
    p->data = pkt + ICMP6_MIN_HEADER_LEN;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n", 
                p->icmph->code, p->icmph->type););

    switch(p->icmph->type)
    {
        case ICMP6_ECHO:
        case ICMP6_REPLY:
            if (p->dsize >= sizeof(struct idseq))
            {
                p->icmp6h = (ICMP6Hdr *)pkt;
                /* Set data pointer to that of the "echo message" */
                p->dsize -= sizeof(struct idseq);   /* add the size of the 
                                                 * echo ext to the data
                                                 * ptr and subtract it 
                                                 * from the data size */
                p->data += sizeof(struct idseq);
            }
            else
            {
                if (BcLogVerbose())
                {
                    ErrorMessage("WARNING: Truncated ICMP Echo header "
                         "(%d bytes)\n", len);
                }

                p->icmp6h = NULL;
                pc.discards++;
                pc.icmpdisc++;
                return;
            }
            break;

        case ICMP6_TIME:
        case ICMP6_PARAMS:
        case ICMP6_BIG:
        case ICMP6_UNREACH:
            if (p->dsize >= 4)
            {
                p->icmp6h = (ICMP6Hdr *)pkt;
                /* Set data pointer past the 'unused/mtu/pointer block */
                p->data += 4;
                p->dsize -= 4;
                DecodeICMPEmbeddedIP6(p->data, p->dsize, p);
            }
            else
            {
                if (BcLogVerbose())
                {
                    ErrorMessage("WARNING: Truncated ICMP header "
                         "(%d bytes)\n", len);
                }

                p->icmp6h = NULL;
                pc.discards++;
                pc.icmpdisc++;
                return;
            }
            break;
    }

    p->proto_bits |= PROTO_BIT__ICMP;
}

void DecodeIPV6Extensions(uint8_t next, const uint8_t *pkt, uint32_t len, Packet *p);

void DecodeIPV6Options(int type, const uint8_t *pkt, uint32_t len, Packet *p)
{
    IP6Extension *exthdr;
    uint32_t hdrlen = 0;

    /* This should only be called by DecodeIPV6 or DecodeIPV6Extensions
     * so no validation performed.  Otherwise, uncomment the following: */
    /* if(IPH_IS_VALID(p)) return */

    pc.ipv6opts++;

    /* Need at least two bytes, one for next header, one for len. */
    /* But size is an integer multiple of 8 octets, so 8 is min.  */
    if(len < sizeof(IP6Extension))
    {
/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//        DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT,
//                     DECODE_IPV6_TRUNCATED_EXT_STR,
//                     pv.decoder_flags.decode_alerts,
//                     pv.decoder_flags.drop_alerts);
        return;
    }

    exthdr = (IP6Extension *)pkt;

    if(p->ip6_extension_count < IP6_EXTMAX)
    {
        p->ip6_extensions[p->ip6_extension_count].type = type;
        p->ip6_extensions[p->ip6_extension_count].data = pkt;

        switch (type)
        {
            case IPPROTO_HOPOPTS:
                if (len < sizeof(IP6HopByHop))
                {
/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//                    DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT,
//                                DECODE_IPV6_TRUNCATED_EXT_STR,
//                                pv.decoder_flags.decode_alerts,
//                                pv.decoder_flags.drop_alerts);
                    return;
                }
                hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);
                break;
            case IPPROTO_DSTOPTS:
                if (len < sizeof(IP6Dest))
                {
/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//                    DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT,
//                                 DECODE_IPV6_TRUNCATED_EXT_STR,
//                                 pv.decoder_flags.decode_alerts,
//                                 pv.decoder_flags.drop_alerts);
                    return;
                }
                hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);
                break;
            case IPPROTO_ROUTING:
                if (len < sizeof(IP6Route))
                {
/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//                    DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT,
//                                 DECODE_IPV6_TRUNCATED_EXT_STR,
//                                 pv.decoder_flags.decode_alerts,
//                                 pv.decoder_flags.drop_alerts);
                    return;
                }
                hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);
                break;
            case IPPROTO_FRAGMENT:
                {
                    IP6Frag *ip6frag_hdr = (IP6Frag *)pkt;
                    if (len < sizeof(IP6Frag))
                    {
/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//                        DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT,
//                                     DECODE_IPV6_TRUNCATED_EXT_STR,
//                                     pv.decoder_flags.decode_alerts,
//                                     pv.decoder_flags.drop_alerts);
                        return;
                    }
                    /* If this is an IP Fragment, set some data... */
                    p->ip6_frag_index = p->ip6_extension_count;
                    p->ip_frag_start = pkt + sizeof(IP6Frag);
                    p->frag_flag = 1;
                    pc.frag6++;

                    p->df = 0;
                    p->rf = IP6F_RES(ip6frag_hdr);
                    p->mf = IP6F_MF(ip6frag_hdr);
                    p->frag_offset = IP6F_OFFSET(ip6frag_hdr);
                }
                hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);
                p->ip_frag_len = (uint16_t)(len - hdrlen);
                break;
            default:
                hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);
                break;
        }

        p->ip6_extension_count++;
    }

    if(hdrlen > len) 
    {
/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//        DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT,
//                     DECODE_IPV6_TRUNCATED_EXT_STR,
//                    pv.decoder_flags.decode_alerts,
//                     pv.decoder_flags.drop_alerts);
        return;
    }

    DecodeIPV6Extensions(*pkt, pkt + hdrlen, len - hdrlen, p);
}

void DecodeIPV6Extensions(uint8_t next, const uint8_t *pkt, uint32_t len, Packet *p)
{
    pc.ip6ext++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ipv6ext++;
#endif

    /* XXX might this introduce an issue if the "next" field is invalid? */
    p->ip6h->next = next;

    switch(next) {
        case IPPROTO_TCP:
            pc.tcp6++;
            DecodeTCP(pkt, len, p);
            return;
        case IPPROTO_UDP:
            pc.udp6++;
            DecodeUDP(pkt, len, p);
            return;
        case IPPROTO_ICMP:
            pc.icmp++;
            DecodeICMP(pkt, len, p);
            return;
        case IPPROTO_ICMPV6:
            pc.icmp6++;
            DecodeICMP6(pkt , len, p);
            return;
#ifndef SUP_IP6
        case IPPROTO_FRAGMENT:
            // XXX
            // Fragmentation not yet supported
            // DecodeIPv6FragHdr(p, pkt);
            // XXX 
             
            p->frag_flag = 1;
            pc.frag6++;
            p->dsize = 0;
            return;
#endif
        case IPPROTO_NONE:
            p->dsize = 0;
            return;
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
#ifdef SUP_IP6
        case IPPROTO_FRAGMENT:
#endif
            DecodeIPV6Options(next, pkt, len, p); 
            // Anything special to do here?  just return?
            return;
#ifdef GRE
        case IPPROTO_GRE:
            pc.gre++;
            DecodeGRE(pkt, len, p);
            return;
        case IPPROTO_IPIP:
            pc.ip6ip4++;
            DecodeIP(pkt, len, p);
            return;
        case IPPROTO_IPV6:
            pc.ip6ip6++;
            DecodeIPV6(pkt, len, p);
            return;
#endif
        default: 
            // There may be valid headers after this unsupported one,
            // need to decode this header, set "next" and continue 
            // looping.
            pc.other++;
            p->data = pkt;
            p->dsize = (uint16_t)len;
            break;
    };
}
#endif /* SUP_IP6 */

/*
 * Function: DecodeIPV6(uint8_t *, uint32_t)
 *
 * Purpose: Decoding IPv6 headers
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeIPV6(const uint8_t *pkt, uint32_t len, Packet *p)
{
#ifndef SUP_IP6
    static uint8_t pseudopacket_buf[SPARC_TWIDDLE + ETHERNET_HEADER_LEN + IP_MAXPACKET];
    static Packet pseudopacket;
    static struct pcap_pkthdr pseudopcap_header;
    IP6RawHdr *ip6h;
//    int alert_status;

    pc.ipv6++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ipv6++;
#endif

//    alert_status = CheckIPV6Frag((char *) pkt, len, p);

//    if(alert_status == IPV6_FRAG_NO_ALERT)
//    {
//        return;
//    }

    p->packet_flags |= PKT_NO_DETECT;

    /* Need to set up a fake IP header for logging purposes.  First make sure
     * there is room */
    if(sizeof(IP6RawHdr) <= len) 
    {
        pseudopcap_header.ts.tv_sec = p->pkth->ts.tv_sec;
        pseudopcap_header.ts.tv_usec = p->pkth->ts.tv_usec;

        BsdPseudoPacket = &pseudopacket;
        pseudopacket.pkt = pseudopacket_buf + SPARC_TWIDDLE;
        pseudopacket.pkth = &pseudopcap_header;

        if(p->eh)
        {
            SafeMemcpy(pseudopacket_buf + SPARC_TWIDDLE, p->eh, 
                       ETHERNET_HEADER_LEN,
                       pseudopacket_buf, 
                       pseudopacket_buf + SPARC_TWIDDLE + ETHERNET_HEADER_LEN + IP_MAXPACKET);

            pseudopcap_header.len = IP_HEADER_LEN + ETHERNET_HEADER_LEN;

            pseudopacket.eh = (EtherHdr*)(pseudopacket_buf + SPARC_TWIDDLE);
            pseudopacket.iph = (IPHdr*)(pseudopacket_buf + SPARC_TWIDDLE + ETHERNET_HEADER_LEN);
            ((EtherHdr*)pseudopacket.eh)->ether_type = htons(ETHERNET_TYPE_IP);
        }
        else
        {
            SafeMemcpy(pseudopacket_buf, p->pkt, 
                       (pkt - p->pkt),
                       pseudopacket_buf, 
                       pseudopacket_buf + SPARC_TWIDDLE + ETHERNET_HEADER_LEN + IP_MAXPACKET);

            pseudopcap_header.len = IP_HEADER_LEN + (pkt - p->pkt);

            pseudopacket.iph = (IPHdr*)(pseudopacket_buf + (pkt - p->pkt));
            pseudopacket.eh = NULL;
        }

        pseudopcap_header.caplen = pseudopcap_header.len;

        /* Need IP addresses for packet logging -- for now, just using the 
         * lowest 4 bytes of the IPv6 addresses */
        memset((IPHdr *)pseudopacket.iph, 0, sizeof(IPHdr));

        ((IPHdr *)pseudopacket.iph)->ip_len = htons(IP_HEADER_LEN);
        SET_IP_VER((IPHdr *)pseudopacket.iph, 0x4);
        SET_IP_HLEN((IPHdr *)pseudopacket.iph, 0x5);

        ip6h = (IP6RawHdr*)pkt;
   
#ifdef WORDS_BIGENDIAN
        ((IPHdr *)pseudopacket.iph)->ip_src.s_addr =
            ip6h->ip6_src.s6_addr[13] << 16 | ip6h->ip6_src.s6_addr[14] << 8 | ip6h->ip6_src.s6_addr[15];
        ((IPHdr *)pseudopacket.iph)->ip_dst.s_addr =
            ip6h->ip6_dst.s6_addr[13] << 16 | ip6h->ip6_dst.s6_addr[14] << 8 | ip6h->ip6_dst.s6_addr[15];
#else
        ((IPHdr *)pseudopacket.iph)->ip_src.s_addr =
            ip6h->ip6_src.s6_addr[15] << 24 | ip6h->ip6_src.s6_addr[14] << 16 | ip6h->ip6_src.s6_addr[13] << 8;
        ((IPHdr *)pseudopacket.iph)->ip_dst.s_addr =
            ip6h->ip6_dst.s6_addr[15] << 24 | ip6h->ip6_dst.s6_addr[14] << 16 | ip6h->ip6_dst.s6_addr[13] << 8;
#endif
    }
    else 
    {
        p->iph = NULL;
    }

    pc.discards++;
    return;
#else

    IP6RawHdr *hdr; 
    uint32_t payload_len;

    pc.ipv6++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ipv6++;
#endif

    hdr = (IP6RawHdr*)pkt;

    if(len < IP6_HDR_LEN)
    {
        if (BcLogVerbose())
        {
            ErrorMessage("IP6 header truncated! (%d bytes)\n", len);
        }

/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//        DecoderEvent(p, DECODE_IPV6_TRUNCATED, DECODE_IPV6_TRUNCATED_STR,
//                     pv.decoder_flags.decode_alerts, pv.decoder_flags.drop_alerts);

        goto decodeipv6_fail;
    }

    /* Verify version in IP6 Header agrees */
    if((hdr->ip6vfc >> 4) != 6) 
    {
        if (BcLogVerbose())
        {
            ErrorMessage("Not IPv6 datagram! ([ver: 0x%x][len: 0x%x])\n", 
                    (hdr->ip6vfc >> 4), hdr->ip6plen + IP6_HDR_LEN);
        }

/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//        DecoderEvent(p, DECODE_IPV6_IS_NOT, 
//                DECODE_IPV6_IS_NOT_STR, 
//                pv.decoder_flags.decode_alerts,
//                pv.decoder_flags.drop_alerts);

        goto decodeipv6_fail;
    }

#ifdef GRE
    if (p->family != NO_IP)
    {
        IP6RawHdr *tmp = (IP6RawHdr *)pkt;

        if (p->encapsulated ||
            ((tmp->ip6nxt == IPPROTO_IPIP) || (tmp->ip6nxt == IPPROTO_GRE) ||
             (tmp->ip6nxt == IPPROTO_IPV6)))
        {

            DecoderAlertGRE(p, DECODE_GRE_MULTIPLE_ENCAPSULATION,
                            DECODE_GRE_MULTIPLE_ENCAPSULATION_STR,
                            pkt, len);
            return;
        }
        else
        {
            p->encapsulated = 1;
            p->outer_iph = p->iph;
            p->outer_ip_data = p->ip_data;
            p->outer_ip_dsize = p->ip_dsize;
        }
    }
#endif
    /* lay the IP struct over the raw data */
    p->inner_iph = p->iph = (IPHdr *)pkt;

    payload_len = ntohs(hdr->ip6plen) + IP6_HDR_LEN;

    if(payload_len != len)
    {
        if (payload_len > len) 
        {
#ifdef DEBUG
            if (BcLogVerbose())
            {
                ErrorMessage("IP Len field is %d bytes bigger than captured "
                             "length (ip.len: %lu, cap.len: %lu)\n",
                             payload_len - len, payload_len, len);
            }
#endif
/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
//            DecoderEvent(p, DECODE_IPV6_DGRAM_GT_CAPLEN, 
//                    DECODE_IPV6_DGRAM_GT_CAPLEN_STR, 
//                    pv.decoder_flags.oversized_alert,
//                    pv.decoder_flags.oversized_drop);

            goto decodeipv6_fail;
        }
        else
        {
#ifdef DEBUG
            if (BcLogVerbose())
            {
                ErrorMessage("IP Len field is %d bytes smaller than captured "
                             "length (ip.len: %lu, cap.len: %lu)\n",
                             len - payload_len, payload_len, len);
            }
#endif
        }
    }

/*
** barnyard2
** As we are reading from the unified2 file, when decoding these packets we
** don't want additional events to be created.
*/
    /* Check TTL */
//    if(hdr->ip6hops < pv.min_ttl) 
//    {
//        DecoderEvent(p, DECODE_IPV6_MIN_TTL, DECODE_IPV6_MIN_TTL_STR, 
//                    pv.decoder_flags.decode_alerts,
//                    pv.decoder_flags.drop_alerts);
//    }

    /* Build Packet structure's version of the IP6 header */
    sfiph_build(p, hdr, AF_INET6);

    {
#ifdef GRE
        /* Remove outer IP options */
        if (p->encapsulated)
        {
            p->ip_options_data = NULL;
            p->ip_options_len = 0;
            p->ip_lastopt_bad = 0;
        }
#endif
        p->ip_option_count = 0;
    }

    /* set the real IP length for logging */
    p->actual_ip_len = ntohs(p->ip6h->len);
    p->ip_data = pkt + IP6_HDR_LEN;
    p->ip_dsize = ntohs(p->ip6h->len);

    DecodeIPV6Extensions(GET_IPH_PROTO(p), pkt + IP6_HDR_LEN, ntohs(p->ip6h->len), p);
    return;

decodeipv6_fail:
    pc.discards++;
    pc.ipv6disc++;
    p->iph = NULL;  
    p->family = NO_IP;
#endif
}

/*
 * Function: DecodeEthLoopback(uint8_t *, uint32_t)
 *
 * Purpose: Just like IPX, it's just for counting.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEthLoopback(const uint8_t *pkt, uint32_t len, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "EthLoopback is not supported.\n"););

    pc.ethloopback++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_loopback++;
#endif

    return;
}


#ifndef NO_NON_ETHER_DECODER
/*
 * Function: DecodeIPX(uint8_t *, uint32_t)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 */
void DecodeIPX(const uint8_t *pkt, uint32_t len, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IPX is not supported.\n"););

    pc.ipx++;

#ifdef GRE
    if (p->greh != NULL)
        pc.gre_ipx++;
#endif

    return;
}
#endif  // NO_NON_ETHER_DECODER


#ifdef GRE
/*
 * Function: DecodeGRE(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Generic Routing Encapsulation Protocol
 *          This will decode normal GRE and PPTP GRE.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 * Notes: see RFCs 1701, 2784 and 2637
 */
void DecodeGRE(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t hlen;    /* GRE header length */
    uint32_t payload_len;

    if (len < GRE_HEADER_LEN)
    {
        DecoderAlertGRE(p, DECODE_GRE_DGRAM_LT_GREHDR,
                        DECODE_GRE_DGRAM_LT_GREHDR_STR,
                        pkt, len);
        return;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple GRE encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        DecoderAlertGRE(p, DECODE_GRE_MULTIPLE_ENCAPSULATION,
                        DECODE_GRE_MULTIPLE_ENCAPSULATION_STR,
                        pkt, len);
        return;
    }

    /* Note: Since GRE doesn't have a field to indicate header length and 
     * can contain a few options, we need to walk through the header to 
     * figure out the length
     */

    p->greh = (GREHdr *)pkt;
    hlen = GRE_HEADER_LEN;

    switch (GRE_VERSION(p->greh))
    {
        case 0x00:
            /* these must not be set */
            if (GRE_RECUR(p->greh) || GRE_FLAGS(p->greh))
            {
                DecoderAlertGRE(p, DECODE_GRE_INVALID_HEADER,
                                DECODE_GRE_INVALID_HEADER_STR,
                                pkt, len);
                return;
            }

            if (GRE_CHKSUM(p->greh) || GRE_ROUTE(p->greh))
                hlen += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;

            if (GRE_KEY(p->greh))
                hlen += GRE_KEY_LEN;

            if (GRE_SEQ(p->greh))
                hlen += GRE_SEQ_LEN;

            /* if this flag is set, we need to walk through all of the
             * Source Route Entries */
            if (GRE_ROUTE(p->greh))
            {
                uint16_t sre_addrfamily;
                uint8_t sre_offset;
                uint8_t sre_length;
                const uint8_t *sre_ptr;
               
                sre_ptr = pkt + hlen;

                while (1)
                {
                    hlen += GRE_SRE_HEADER_LEN;
                    if (hlen > len)
                        break;

                    sre_addrfamily = ntohs(*((uint16_t *)sre_ptr));
                    sre_ptr += sizeof(sre_addrfamily);

                    sre_offset = *((uint8_t *)sre_ptr);
                    sre_ptr += sizeof(sre_offset);

                    sre_length = *((uint8_t *)sre_ptr);
                    sre_ptr += sizeof(sre_length);

                    if ((sre_addrfamily == 0) && (sre_length == 0))
                        break;

                    hlen += sre_length;
                    sre_ptr += sre_length;
                }
            }

            break;

        /* PPTP */
        case 0x01:
            /* these flags should never be present */
            if (GRE_CHKSUM(p->greh) || GRE_ROUTE(p->greh) || GRE_SSR(p->greh) ||
                GRE_RECUR(p->greh) || GRE_V1_FLAGS(p->greh))
            {
                DecoderAlertGRE(p, DECODE_GRE_V1_INVALID_HEADER,
                                DECODE_GRE_V1_INVALID_HEADER_STR,
                                pkt, len);
                return;
            }

            /* protocol must be 0x880B - PPP */
            if (GRE_PROTO(p->greh) != GRE_TYPE_PPP)
            {
                DecoderAlertGRE(p, DECODE_GRE_V1_INVALID_HEADER,
                                DECODE_GRE_V1_INVALID_HEADER_STR,
                                pkt, len);
                return;
            }

            /* this flag should always be present */
            if (!(GRE_KEY(p->greh)))
            {
                DecoderAlertGRE(p, DECODE_GRE_V1_INVALID_HEADER,
                                DECODE_GRE_V1_INVALID_HEADER_STR,
                                pkt, len);
                return;
            }

            hlen += GRE_KEY_LEN;

            if (GRE_SEQ(p->greh))
                hlen += GRE_SEQ_LEN;

            if (GRE_V1_ACK(p->greh))
                hlen += GRE_V1_ACK_LEN;

            break;

        default:
            DecoderAlertGRE(p, DECODE_GRE_INVALID_VERSION,
                            DECODE_GRE_INVALID_VERSION_STR,
                            pkt, len);
            return;
    }

    if (hlen > len)
    {
        DecoderAlertGRE(p, DECODE_GRE_DGRAM_LT_GREHDR,
                        DECODE_GRE_DGRAM_LT_GREHDR_STR,
                        pkt, len);
        return;
    }

    payload_len = len - hlen;

    /* Send to next protocol decoder */
    /* As described in RFC 2784 the possible protocols are listed in
     * RFC 1700 under "ETHER TYPES"
     * See also "Current List of Protocol Types" in RFC 1701
     */
    switch (GRE_PROTO(p->greh))
    {
        case ETHERNET_TYPE_IP:
            DecodeIP(pkt + hlen, payload_len, p);
            return;

        case GRE_TYPE_TRANS_BRIDGING:
            DecodeTransBridging(pkt + hlen, payload_len, p); 
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            /* clear outer IP headers */
            p->iph = NULL;
#ifdef SUP_IP6
            p->family = NO_IP;
#endif
            DecodeARP(pkt + hlen, payload_len, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(pkt + hlen, payload_len, p); 
            return;

        case GRE_TYPE_PPP:
            DecodePppPktEncapsulated(p, payload_len, pkt + hlen);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_IPX:
            DecodeIPX(pkt + hlen, payload_len, p); 
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(pkt + hlen, payload_len, p);
            return; 

        /* not sure if this occurs, but 802.1q is an Ether type */
        case ETHERNET_TYPE_8021Q:
            DecodeVlan(pkt + hlen, payload_len, p);
            return; 

        default:
            pc.other++;
            p->data = pkt + hlen;
            p->dsize = (uint16_t)payload_len;
            return;
    }
}

/*
 * Function: DecodeTransBridging(uint8_t *, const uint32_t, Packet)
 *
 * Purpose: Decode Transparent Ethernet Bridging
 *
 * Arguments: pkt => pointer to the real live packet data
 *            len => length of remaining data in packet
 *            p => pointer to the decoded packet struct
 *            
 *
 * Returns: void function
 *
 * Note: This is basically the code from DecodeEthPkt but the calling
 * convention needed to be changed and the stuff at the beginning 
 * wasn't needed since we are already deep into the packet
 */
void DecodeTransBridging(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    pc.gre_eth++;

    if(len < ETHERNET_HEADER_LEN)
    {
        DecoderAlertGRE(p, DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR,
                        DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR_STR,
                        pkt, len);
        return;
    }

    /* The Packet struct's ethernet header will now point to the inner ethernet
     * header of the packet
     */
    p->eh = (EtherHdr *)pkt;

    switch (ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DecodeIP(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_IPX:
            DecodeIPX(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return; 

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return; 

        default:
            pc.other++;
            p->data = pkt + ETHERNET_HEADER_LEN;
            p->dsize = (uint16_t)(len - ETHERNET_HEADER_LEN);
            return;
    }
}

/* should probably generalize for all decoder alerts */
void DecoderAlertGRE(Packet *p, int type, const char *str, const uint8_t *pkt, uint32_t len)
{
    p->data = pkt;
    p->dsize = (uint16_t)len;

    p->greh = NULL;
}

#endif  /* GRE */


/** 
 * Validate that the length is an expected length AND that it's in bounds
 *
 * EOL and NOP are handled separately
 * 
 * @param option_ptr current location
 * @param end the byte past the end of the decode list
 * @param len_ptr the pointer to the length field
 * @param expected_len the number of bytes we expect to see per rfc KIND+LEN+DATA, -1 means dynamic.
 * @param tcpopt options structure to populate
 * @param byte_skip distance to move upon completion
 *
 * @return returns 0 on success, < 0 on error
 */
static INLINE int OptLenValidate(const uint8_t *option_ptr,
                                 const uint8_t *end,
                                 const uint8_t *len_ptr,
                                 int expected_len,
                                 Options *tcpopt,
                                 uint8_t *byte_skip)
{
    *byte_skip = 0;
    
    if(len_ptr == NULL)
    {
        return TCP_OPT_TRUNC;
    }
    
    if(*len_ptr == 0 || expected_len == 0 || expected_len == 1)
    {
        return TCP_OPT_BADLEN;
    }
    else if(expected_len > 1)
    {
        if((option_ptr + expected_len) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }

        if(*len_ptr != expected_len)
        {
            /* length is not valid */
            return TCP_OPT_BADLEN;
        }
    }
    else /* expected_len < 0 (i.e. variable length) */
    {
        if(*len_ptr < 2)
        {
            /* RFC sez that we MUST have atleast this much data */
            return TCP_OPT_BADLEN;
        }
           
        if((option_ptr + *len_ptr) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }
    }

    tcpopt->len = *len_ptr - 2;

    if(*len_ptr == 2)
    {
        tcpopt->data = NULL;
    }
    else
    {
        tcpopt->data = option_ptr + 2;
    }

    *byte_skip = *len_ptr;
    
    return 0;
}

/*
 * Function: DecodeTCPOptions(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 *          TCP Option Header length validation is left to the caller
 *
 *          For a good listing of TCP Options, 
 *          http://www.iana.org/assignments/tcp-parameters 
 *
 *   ------------------------------------------------------------
 *   From: "Kastenholz, Frank" <FKastenholz@unispherenetworks.com>
 *   Subject: Re: skeeter & bubba TCP options?
 *
 *   ah, the sins of ones youth that never seem to be lost...
 *
 *   it was something that ben levy and stev and i did at ftp many
 *   many moons ago. bridgham and stev were the instigators of it.
 *   the idea was simple, put a dh key exchange directly in tcp
 *   so that all tcp sessions could be encrypted without requiring
 *   any significant key management system. authentication was not
 *   a part of the idea, it was to be provided by passwords or
 *   whatever, which could now be transmitted over the internet
 *   with impunity since they were encrypted... we implemented
 *   a simple form of this (doing the math was non trivial on the
 *   machines of the day). it worked. the only failure that i 
 *   remember was that it was vulnerable to man-in-the-middle 
 *   attacks.
 *   
 *   why "skeeter" and "bubba"? well, that's known only to stev...
 *   ------------------------------------------------------------
 *
 * 4.2.2.5 TCP Options: RFC-793 Section 3.1
 *
 *    A TCP MUST be able to receive a TCP option in any segment. A TCP
 *    MUST ignore without error any TCP option it does not implement,
 *    assuming that the option has a length field (all TCP options
 *    defined in the future will have length fields). TCP MUST be
 *    prepared to handle an illegal option length (e.g., zero) without
 *    crashing; a suggested procedure is to reset the connection and log
 *    the reason.
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeTCPOptions(const uint8_t *start, uint32_t o_len, Packet *p)
{
    const uint8_t *option_ptr = start;
    const uint8_t *end_ptr = start + o_len; /* points to byte after last option */
    const uint8_t *len_ptr;
    uint8_t opt_count = 0;
    u_char done = 0; /* have we reached TCPOPT_EOL yet?*/
    u_char experimental_option_found = 0;      /* are all options RFC compliant? */
    u_char obsolete_option_found = 0;
    u_char ttcp_found = 0;
    
    int code = 2;
    uint8_t byte_skip;

    /* Here's what we're doing so that when we find out what these
     * other buggers of TCP option codes are, we can do something
     * useful
     * 
     * 1) get option code
     * 2) check for enough space for current option code
     * 3) set option data ptr
     * 4) increment option code ptr
     *
     * TCP_OPTLENMAX = 40 because of
     *        (((2^4) - 1) * 4  - TCP_HEADER_LEN)
     *      
     */

    if(o_len > TCP_OPTLENMAX)
    {
        /* This shouldn't ever alert if we are doing our job properly
         * in the caller */        
        p->tcph = NULL; /* let's just alert */
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                                "o_len(%u) > TCP_OPTLENMAX(%u)\n",
                                o_len, TCP_OPTLENMAX));
        return;
    }
    
    while((option_ptr < end_ptr) && (opt_count < TCP_OPTLENMAX) && (code >= 0) && !done)
    {
        p->tcp_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }
        
        switch(*option_ptr)
        {
        case TCPOPT_EOL:
            done = 1; /* fall through to the NOP case */
        case TCPOPT_NOP:
            p->tcp_options[opt_count].len = 0; 
            p->tcp_options[opt_count].data = NULL;
            byte_skip = 1;
            code = 0;
            break;
        case TCPOPT_MAXSEG:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MAXSEG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_SACKOK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_SACKOK,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_WSCALE:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_WSCALE,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_ECHO: /* both use the same lengths */
        case TCPOPT_ECHOREPLY:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_ECHO,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_MD5SIG:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MD5SIG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_SACK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            if(p->tcp_options[opt_count].data == NULL)
                code = TCP_OPT_BADLEN;

            break;
        case TCPOPT_CC_ECHO:
            ttcp_found = 1;
            /* fall through */
        case TCPOPT_CC:  /* all 3 use the same lengths / T/TCP */
        case TCPOPT_CC_NEW:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_CC,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_TRAILER_CSUM:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TRAILER_CSUM,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;

        case TCPOPT_TIMESTAMP:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TIMESTAMP,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
    
        case TCPOPT_SKEETER:
        case TCPOPT_BUBBA:
        case TCPOPT_UNASSIGNED:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        default:
        case TCPOPT_SCPS:  
        case TCPOPT_SELNEGACK:
        case TCPOPT_RECORDBOUND:
        case TCPOPT_CORRUPTION:
        case TCPOPT_PARTIAL_PERM:
        case TCPOPT_PARTIAL_SVC:
        case TCPOPT_ALTCSUM:
        case TCPOPT_SNAP:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        }

        if(code < 0)
        {
            /* set the option count to the number of valid
             * options found before this bad one
             * some implementations (BSD and Linux) ignore
             * the bad ones, but accept the good ones */
            p->tcp_option_count = opt_count;

            return;
        }

        opt_count++;

        option_ptr += byte_skip;
    }

    p->tcp_option_count = opt_count;

    return;
}


/*
 * Function: DecodeIPOptions(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeIPOptions(const uint8_t *start, uint32_t o_len, Packet *p)
{
    const uint8_t *option_ptr = start;
    u_char done = 0; /* have we reached IP_OPTEOL yet? */
    const uint8_t *end_ptr = start + o_len;
    uint8_t opt_count = 0; /* what option are we processing right now */
    uint8_t byte_skip;
    const uint8_t *len_ptr;
    int code = 0;  /* negative error codes are returned from bad options */
    

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,  "Decoding %d bytes of IP options\n", o_len););


    while((option_ptr < end_ptr) && (opt_count < IP_OPTMAX) && (code >= 0))
    {
        p->ip_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }

        switch(*option_ptr)
        {
        case IPOPT_NOP:
        case IPOPT_EOL:
            /* if we hit an EOL, we're done */
            if(*option_ptr == IPOPT_EOL)
                done = 1;
            
            p->ip_options[opt_count].len = 0;
            p->ip_options[opt_count].data = NULL;
            byte_skip = 1;
            break;
        default:
            /* handle all the dynamic features */
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->ip_options[opt_count], &byte_skip);
        }

        if(!done)
            opt_count++;

        option_ptr += byte_skip;
    }
    
    p->ip_option_count = opt_count;

    return;
}

#if defined(WORDS_MUSTALIGN) && !defined(__GNUC__)
uint32_t
EXTRACT_32BITS (u_char *p)
{
  uint32_t __tmp;

  memmove(&__tmp, p, sizeof(uint32_t));
  return (uint32_t) ntohl(__tmp);
}
#endif /* WORDS_MUSTALIGN && !__GNUC__ */

#ifdef MPLS
int isPrivateIP(uint32_t addr)
{
    switch (addr & 0xff)
    {
        case 0x0a:
            return 1;
            break;
        case 0xac:
            if ((addr & 0xf000) == 0x1000)
                return 1;
            break;
        case 0xc0:
            if (((addr & 0xff00) ) == 0xa800)
                return 1;
            break;
    }
    return 0;
}
#endif

/*
void InitSynToMulticastDstIp( void )
{
#ifdef SUP_IP6
    extern SnortConfig *snort_conf_for_parsing;
    snort_conf_for_parsing = snort_conf;
#endif
    SynToMulticastDstIp = IpAddrSetParse("[232.0.0.0/8,233.0.0.0/8,239.0.0.0/8]");

    if( SynToMulticastDstIp == NULL )
    {
        FatalError("Could not initialize SynToMulticastDstIp\n");
    }
#ifdef SUP_IP6
    snort_conf_for_parsing = NULL;
#endif
}

void SynToMulticastDstIpDestroy( void )
{

    if( SynToMulticastDstIp )
    {
        IpAddrSetDestroy(SynToMulticastDstIp);
#ifndef SUP_IP6
        free(SynToMulticastDstIp);
        SynToMulticastDstIp = NULL;
#endif
    }
}

*/

