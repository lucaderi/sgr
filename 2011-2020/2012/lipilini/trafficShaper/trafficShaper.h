/*
 * trafficShaper.h
 * API for trafficShaper
 * 
 * Jacopo Lipilini
 * 
 */

#include "tsTypes.h"

/*
 * initialize a new traffic shaper
 * 
 * no_mq, number of masterQueue
 * w[], array of weight (in bytes) of each masterQueue
 * no_sq, number of slaveQueue (one for each process, thread, ...)
 * qs, size of each queue of a slaveQueue
 * 
 * returns a pointer to initialized traffic shaper module or NULL on error
 */

trafficShaper_t * init_traffic_shaper(u_int16_t no_mq, u_int16_t w[], u_int16_t no_sq, u_int16_t qs);

/*
 * destroy a traffic shaper
 */

void term_traffic_shaper(trafficShaper_t * ts);

/*
 * enqueue a packet in slaveQueue sq of masterQueue mq of trafficShaper ts
 * 
 * returns 0 if successfully enqueue packet, -1 on error (queue full)
 */

int enqueue_packet(trafficShaper_t * ts, u_int16_t mq, u_int16_t sq, packet_t p);

/*
 * dequeue next packet from trafficShaper ts
 * 
 * wait, wait > 0, if there isn't any packet, ("active") wait until a new one is enqueued
 *       wait == 0, if there isn't any packet, returns a NULL_PACKET
 * 
 * returns the next packet to send (or a NULL_PACKET)
 */

packet_t dequeue_packet(trafficShaper_t * ts, u_int wait);

/*
 * dequeue and send n_pkt sendable packet from trafficShaper ts
 * 
 * n_pkt, n_pkt == 0, send sendable packet until an error occurs
 *        n_pkt > 0, send the specified number of packet
 * wait, (like dequeue_packet)
 * 
 * returns the number of sent packet
 */

u_int32_t send_shaped_traffic(trafficShaper_t * ts, u_int32_t n_pkt, u_int wait);