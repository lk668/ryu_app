## RYU controller app


#### test_band_v1.3.py

> Using to test the bandwidth of the topology.
> You should use the specific ovs. Which modify the action.c file and Add the following codes. The codes are used to set current time on Ipv4. So the controller can get the time which the packet arrive to the port on ovs by the IPv4.

```C
if (key->ipv4.addr.src == 0 && key->ipv4.addr.dst == 0){
               struct timeval time;
               do_gettimeofday(&time);
               __be32 local_time = (__be32)(time.tv_sec);
               __be32 mtime = (__be32)time.tv_usec;
               //key->ipv4.addr.src = local_time;
               //key->ipv4.addr.dst = mtime;
               nh = ip_hdr(skb);
               __be32 *addr = &nh->saddr;
               inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
                                *addr, local_time, 1);
               csum_replace4(&nh->check, *addr, local_time);
               skb_clear_hash(skb);
               *addr = local_time;
               addr = &nh->daddr;
               inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
                                *addr, mtime, 1);
               csum_replace4(&nh->check, *addr, mtime);
               skb_clear_hash(skb);
               *addr = mtime;
          }
```

#### test_delay_v1.3.py

> Test delay for topology depends on OpenFlow1.3


#### test_delay_v1.0.py

> Test delay for topology depends on OpenFlow1.0
> Use RabbitMQ to receive the message
