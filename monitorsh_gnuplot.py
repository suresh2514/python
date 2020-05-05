#!/usr/bin/python3.6
import re
import sys
import os
from collections import defaultdict

if len(sys.argv) != 2:
    print("Invalid arguments.....!")
    print("Usage: <cmd> <filename>")
    sys.exit(1)

data_file = sys.argv[1]
data_dict = defaultdict(list)

input_file=open(data_file, 'r')

time = ""
prefix1 = None
for line in input_file:

    prefix2=None

    #if line start with ====, that is our timestamp
    timestamp=re.compile('^===== ....-..-.. (..:..:..).*=====')
    result = re.search(timestamp, line)
    if result:
        time = result.group(1)
        data_dict[time] = {}
        continue

    mykey = re.compile('ICMP input histogram:')
    result = mykey.search(line)
    if result:
        prefix1 = line
        continue

    mykey=re.compile('ICMP output histogram:')
    result=mykey.search(line)
    if result:
        prefix1=line
        continue

    mykey=re.compile('destination unreachable:')
    result=mykey.search(line)
    if result:
        prefix2=prefix1

    mykey=re.compile('echo requests:')
    result=mykey.search(line)
    if result:
        prefix2=prefix1

    mykey=re.compile('echo replies:')
    result=mykey.search(line)
    if result:
        prefix2=prefix1


    # for other lines, split them into 'counter' and 'string'
    p1=re.compile('(.*?)(\d+)$')
    p2=re.compile('^\s+(\d+)( .*$)')
    p3=re.compile('(.*\S+) (\d+) (.*$)')
    result=False

    result=p1.search(line)
    if result:
        if prefix2:
            key=prefix2.rstrip()+"_"+result.group(1)
        else:
            key=result.group(1)

        data_dict[time][key]=result.group(2)
    else:
        result=p2.search(line)
        if result:
            key=result.group(2)
            data_dict[time][key]=result.group(1)
        else:
            result=p3.search(line)
            if result:
                key=result.group(1)+" X "+result.group(3)
                data_dict[time][key]=result.group(2)

# Now we have a dictionary of primary key having all timestamps, and on each key, comma separated list of
# netstat values : counters
# print(data_dict)

data_dir="/tmp/"+data_file+"_data/"

# Now read this dictionary and write to data_dir
if os.path.exists(data_dir):
    try:  
        os.system("rm -rf " + data_dir)
    except OSError as error:  
        print(error)   

os.mkdir(data_dir)  

for key,value in data_dict.items():
    for data,count in value.items():
        filename=data.replace(" ","_")
        filename=re.sub(r'(_)\1+', r'\1',filename)
        filename=re.sub(r'^_', r'',filename)
        f = open(data_dir + filename,"a+")
        f.write(key + " " + count + "\n")


for a in os.listdir(data_dir):
    title=a.replace("_","-")
    f=open(data_dir + a +".plot","a+")
    f.write("unset output\n")
    f.write("set terminal png\n")
    #f.write("set output \"/tmp/netstat_data/"+a+".png\"\n")
    f.write("set output \"" + data_dir + a +".png\"\n")
    f.write("set term png size 1200, 800\n")
    f.write("set origin 0,0\n")
    f.write("set multiplot\n")
    f.write("set size 1,0.4\n")
    f.write("set origin 0,0.6\n")
    f.write("set format x \"%H:%M:%S\"\n")
    f.write("set timefmt \"%H:%M:%S\"\n")
    f.write("set xdata time\n")
    f.write("set grid\n")
    f.write("plot   \""+a+"\" using 1:2 title \""+title+"\" with lines\n")
    f.write("unset multiplot\n")
    f.write("unset output\n")
    f.write("reset\n")


print("Done. Now go to "+data_dir+ " and run command:")
print("for i in $(ls *plot); do gnuplot $i; done")



"""
During issue time, following data shows spike/variation:
bytes_directly_in_process_context_from_backlog

1569 int tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
1570                 size_t len, int nonblock, int flags, int *addr_len)
1571 {
...
1763                 if (user_recv) {               
1764                         int chunk;             
1765        
1766                         /* __ Restore normal policy in scheduler __ */
1767 
1768                         if ((chunk = len - tp->ucopy.len) != 0) {
1769                                 NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);
1770                                 len -= chunk;  
1771                                 copied += chunk;
1772                         }



If the socket is locked by the top-half process, it can’t accept any more segments, so we must put the incoming segment on the backlog queue by calling sk_add_backlog. If the socket is not locked, we try to put the segments on the prequeue. The prequeue is in the user copy structure, ucopy. Ucopy is part of the TCP options structure, Once segments are put on the prequeue, they are processed in the application task’s context rather than in the kernel context. This improves the efficiency of TCP by minimizing context switches between kernel and user. If tcp_prequeue returns zero, it means that there was no current user task associated with the socket, so tcp_v4_do_rcv is called to continue with normal "slow path" receive processing.

￼
1 if (!sock_owned_by_user(sk)) {
2 if (!tcp_prequeue(sk, skb))
3 ret = tcp_v4_do_rcv(sk, skb);
4 } else
5 sk_add_backlog(sk, skb);
6

Now we can unlock the socket by calling bh_unlock_sock instead of unlock_sock, because in this function, we are executing in the "bottom half" context. Sock_put decrements the socket reference count indicating that the sock has been processed.

￼
1 bh_unlock_sock(sk);
2 sock_put(sk);
3 return ret;



This looks like packets were receiving, but was kept in backlog during issue time. When issue got cleared, a spike of data got copied to process.



acknowledgments_not_containing_data_payload_received
active_connections_openings
bad_segments_received.
bytes_directly_received_in_process_context_from_prequeue
congestion_windows_partially_recovered_using_Hoe_heuristic
congestion_windows_recovered_without_slow_start_after_partial_ack
congestion_windows_recovered_without_slow_start_by_DSACK
connection_resets_received
connections_aborted_due_to_timeout
connections_established
connections_reset_due_to_early_user_close
connections_reset_due_to_unexpected_data
delayed_acks_further_delayed_because_of_locked_socket
delayed_acks_sent
Detected_reordering_X_times_using_time_stamp
dropped_because_of_missing_route
DSACKs_for_out_of_order_packets_received
DSACKs_received
echo_request
failed_connection_attempts
fast_retransmits
forwarded
ICMP_input_histogram
ICMP_input_histogram
ICMP_input_histogram
ICMP_messages_failed
ICMP_messages_received
ICMP_messages_sent
ICMP_output_histogram
ICMP_output_histogram
incoming_packets_delivered
incoming_packets_discarded
InECT0Pkts
InNoECTPkts
InNoRoutes
InOctets
input_ICMP_message_failed.
InType0
InType3
InType8
invalid_SYN_cookies_received
other_TCP_timeouts
outgoing_packets_dropped
OutMcastOctets
OutMcastPkts
OutOctets
OutType0
OutType3
OutType8
packet_headers_predicted
packet_receive_errors
packets_directly_queued_to_recvmsg_prequeue.
packets_header_predicted_and_directly_queued_to_user
packets_received
packets_rejects_in_established_connections_because_of_timestamp
packets_sent
packets_to_unknown_port_received.
passive_connection_openings
passive_connections_rejected_because_of_time_stamp
predicted_acknowledgments
Quick_ack_mode_was_activated_X_times
receive_buffer_errors
requests_sent_out
resets_received_for_embryonic_SYN_RECV_sockets
resets_sent
retransmits_in_slow_start
segments_received
segments_retransmited
segments_send_out
send_buffer_errors
SYNs_to_LISTEN_sockets_dropped
TCPAutoCorking
TCPChallengeACK
TCPDSACKIgnoredNoUndo
TCPDSACKIgnoredOld
TCPFromZeroWindowAdv
TCPHystartDelayCwnd
TCPHystartDelayDetect
TCPHystartTrainCwnd
TCPHystartTrainDetect
TCPLossProbeRecovery
TCPLossProbes
TCPLostRetransmit
TCPOFOQueue
TCPOrigDataSent
TCPRcvCoalesce
TCPRetransFail
TCPSackMerged
TCPSackShifted
TCPSackShiftFallback
TCP_sockets_finished_time_wait_in_fast_timer
TCP_sockets_finished_time_wait_in_slow_timer
TCPSpuriousRTOs
TCPSpuriousRtxHostQueues
TCPSYNChallenge
TCPSynRetrans
TCPToZeroWindowAdv
TCPWantZeroWindowAdv
timeouts_in_loss_state
times_receiver_scheduled_too_late_for_direct_processing
times_recovered_from_packet_loss_by_selective_acknowledgements
total_packets_received
"""
