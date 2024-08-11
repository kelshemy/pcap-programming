import dpkt
from dpkt.tcp import TH_FIN, TH_ACK, TH_SYN, parse_opts

fileName = open('assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(fileName)

flowMap = {}
counter = 0

def parseIP(bytes):
    ip = ""
    for byte in bytes:
        ip += str(int(byte)) + "."
    return ip[:len(ip)-1]

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    flags = tcp.flags
    opts = parse_opts(tcp.opts)
    scale = 0
    flowTuple = (parseIP(ip.src), tcp.sport, parseIP(ip.dst), tcp.dport)
    receiverTuple = (parseIP(ip.dst) , tcp.dport, parseIP(ip.src), tcp.sport)
    for opNumber, opt in opts:
        if opNumber == 3:
            scale = int(opt[0])
            break
            # actual window size is tcp.win * (2**scale)
    if flowTuple in flowMap:
        flowMap[flowTuple].append((tcp, True, scale, ts))
    elif receiverTuple in flowMap:
        flowMap[receiverTuple].append((tcp, False, scale, ts))
    else:
        flowMap[flowTuple] = [(tcp, True, scale, ts)]

print('The format of the tuple is (source ip, source port, destination ip, destination port).')
flow = 0
for flowTuple, packets in flowMap.items():
    flow += 1
    print('-----------------------------------')
    print('Flow ', flow)
    print('-----------------------------------')
    print(flowTuple)
    handshakeFinished = False
    printedPackets = 0
    scale = packets[0][2]
    end = 0
    totalData = 0
    oneRTT = 0

    printTS = packets[3][3] - packets[0][3] + 0.00145
    cwndsPrinted = 0 
    cwnd = 0
    outgoingSize = 0

    sequenceNumbers = set()
    ackCounts = {}

    numberOfTripleDuplicate = 0
    numberOfTimeout = 0
    for tcp, outgoing, _, ts in packets:
        if outgoing and tcp.flags & TH_ACK > 0 and not handshakeFinished:
            if len(tcp.data) > 0 and printedPackets < 2:
                # piggybacked packet
                printedPackets += 1
            handshakeFinished = True
            oneRTT = ts - packets[0][3]
            continue
        if handshakeFinished and printedPackets < 2:
            print ("{:<25} {:<25} {:<25}".format('SEQUENCE NUMBER', 'ACKNOWLEDGEMENT NUMBER', 'RECEIVE WINDOW SIZE'))
            print ("{:<25} {:<25} {:<25}".format(tcp.seq, tcp.ack, tcp.win * 2 ** scale))
            printedPackets += 1 

        currentSeq = tcp.seq

        if ts - packets[0][3] > printTS and cwndsPrinted < 3:
            cwndsPrinted += 1
            print("CWND: ", cwnd)
            printTS += oneRTT

        if not outgoing and tcp.flags & TH_FIN > 0 and tcp.flags & TH_ACK > 0:
            end = ts

            
        if outgoing:
            totalData += len(tcp)
            outgoingSize = len(tcp)
            cwnd += outgoingSize
            if currentSeq not in sequenceNumbers:
                sequenceNumbers.add(currentSeq)
                ackCounts[currentSeq] = 0
                continue
            elif ackCounts[currentSeq] >= 3:
                numberOfTripleDuplicate += 1
            else:
                numberOfTimeout += 1
        else:
            if tcp.ack in ackCounts:
                ackCounts[tcp.ack] += 1
            else:
                ackCounts[tcp.ack] = 1
            cwnd -= outgoingSize
    print('The number of retransmissions due to triple duplicate ack is: ', numberOfTripleDuplicate)
    print("The number of retransmissions due to timeout is: ", numberOfTimeout)
    print ('The throughput is: ', totalData / (end - packets[0][3]))
    

fileName.close()
