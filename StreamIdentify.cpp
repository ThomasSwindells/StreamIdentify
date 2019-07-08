//============================================================================
// Name        : StreamIdentify.cpp
// Author      : Thomas Swindells
// Version     :
// Copyright   : (C) Thomas Swindells
// Description : Prototype to identify ABR traffic in encrypted streams
//============================================================================

#include <iostream>
using namespace std;
#include <deque>
#include <map>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

enum Flow {silence, request, response};

class FlowRecord {
	public:	
		Flow flow;
		long bytes;
		//start time
		//end time	

		FlowRecord (Flow f, long b) : flow(f), bytes(b) {
		};
		void addData(long newBytes) { bytes += newBytes; };
};

class ConnectionRecord {
	public:
		deque<FlowRecord> flows;
		int packets;
		ConnectionRecord() {
		}
};

class Data {
	public: 
		 map<string, ConnectionRecord > connections;
	
};

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void dump(Data &data);

int main(int argc, const char* argv[]) {
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	Data data;

	if(argc < 2) {
		cout << "Missing filename" << endl;
	  return 2;
	}

	// open capture file for offline processing
	descr = pcap_open_offline(argv[1], errbuf);
	if (descr == NULL) {
			cout << "pcap_open_live() failed: " << errbuf << endl;
			return 1;
	}

	// start packet processing loop, just like live capture
	if (pcap_loop(descr, 0, packetHandler, (u_char *) &data) < 0) {
			cout << "pcap_loop() failed: " << pcap_geterr(descr);
			return 1;
	}

	cout << "capture finished" << endl;
	dump(data);
	return 0;
}

string makeKey(char *sourceIp, u_int sourcePort, char *destIp, u_int destPort) {
	string retVal;
	//Typically initiator will be communicating with ephemeral whist the target will be in the system (or at least user) ports
	//Ordering by port number is a good way to get a stable key for the connection most likely starting with the initiator
	if(destPort <= sourcePort) {
		retVal = string(sourceIp) + ":"+to_string(sourcePort)+"-"+string(destIp)+":"+to_string(destPort);
	} else {
		retVal = string(destIp)+":"+to_string(destPort) + "-" + string(sourceIp) + ":"+to_string(sourcePort);
	}

	return retVal;
}

void packetHandler(u_char  *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
	int dataLength = 0;
	string dataStr = "";
	string key;
	Flow flow; 
	Data *data = (Data* )userData;


	ethernetHeader = (struct ether_header*)packet;
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

		if (ipHeader->ip_p == IPPROTO_TCP) {
			tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			sourcePort = ntohs(tcpHeader->source);
			destPort = ntohs(tcpHeader->dest);
			dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			
			//we don't care about 0 byte packets - they are acks (or similar) and not true communication
			if(dataLength > 0) { 
				if(destPort < sourcePort) {
					flow = request;
				} else {
					flow = response;
				}
			
			
				key = makeKey(sourceIp, sourcePort, destIp, destPort);
				ConnectionRecord &cr = data->connections[key];
				
				
				if (  cr.flows.empty()) {
					cr.flows.push_back(FlowRecord(flow, dataLength));
				} else if (cr.flows.back().flow == flow) {
					cr.flows.back().addData(dataLength);
				} else {
					cr.flows.push_back(FlowRecord(flow, dataLength));
				}  
			}
		}
	}
}

void dump( Data &data) {
	for(const auto &c : data.connections) {
		cout << "Dumping connection " << c.first << endl;
		for(const auto &flowRecord :  c.second.flows) {
			switch(flowRecord.flow) {
				case silence: cout << "silence"; break;
				case request: cout << "request"; break;
				case response: cout << "response"; break;
				default: cout << "unknown";
			}
			cout << " " << flowRecord.bytes << endl;

		}

	}

}
