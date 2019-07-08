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
#include <limits>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "cxxopts.hpp"

using namespace std;

enum Flow {serverSilence, clientSilence, request, response};
class Data;
class FlowRecord {
	public:	
		Flow flow;
		long bytes;
		//start time
		double start;
		double end;
		long packets;
		//end time	

		FlowRecord (Flow f, long b, double timestamp) : flow(f), bytes(b), start(timestamp), end(timestamp), packets(1) {
		};
		
		FlowRecord (Flow f, long b, double startTime, double endTime) : flow(f), bytes(b), start(startTime), end(endTime), packets(0) {
		};
		void addData(long newBytes, double timestamp) { 
			bytes += newBytes; 
			end = timestamp;
			packets++;
		};

		double duration() const { return end-start;} 
		double kbps() const { return bytes*8/duration()/1024;} 

};

class ConnectionRecord {
	public:
		deque<FlowRecord> flows;
		double silenceThreshold = 0.050; //050ms approx
		
		void packet(Flow f, long bytes, double timestamp);
		void dump(const Data *parent) const;
		double duration() const { return end-start;} 
		double kbps() const { return totalBytes*8/duration()/1024;} 
	private:
		double start;
		double end;
		long totalBytes;
		long totalPackets;
};

class Data {
	public: 
		map<string, ConnectionRecord > connections;
		double startTime;
		bool dumpFlows = false;
		void dump() const;
};


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

double toDouble(const struct timeval val) {
	return (double)val.tv_sec + (double)val.tv_usec / 1000000.0;
}
 
int main(int argc, char* argv[]) {
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	Data data;
	bool dumpFlows = false;
	string filename;

	cxxopts::Options options(argv[0], "Attempts to identify usage of tcp streams in a capture");
	
	options
		.add_options()
		("f,file", "Filename to process", cxxopts::value<std::string>())
		("flows", "Dump flows", cxxopts::value<bool>(data.dumpFlows))
		("help", "Print help")
	;

	auto results = options.parse(argc, argv);

	if(results.count("help")) {
		cout << options.help() << endl;
		exit(0);
	}

	if(results.count("file") == 0) {
		cout << "Missing filename" << endl;

		cout << options.help() << endl;
	  	exit(2);
	} else {
		filename = results["file"].as<std::string>();
	}

	// open capture file for offline processing
	descr = pcap_open_offline(filename.c_str(), errbuf);
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
	data.dump();
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
	double timestamp;
	double previousTimestamp;

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
			
			timestamp = toDouble(pkthdr->ts);
			
			if(data->startTime == 0) {
				data->startTime = timestamp;
			}
			timestamp -= data->startTime;
			//we don't care about 0 byte packets - they are acks (or similar) and not true communication
			if(dataLength > 0) { 
				if(destPort < sourcePort) {
					flow = request;
				} else {
					flow = response;
				}
			
			
				key = makeKey(sourceIp, sourcePort, destIp, destPort);
				ConnectionRecord &cr = data->connections[key];
				cr.packet(flow, dataLength, timestamp);
			}
		}
	}
}

void Data::dump() const {
	cout.precision(numeric_limits< double >::max_digits10);
	for(const auto &c : connections) {
		cout << endl << "Dumping connection " << c.first << endl;
		c.second.dump(this);		
	}
}

void ConnectionRecord::dump(const Data *parent) const {
	cout << "\ttotalBytes\ttotalPackets\tduration\tstart\tend\tkbps" << endl;
	cout << "\t" << totalBytes << "\t" << totalPackets << "\t" << duration() << "\t" << start << "\t" << end << "\t" << kbps() << endl;
		
	cout << endl;
	if(parent->dumpFlows) {
		cout << "flow\tbytes\tpackets\tduration\tstart\tend\tkbps" << endl;
		for(const auto &flowRecord :  flows) {
			switch(flowRecord.flow) {
				case serverSilence: cout << "serverSilence "; break;
				case clientSilence: cout << "clientSilence "; break;
				case request: cout << "request "; break;
				case response: cout << "response"; break;
				default: cout << "unknown ";
			}
			cout << "\t" << flowRecord.bytes << "\t" << flowRecord.packets << "\t" << flowRecord.duration() << "\t" << flowRecord.start << "\t" << flowRecord.end << "\t" <<  flowRecord.kbps()<< endl;
		}
	}

}

void ConnectionRecord::packet(Flow flow, long dataLength, double timestamp) {
	if ( flows.empty()) {
		start = timestamp;
		flows.push_back(FlowRecord(flow, dataLength, timestamp));
	} else if (flows.back().flow == flow) {
		flows.back().addData(dataLength, timestamp);
	} else {
		if(timestamp - end > silenceThreshold) { 
			if(flow == response) {
				//request sent, period waiting and then a response indicates it was the server being slow and silent
				flows.push_back(FlowRecord(serverSilence, 0, end, timestamp));
			} else {
				//response recieved, period waiting before the next request indicates the client didn't have any important work
				flows.push_back(FlowRecord(clientSilence, 0, end, timestamp));
			}
		}
		flows.push_back(FlowRecord(flow, dataLength, timestamp));
	} 
	if(timestamp > end) {
		end = timestamp;
	}
	totalBytes += dataLength;
	totalPackets ++;
}
