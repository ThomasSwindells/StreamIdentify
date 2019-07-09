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

enum class Flow {serverSilence, clientSilence, request, response, COUNT};
class Data;

class Config {
	public:
		bool dumpFlows = false;
		bool showAll = false;
		bool showConSummary = false;
		double minSilencePeriod = 0.050;
		double trivialDuration = 3;
		long trivialResponseBytes=10000;
		double longDuration = 20; 

		double interestingKbps = 50;
		bool showClassifyDetails = false;
};

class FlowRecord {
	public:	
		Flow flow;
		long bytes;
		double start;
		double end;
		long packets;

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
	   string classification;
		string classificationDetail;

		void packet(Config &config, Flow f, long bytes, double timestamp);
		void dump(Config &config) ;
		double duration() const { return end-start;} 
		double kbps() const { return totalBytes*8/duration()/1024;}
		void classify(Config &config);
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
		void dump() ;
		void classify();
		Config config;
};


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

double toDouble(const struct timeval val) {
	return (double)val.tv_sec + (double)val.tv_usec / 1000000.0;
}
 
int main(int argc, char* argv[]) {
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	Data data;
	string filename;


	cxxopts::Options options(argv[0], "Attempts to identify usage of tcp streams in a capture");
	options
		.add_options()
		("f,file", "Filename to process", cxxopts::value<std::string>())
		("showFlows", "Show flows", cxxopts::value<bool>(data.config.dumpFlows))
		("showAll", "Show all connections, otherwise only show possible streams", cxxopts::value<bool>(data.config.showAll))
		("showConSummary", "Show connection summary", cxxopts::value<bool>(data.config.showConSummary))
		("showClassifyDetails", "Shows details during classify step", cxxopts::value<bool>(data.config.showClassifyDetails))
		("minSilencePeriod", "Minimum silence period", cxxopts::value<double>(data.config.minSilencePeriod))
		("trivialDuration", "Minimum connection duration to consider interesting", cxxopts::value<double>(data.config.trivialDuration))
		("trivialResponseBytes", "Minimum response bytes consider interesting", cxxopts::value<long>(data.config.trivialResponseBytes))
		("longDuration", "Minimum connection duration to consider as a candidate for being an ABR stream", cxxopts::value<double>(data.config.longDuration))
		("interestingKbps", "Minimum kbps to consider as a candidate for being an ABR stream", cxxopts::value<double>(data.config.trivialDuration))

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
	data.classify();
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

string toString(Flow flow) {
	string retVal;
	switch(flow) {
		case Flow::serverSilence: retVal = "serverSilence"; break;
		case Flow::clientSilence: retVal = "clientSilence"; break;
		case Flow::request: retVal = "request"; break;
		case Flow::response: retVal = "response"; break;
		default: retVal = "unknown ";
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
					flow = Flow::request;
				} else {
					flow = Flow::response;
				}
			
			
				key = makeKey(sourceIp, sourcePort, destIp, destPort);
				ConnectionRecord &cr = data->connections[key];
				cr.packet(data->config, flow, dataLength, timestamp);
			}
		}
	}
}

void Data::dump() {
	cout.precision(numeric_limits< double >::max_digits10);
	for(auto &c : connections) {
		if(config.showAll || c.second.classification == "Possible stream") {
			cout << endl << "connection " << c.first << endl;
			cout << c.second.classification << ": " << c.second.classificationDetail << endl;
			c.second.dump(config);		
		}
	}
}

void Data::classify() {
	for(auto &c : connections) {
		c.second.classify(config);		
	}
}


void ConnectionRecord::dump(Config &config) {

	if(config.showConSummary) {
		cout << "\ttotalBytes\ttotalPackets\tduration\tstart\tend\tkbps" << endl;
		cout << "\t" << totalBytes << "\t" << totalPackets << "\t" << duration() << "\t" << start << "\t" << end << "\t" << kbps() << endl;
	}

	cout << endl;
	if(config.dumpFlows) {
		cout << "flow\tbytes\tpackets\tduration\tstart\tend\tkbps" << endl;
		string flowType;
		for(const auto &flowRecord :  flows) {
			flowType = toString(flowRecord.flow);
			cout << flowType << "\t" << flowRecord.bytes << "\t" << flowRecord.packets << "\t" << flowRecord.duration() << "\t" << flowRecord.start << "\t" << flowRecord.end << "\t" <<  flowRecord.kbps()<< endl;
		}
	}
}

/** Key logic to classify different connections based on their properties*/
void ConnectionRecord::classify(Config &config) {
	//Some very simple data extractoin.
	//more advanced stats method, particularly quartiles, standard deviations etc would allow more sophisticated techniques
	//machine learning approaches could also be interesting and fit well.
	const int numFTypes = (int)Flow::COUNT;
	const int req = (int)Flow::request;
	const int resp = (int)Flow::response;
	const int cliSi = (int)Flow::clientSilence;
	long count[numFTypes]= {};
	long gapAccum[numFTypes] = {};
	long bytes[numFTypes] = {};
	double dur[numFTypes] = {};
	double lastEnd[numFTypes] = {};


	for(const auto &flowRecord : flows) {
		int flowType = (int)flowRecord.flow;
		count[flowType] ++;
		if(lastEnd[flowType] != 0) {
			gapAccum[flowType] += flowRecord.end-lastEnd[flowType];
		}
		lastEnd[flowType] = flowRecord.end;
		dur[flowType] += flowRecord.duration();
		bytes[flowType] += flowRecord.bytes;
	}

	if(config.showClassifyDetails) {
		cout << "req count" + to_string(count[req]) + " bytes " + to_string(bytes[req]) + " dur " + to_string(dur[req]) << endl;
		cout << "resp count" + to_string(count[resp]) + " bytes " + to_string(bytes[resp]) + " dur " + to_string(dur[resp]) << endl;
		cout << "cliSi count" + to_string(count[cliSi]) + " bytes " + to_string(bytes[cliSi]) + " dur " + to_string(dur[cliSi]) << endl;
	}

	//now demonstrate different classifications
	if(count[req] == 0 && count[resp] == 0) {
		classification = "Single Request/Response";
		classificationDetail = "Request " + to_string(bytes[req]) + " bytes in " + to_string(dur[req]) + "s / Response " + to_string(bytes[resp]) + " bytes in " + to_string(dur[resp]);
	} else if (bytes[resp] < config.trivialResponseBytes || duration() < config.trivialDuration) {
		classification = "Trivial";
		classificationDetail = "Response " + to_string(bytes[resp]) + " bytes total exchange duration  " + to_string(duration());
	} else if (duration() > config.longDuration && kbps() > config.interestingKbps) {
		classification = "Possible stream";
		classificationDetail = "Request " + to_string(bytes[req]) + " bytes in " + to_string(dur[req]) + "s / Response " + to_string(bytes[resp]) + " bytes in " + to_string(dur[resp]) + "\n";
		classificationDetail += " Total client silence " + to_string(dur[cliSi]) + " average client silence interval " + to_string((double)gapAccum[cliSi]/(count[cliSi]-1)) + "\n";
		classificationDetail += " Request actual bitrate " + to_string(bytes[req]/dur[req]*8/1024) + "kbps, nominal bitrate " + to_string(bytes[req]/duration()*8/1024) + "kbps.\n";
		classificationDetail += " Response actual bitrate " + to_string(bytes[resp]/dur[resp]*8/1024) + "kbps, nominal bitrate " + to_string(bytes[resp]/duration()*8/1024) + "kbps.\n";
	} else {
		
		classification = "Unknown";
		classificationDetail = "Request " + to_string(bytes[req]) + " bytes in " + to_string(dur[req]) + "s / Response " + to_string(bytes[resp]) + " bytes in " + to_string(dur[resp]);
	}
}

void ConnectionRecord::packet(Config &config, Flow flow, long dataLength, double timestamp) {
	if ( flows.empty()) {
		start = timestamp;
		flows.push_back(FlowRecord(flow, dataLength, timestamp));
	} else if (flows.back().flow == flow) {
		flows.back().addData(dataLength, timestamp);
	} else {
		if(timestamp - end > config.minSilencePeriod) { 
			if(flow == Flow::response) {
				//request sent, period waiting and then a response indicates it was the server being slow and silent
				flows.push_back(FlowRecord(Flow::serverSilence, 0, end, timestamp));
			} else {
				//response recieved, period waiting before the next request indicates the client didn't have any important work
				flows.push_back(FlowRecord(Flow::clientSilence, 0, end, timestamp));
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
