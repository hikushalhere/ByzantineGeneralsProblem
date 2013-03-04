/*
+----------------------------------------------------------------------+
| The Byzantine Generals Problem |
+----------------------------------------------------------------------+
| http://research.microsoft.com/en-us/um/people/lamport/pubs/byz.pdf |
| http://en.wikipedia.org/wiki/Byzantine_fault_tolerance |
+----------------------------------------------------------------------+
| This is a solution of the Byzantine Generals Problem, |
| as described in the paper (link given above). |
+----------------------------------------------------------------------+
| This source file is the entry point of the implementation. |
+----------------------------------------------------------------------+
*/

#include <cstring>
#include <fstream>
#include "Commander.h"
#include "Lieutenant.h"

#define NOP 0

#define PORT 1
#define HOSTFILE 2
#define FAULTY 3
#define ORDER 4

#define MIN_PORT_NUM 1024
#define MAX_PORT_NUM 65535

#define RETREAT_STRING "retreat"
#define ATTACK_STRING "attack"

#define HOST_NAME_LEN 256

using namespace std;

General *bootstrap(string, char *, int, bool, uint32_t, uint32_t *); // Bootstraps the application.
void printUsage();                                                   // Prints the usage.

// The show starts here!
int main(int argc, char **argv) {
	int nextArg, maxFailures, portNum;
	uint32_t order;
	char *hostFilePath;
	string port;
	bool proceed = true, cryptoOff = false;

	nextArg = NOP;
	order = NO_ORDER;

    // Parses the command line arguments and reads the values passed.
	for(int i = 1; i < argc && proceed; i++) {
		if(argv[i][0] == '-') {
			if(strlen(argv[i]) != 2) {
				proceed = false;
				continue;
			}
			
			switch(argv[i][1]) {
				case 'p':
					nextArg = PORT;
					break;

				case 'h':
					nextArg = HOSTFILE;
					break;

				case 'f':
					nextArg = FAULTY;
					break;

				case 'c':
					cryptoOff = true;
					break;

				case 'o':
					nextArg = ORDER;
					break;

				default:
					printUsage();
					proceed = false;
			}
		} else {
			switch(nextArg) {
				case PORT:
					port = string(argv[i]);
					portNum = atoi(argv[i]);
					if(portNum < MIN_PORT_NUM || portNum > MAX_PORT_NUM) {
						cerr<<"The port number should lie between 1024 and 65535 including both.";
						proceed = false;
						continue;
					}
					break;

				case HOSTFILE:
					hostFilePath = argv[i];
					break;

				case FAULTY:
					maxFailures = atoi(argv[i]);
					break;

				case ORDER:
					if(strcmp(argv[i], ATTACK_STRING) == 0) {
						order = ATTACK;
					} else if(strcmp(argv[i], RETREAT_STRING) == 0) {
						order = RETREAT;
					} else {
						cout<<"The order must either be 'attack' or 'retreat'.";
						proceed = false;
						continue;
					}
					break;

				case NOP:
					printUsage();
					proceed = false;
					break;
			}
		}
	}

    // All OK. The command line arguments were fine.
	if(proceed) {
		uint32_t myId;
		General *generalObj = bootstrap(port, hostFilePath, maxFailures, cryptoOff, order, &myId);
		if(generalObj) {
			try {
				int decision = generalObj->run();
				if(decision != NO_ORDER) {
					const char *decisionStr = (decision == ATTACK) ? ATTACK_STRING : RETREAT_STRING;
					cout<<"\n"<<myId<<": Agreed on "<<decisionStr;
                    cout.flush();
				}
			} catch(string msg) {
				cerr<<msg;
			}
			delete generalObj;
		}
	}
}

// Prints the usage.
void printUsage() {
	cout<<"Incorrect usage.";
	cout<<"\nUsage: general -p <port number> -h <hostfile> -f <#faulty generals> [-c] [-o <order>]";
    cout<<"\n-c option asks the crypto to be turned off.";
}

// Reads the host file and builds the required data structures.
// Instantiates the appropriate object (Commander or Lieutenant) depending on the role in the system.
General *bootstrap(string port, char *hostFilePath, int maxFailures, bool cryptoOff, uint32_t order, uint32_t *myId) {
	int status, numGenerals = 0;
	uint32_t commanderId;
	char myHostName[HOST_NAME_LEN];
	vector<string> hostNames;
	map<unsigned long, uint32_t> ipToId;
	ifstream hostfile(hostFilePath);
	General *generalObj = NULL;

	*myId = 0;

	if(hostfile.is_open()) {
		if((status = gethostname(myHostName, HOST_NAME_LEN)) != 0) {
			perror("Error encountered in fetching my host name.");
		}
		
        // Read the hostfile and prepare the required data structures related to the hosts (generals).
        while(hostfile.good()) {
			string hostName;
			getline(hostfile, hostName);
			if(!hostName.empty()) {
				numGenerals++;
				hostNames.push_back(hostName);
				struct hostent *host = gethostbyname(hostName.c_str()); // Get the host address from host name.

				if(host != NULL) {
					struct in_addr hostAddress;
					memcpy(&hostAddress, host->h_addr_list[0], sizeof(struct in_addr)); // Extract the IP adress from hostent structure.
					ipToId[hostAddress.s_addr] = numGenerals;                           // IP address : General id.
				}

                // Determine my id number.
				if(strcmp(myHostName, hostName.c_str()) == 0) {
					*myId = numGenerals;
				}
			}
		}
		hostfile.close();
	}
	
	// Check if the total number of generals must be no less than (maxFailures + 2).
	if(numGenerals < maxFailures + 2) {
		cout<<"The total number of generals must be no less than (faulty + 2). Number of generals: "<<numGenerals<<" and number of faulty ones: "<<maxFailures;
	} else if(*myId > 0) {
        // Prepare the object with the required information to be passed to the constructors.
		GeneralInfo *generaInfo = new GeneralInfo;
		generaInfo->myId = *myId;
		generaInfo->port = port;
		generaInfo->maxFailures = maxFailures;
		generaInfo->numGenerals = numGenerals;
		generaInfo->cryptoOff = cryptoOff;
		generaInfo->myHostName = string(myHostName);
		generaInfo->hostNames = hostNames;
		generaInfo->ipToId = ipToId;
		
		try {
			if(order == ATTACK || order == RETREAT) {
				generalObj = new Commander(generaInfo, order); // It's a Commander.
			} else {
				generalObj = new Lieutenant(generaInfo);       // It's a Lieutenant.
			}
		} catch(string msg) {
			cerr<<msg;
		}

		if(generaInfo) {
			delete generaInfo;
		}
	} else {
		cerr<<"My hostname was not found in the file: "<<hostFilePath;
	}

	return generalObj;
}
