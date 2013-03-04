/*
+----------------------------------------------------------------------+
| This is the base class. |
| 
| It implements the common properties of all generals, |
| regardless of its role as Commander or Lieutenant.
+----------------------------------------------------------------------+
*/

#include "General.h"

using namespace std;

// Constructor to initialize variables, start listening for incoming connections
// and load the private key.
General::General(GeneralInfo *generalInfo) throw(string) {
    this->myId = generalInfo->myId;
    this->maxFailures = generalInfo->maxFailures;
    this->numGenerals = generalInfo->numGenerals;
    this->cryptoOff = generalInfo->cryptoOff;
    this->listenPort = generalInfo->port;
    this->hostNames = generalInfo->hostNames;
    this->ipToId = generalInfo->ipToId;
    
    this->sendQueue = new int[this->numGenerals];
    this->round = 1;
    this->numMsgsSent = 0;
    this->listenSocketFD = -1;

    startListening();
    if(this->listenSocketFD == -1) {
        throw string("\nDon't have a socket to listen. Hence can not receive messages.");
    }

    memset(this->sendQueue, NOP_SEND_STATUS, sizeof(int) * this->numGenerals);
    loadPrivateKey();
}

// Destructor to deallocate memory, close the socket opened for incoming connection
// and release the loaded private key.
General::~General() {
    if(this->sendQueue) {
        delete[] this->sendQueue;
    }
    close(this->listenSocketFD);
    EVP_PKEY_free(this->pvtKey);
}

// Reads and loads the private key of the general.
void General::loadPrivateKey() throw(string) {
    ERR_load_crypto_strings();

    // Open the file containing the private key.
    string keyFile = "generals/host_" + intToString(this->myId) + "_key.pem";
    FILE *fp = fopen(keyFile.c_str(), "r");
    if(fp == NULL) {
        throw string("\nCould not open private key file");
    }

    // Read the private key.
    this->pvtKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose (fp);
    
    if(this->pvtKey == NULL) {
        ERR_print_errors_fp (stderr);
        throw string("\nPrivate key is NULL.");
    }
}

// Opens a port and starts listening for incoming connections.
void General::startListening() throw(string) {
    int socketFD, status;
    struct addrinfo hints, *hostInfo, *curr;

    // Initialize the socket properties.
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    // Prepare the structure with the port number and socket properties initialized above.
    if((status = getaddrinfo(NULL, this->listenPort.c_str(), &hints, &hostInfo)) != 0) {
        cerr<<"getaddrinfo: "<<gai_strerror(status);
        throw string("\nCould not retrieve my address info.");
    }

    // Get the socket descriptor to use for listening.
    for(curr = hostInfo; curr != NULL; curr = curr->ai_next) {
        // Create the socket.
        if((socketFD = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol)) == -1) {
            perror("Failed to create a socket for myself to listen on: socket() failed.");
            continue;
        }
        
        // Set the socket options.
        int yes = 1;
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        // Bind the socket to the port to listen on.
        if(bind(socketFD, curr->ai_addr, curr->ai_addrlen) == -1) {
            close(socketFD);
            perror("Failed to bind the socket for myself to listen on: bind() failed.");
            continue;
        }

        break;
    }
    
    if(curr == NULL) {
        throw string("\nFailed to create or bind any socket to listen on.");
    }

    freeaddrinfo(hostInfo);
    this->listenSocketFD = socketFD; // Remember the socket file descriptor.
}

// Digitally signs the message to be sent.
struct sig* General::signMessage(void *data, int dataLen) {
    ERR_load_crypto_strings();

    EVP_MD_CTX md_ctx;
    unsigned int sig_len = SIG_SIZE;
    struct sig *sign = new sig;
    sign->id = this->myId;

    // Do the signature
    EVP_SignInit(&md_ctx, EVP_sha1());
    EVP_SignUpdate (&md_ctx, data, dataLen);
    int err = EVP_SignFinal(&md_ctx, sign->signature, &sig_len, this->pvtKey);

    if(err != 1) {
        ERR_print_errors_fp(stderr);
        throw string("\nSigning failed.");
    }

    this->state = SIGNED;
    return sign;
}

// Sends an order to generals.
void General::sendOrder(SignedMessage *message) throw(string) {
    // Depending on the state in which a general is, the order is sent to desired generals.
    switch(this->state) {
        // Send to generals whose signatures were not found in the signature chain.
        case SIGNED:
        case SENDING:
            for(int i = 1; i < this->numGenerals; i++) {
                if(this->sendQueue[i] != DO_NOT_SEND && (i + 1) != myId) {
                    sendMessage(message, i);
                }
            }
            break;

        // Send to generals to whom order could not be sent earlier.
        case ALL_NOT_SENT:
            for(int i = 1; i < this->numGenerals; i++) {
                if(this->sendQueue[i] == NOT_SENT && (i + 1) != myId) {
                    sendMessage(message, i);
                }
            }
            break;

        // Send to generals from whom an ACK has not been received within timeout period.
        case ALL_ACKS_NOT_RECEIVED:
            for(int i = 1; i < this->numGenerals; i++) {
                if(this->sendQueue[i] != ACKED && this->sendQueue[i] != DO_NOT_SEND && this->sendQueue[i] != NOP_SEND_STATUS && (i + 1) != myId) {
                    sendMessage(message, i);
                }
            }
            break;
    }
}

// Sends a message to a general given his id.
void General::sendMessage(SignedMessage *message, int generalK) throw(string) {
    int socketFD, status, numbytes;
    struct addrinfo hint, *hostInfo, *curr;
    string general = this->hostNames[generalK];

    // Set the appropriate flags.
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_flags = AI_PASSIVE;

    // Get the address info of the host to send to.
    if((status = getaddrinfo(general.c_str(), this->listenPort.c_str(), &hint, &hostInfo)) != 0) {
        cerr<<"getaddrinfo: "<<gai_strerror(status);
        throw general.append(" :could not retrieve the address info.");
    }

    // Get the socket descriptor to use for sending the message.
    for(curr = hostInfo; curr != NULL; curr = curr->ai_next) {
        if((socketFD = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol)) == -1) {
            perror("Failed to create a socket: socket() failed.");
            continue;
        }
        break;
    }

    // Socket creation failed for all options.
    if(curr == NULL) {
        cerr<<"\nFailed to create any socket for "<<general;
        this->sendQueue[generalK] = NOT_SENT;
        return;
    }

    freeaddrinfo(hostInfo);

    // Try sending the message to the general.
    int msgLen = sizeof(SignedMessage) + sizeof(struct sig) * this->round;
    if((numbytes = sendto(socketFD, (void *) message, msgLen, 0, curr->ai_addr, curr->ai_addrlen)) == -1) {
        cerr<<"Failed to send message to "<<general;
        perror("Failed to send message: sendto() failed");
        this->sendQueue[generalK] = NOT_SENT;
    } else {
        // Update the status of the sending and increment the number of messages that have been sent.
        this->sendQueue[generalK] = SENT;
        this->numMsgsSent++;
    }
    close(socketFD);
}

// Converts a SignedMessage from host to network byte order.
SignedMessage* General::hton_sm(SignedMessage *msg) {
    uint32_t numSigs = msg->total_sigs;
    msg->type = htonl(msg->type);
    msg->total_sigs = htonl(msg->total_sigs);
    msg->order = htonl(msg->order);
    for(int i = 0; i < numSigs; i++) {
        msg->sigs[i].id = htonl(msg->sigs[i].id);
    }
    return msg;
}

// Converts a SignedMessage from network to host byte order.
SignedMessage* General::ntoh_sm(SignedMessage *msg, ssize_t numBytesReceived) {
    uint32_t numSigs = (numBytesReceived - sizeof(SignedMessage)) / sizeof(struct sig);
    msg->type = ntohl(msg->type);
    msg->total_sigs = ntohl(msg->total_sigs);
    msg->order = ntohl(msg->order);
    for(int i = 0; i < numSigs; i++) {
        msg->sigs[i].id = ntohl(msg->sigs[i].id);
    }
    return msg;
}

// Converts an Ack from host to network byte order.
Ack* General::hton_ack(Ack *msg) {
    msg->type = htonl(msg->type);
    msg->round = htonl(msg->round);
    return msg;
}

// Converts an Ack from network to host byte order.
Ack* General::ntoh_ack(Ack *msg) {
    msg->type = ntohl(msg->type);
    msg->round = ntohl(msg->round);
    return msg;
}

// Converts an integer to its string equivalent.
string General::intToString(int integer) {
    stringstream strStream;
    strStream << integer;
    return strStream.str();
}
