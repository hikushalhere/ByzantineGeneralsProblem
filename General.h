/*
+----------------------------------------------------------------------+
| This is the base class. It contains the defintion of class General. |
+----------------------------------------------------------------------+
*/

#ifndef GENERAL_H
#define GENERAL_H

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "message_format.h"

#define ACK_TIMEOUT 200000   // in microseconds
#define ROUND_TIMEOUT 500000 // in microseconds
#define MAX_TRIES 10

#define TYPE_SEND 1
#define TYPE_ACK 2

#define NOP_SEND_STATUS 0
#define SENT 1
#define NOT_SENT 2
#define ACKED 3
#define DO_NOT_SEND 4

#define RETREAT 0
#define ATTACK 1
#define NO_ORDER 2

#define INIT 1
#define WAITING 2
#define SIGNATURE_VERIFIED 3
#define VALUE_INCLUDED 4
#define VALUE_SELECTED 5
#define SIGNED 6
#define ALL_NOT_SENT 7
#define ALL_SENT 8
#define ALL_ACKS_RECEIVED 9
#define ALL_ACKS_NOT_RECEIVED 10
#define SENDING 11
#define ACK_RECEIVED 12
#define MSG_RECEIVED 13
#define ACK_VERIFIED 14
#define DONE 15

#define SIG_SIZE 256 /* For 2048 bit RSA private key */

// Data structure to pass information about a general (Commander or Leiutenant).
typedef struct {
    uint32_t myId;
    int maxFailures;
    int numGenerals;
    bool cryptoOff;
    std::string port;
    std::string myHostName;
    std::vector<std::string> hostNames;
    std::map<unsigned long, uint32_t> ipToId;
} GeneralInfo;

// Class definition.
class General {

    protected:
        uint32_t myId;      // General's id.
        int *sendQueue;     // Maintains the send status of the messages.
        int round;          // Current round number. The first round starts from 1.
        int numGenerals;    // Number of generals in the system.
        int maxFailures;    // Maximum number of traitor generals in the system.
        int numMsgsSent;    // The number of generals who have been sent messages.
        int state;          // State of this general.
        int listenSocketFD; // File descriptor of the socket on which the general is listening on.

        std::string listenPort;                   // Port to listen on.
        std::vector<std::string> hostNames;       // Vector of host names in the system.
        std::map<unsigned long, uint32_t> ipToId; // Map for IP address : General id.

        bool cryptoOff;   // Should signature verification be turned off?
        EVP_PKEY *pvtKey; // Stores the private key of the general. 

        void loadPrivateKey() throw(std::string);                  // Reads and loads the private key of the general.
        void startListening() throw(std::string);                  // Opens a port and starts listening for incoming connections.
        void sendOrder(SignedMessage *) throw(std::string);        // Sends an order to generals.
        struct sig* signMessage(void *, int);                      // Digitally signs the message to be sent.
        void sendMessage(SignedMessage *, int) throw(std::string); // Sends a message to a general given his id.
        std::string intToString(int);                              // Converts an integer to its string equivalent.
        SignedMessage* hton_sm(SignedMessage *);                   // Converts a SignedMessage from host to network byte order.
        SignedMessage* ntoh_sm(SignedMessage *, ssize_t);          // Converts a SignedMessage from network to host byte order.
        Ack* hton_ack(Ack *);                                      // Converts an Ack from host to network byte order.
        Ack* ntoh_ack(Ack *);                                      // Converts an Ack from network to host byte order.

    public:
        General(GeneralInfo *) throw(std::string); // Constructor to initialize variables, start listening for incoming connections and load the private key.
        ~General();                                // Destructor to deallocate memory, close the socket opened for incoming connection and release the loaded private key.
        virtual int run() throw(std::string) = 0;  // Pure virtual function that should be implented in the child classes.
};

#endif
