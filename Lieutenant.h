/*
+----------------------------------------------------------------------+
| This is the child class derived from class General. |
| It contains the defintion of class Lieutenant. |
+----------------------------------------------------------------------+
*/

#ifndef LIEUTENANT_H
#define LIEUTENANT_H

#include <set>
#include "General.h"

class Lieutenant : public General {

    private:
        std::set<int> values;                       // The set of values obtained from all generals.
        std::vector<SignedMessage *> msgsToForward; // The list of messages to forward/send to generals.
        std::map<uint32_t, EVP_PKEY *> idToCert;    // Map for General Id : Digital Certificate
        struct timeval start;                       // Stores the start time after sending a message to generals.

        void loadCertificates() throw(std::string);                       // Loads the digital certficates of all generals and stores them.                       
        void receiveAndForward() throw(std::string);                      // It loops over the actions of receiving messages and forwarding messages.
        void receiveMessage();                                            // Received any message that has arrived at the socket.
        void handleAck(Ack *, struct sockaddr_in);                        // Handles an ACK received.
        void handleMessage(SignedMessage *, struct sockaddr_in, ssize_t); // Handles a message received.
        void sendAck(struct sockaddr_in);                                 // Sends an ACK in response to a message received.
        void verifySignatures(uint32_t, uint32_t, struct sig *);          // Verified the digital signature in a message received.
        SignedMessage *constructMessage(SignedMessage *);                 // Constructs a message to be sent.
        long int forwardMessages() throw(std::string);                    // Forwards messages to the generals.
        bool isValueInSet(int);                                           // Check if a value is in the set values.
        int decide();                                                     // Takes a decision based on the values in the set.

    public:
        Lieutenant(GeneralInfo *) throw(std::string); // Constructor to initialize variables, to call parent's parametrized constructor and to load digital certificates of the generals.
        ~Lieutenant();                                // Frees the loaded certificates.
        int run() throw(std::string);                 // Implements the pure virtual function of the parent that kicks off the algorithm.
};

#endif
