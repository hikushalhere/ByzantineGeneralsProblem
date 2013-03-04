/*
+----------------------------------------------------------------------+
| This is the derived class from class General. |
| It implements the actions of the Commander. |
+----------------------------------------------------------------------+
*/

#include "Commander.h"

using namespace std;

// Constructor to initialize the variables and,
// call the parameterized constructor of the base class.
Commander::Commander(GeneralInfo *generalInfo, uint32_t order) throw(string) : General(generalInfo) {
    this->order = order;
    this->state = INIT;
}

// Implements the pure virtual function of parent class which kicks off the algorithm.
int Commander::run() throw(string) {
    selectValue();
    if(this->state == VALUE_SELECTED) {
        send();
        return this->order;
    } else {
        throw string("\nInvalid order selected by commander. Should be either 0 or 1.");
    }
}

// Selects the value/order to be sent.
void Commander::selectValue() {
    if(this->order == RETREAT || this->order == ATTACK) {
        this->state = VALUE_SELECTED;
    }
}

// Sends the order to all generals.
void Commander::send() throw(string) {
    // Digitally sign the order and obtain the pointer to the signature.
    struct sig *sign = signMessage(&(this->order), sizeof(this->order));
    
    if(this->state == SIGNED) {
        // Prepare the order/message to be sent.
        SignedMessage *message = (SignedMessage *) malloc(sizeof(SignedMessage) + sizeof(struct sig));
        message->type = TYPE_SEND;
        message->total_sigs = this->round;
        message->order = this->order;
        memcpy(message->sigs, sign, sizeof(struct sig));
        message = hton_sm(message);

        if(sign) {
            delete sign;
        }

        long int diff = 0;
        struct timeval start;
        gettimeofday(&start, NULL); // Record the start time.

        // Try sending till message has been sent to all the generals or the round gets over.
        while(this->state != ALL_SENT && diff < ROUND_TIMEOUT) {
            sendOrder(message);
            
            for(int i = 0; i < this->numGenerals; i++) {
                if(this->sendQueue[i] == NOT_SENT) {
                    cerr<<"\nCould not send message to: "<<this->hostNames[i];
                    this->state = ALL_NOT_SENT;

                    break;
                }
            }

            if(this->state == ALL_NOT_SENT) {
                // Record the current time and calculate the difference from the time we started checking for ACKs.
                struct timeval end;
                gettimeofday(&end, NULL);
                diff = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
                continue;
            }

            this->state = ALL_SENT;
        }

        // Wait for ACKs till time out occurs.
        while(this->state != ALL_ACKS_RECEIVED && diff < ROUND_TIMEOUT) {
            waitForAck();

            // Try sending to generals from whom ACK has not been received.
            // If all ACKs have been received none of the cases will be matched in the switch statement in sendOrder().
            sendOrder(message);

            // Record the current time and calculate the difference from the time we started checking for ACKs.
            struct timeval end;
            gettimeofday(&end, NULL);
            diff = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
        }

        if(message) {
            free(message);
        }
    } else {
        cerr<<"Message could not be signed";
    }
}

// Waits for incoming ACKs.
void Commander::waitForAck() {
    int numbytes, bufferLen = sizeof(Ack);
    long int diff = 0;
    struct timeval start;
    char *buffer = new char[bufferLen];

    // Record the start time.
    gettimeofday(&start, NULL);

    // Loop until all ACKs are recived or timeout period elapses.
    while(this->state != ALL_ACKS_RECEIVED && diff < ACK_TIMEOUT) {
        struct sockaddr_in peerAddress;
        socklen_t addrLen = sizeof(peerAddress);

        // Receive data from the socket.
        if((numbytes = recvfrom(this->listenSocketFD, buffer, bufferLen, MSG_DONTWAIT, (struct sockaddr *) &peerAddress, &addrLen)) == -1) {
            if(errno != EWOULDBLOCK) {
                perror("Failed to receive a message: recvfrom() failed");
            }

            // Record the current time and calculate the difference from the time we started checking for ACKs.
            struct timeval end;
            gettimeofday(&end, NULL);
            diff = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));

            continue;
        }

        Ack *ackData = ntoh_ack((Ack *) buffer); // Recast the bytes read from the socket.

        // Check if it is an expected ACK.
        if(ackData && ackData->type == TYPE_ACK && ackData->round == this->round) {
            this->numMsgsSent--;
            uint32_t peerId = this->ipToId[peerAddress.sin_addr.s_addr];
            this->sendQueue[peerId] = ACKED;
        }

        if(this->numMsgsSent == 0) {
            this->state = ALL_ACKS_RECEIVED;
        }

        // Record the current time and calculate the difference from the time we started checking for ACKs.
        struct timeval end;
        gettimeofday(&end, NULL);
        diff = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
    }

    if(buffer) {
        delete[] buffer;
    }

    if(this->numMsgsSent > 0) {
        this->state = ALL_ACKS_NOT_RECEIVED;
    }
}
