/*
+----------------------------------------------------------------------+
| This is the derived class from class General. |
| It implements the actions of the Lieutenant. |
+----------------------------------------------------------------------+
*/

#include "Lieutenant.h"

using namespace std;

// Constructor to initialize variables, call parent's parametrized constructor
// and load digital certificates of the generals.
Lieutenant::Lieutenant(GeneralInfo *generalInfo) throw(string) : General(generalInfo) {
    this->state = INIT;
    loadCertificates();
}

// Frees the loaded certificates.
Lieutenant::~Lieutenant() {
    for(uint32_t id = 1; id <= this->numGenerals; id++) {
        EVP_PKEY_free(this->idToCert[id]);
    }
}

// Loads the digital certficates of all generals and stores them.                       
void Lieutenant::loadCertificates() throw(string) {
    for(uint32_t id = 1; id <= this->numGenerals; id++) {
        if(id != this->myId) {
            // Read the file containig the certificate.
            string certFile = "./generals/host_" + intToString(id) + "_cert.pem";
            FILE *fp = fopen(certFile.c_str(), "r");
            if(fp == NULL) {
                return;
            }

            // Read the certificate.
            X509 *x509 = PEM_read_X509(fp, NULL, NULL, NULL);
            fclose (fp);

            if(x509 == NULL) {
                ERR_print_errors_fp(stderr);
                throw string("\nPublic key for " + intToString(id) + " could not be read.\n");
            }

            // Read the public key.
            EVP_PKEY *pkey = X509_get_pubkey(x509);
            if(pkey == NULL) {
                ERR_print_errors_fp(stderr);
                throw string("\nPublic key for " + intToString(id) + " could not be fetched.\n");
            }

            // Store public key (or digital certificate) in the map.
            this->idToCert[id] = pkey;
        }
    }
}

// Implements the pure virtual function of the parent that kicks off the algorithm.
int Lieutenant::run() throw(string) {
	receiveAndForward();

    int decision = RETREAT;
    if(this->state == DONE) {
	   decision = decide();
    }
    return decision;
}

// It loops over the actions of receiving messages and forwarding messages.
void Lieutenant::receiveAndForward() throw(string) {
	while(this->state != DONE) {
        long int diff = 0;
        gettimeofday(&(this->start), NULL); // Record the start time.
        
        // If this is not the first round.
        if(this->round > 1) { 
            // If the number of rounds != f+1.
            if(this->round <= maxFailures + 1) {
                // Reset the queue to maintain the status of message sending and message counter.
                memset(this->sendQueue, NOP_SEND_STATUS, this->numGenerals);
                this->numMsgsSent = 0;
                
                this->state = SENDING;
                diff = forwardMessages();
            } else {
                this->state = DONE;
                continue;
            }
        }

        while(diff < ROUND_TIMEOUT) {
            this->state = WAITING;

    		receiveMessage();
            if(this->state == ALL_ACKS_NOT_RECEIVED) {
                diff = forwardMessages();
                continue;
            }

            // Record the current time and calculate the difference from the time we started checking for ACKs.
            struct timeval end;
            gettimeofday(&end, NULL);
            diff = ((end.tv_sec * 1000000 + end.tv_usec) - ((this->start).tv_sec * 1000000 + (this->start).tv_usec));
        }

        if(this->round > 1) {
            // Clear the messages of this round.
            for(vector<SignedMessage*>::iterator iter = this->msgsToForward.begin(); iter != this->msgsToForward.end(); iter++) {
                if(*iter) {
                    free(*iter);
                }
            }
            this->msgsToForward.clear();
        }
        this->round++;
	}
}

// Received any message that has arrived at the socket.
void Lieutenant::receiveMessage() {
    int bufferLen, flag;
    long int diff = 0;
    struct timeval ackStart;

    bufferLen = sizeof(SignedMessage) + sizeof(struct sig) * this->numGenerals;
    flag = (this->round == 1) ? 0 : MSG_DONTWAIT; // If this is the first round then make recvfrom() blocking, otherwise non-blocking.

    // Record the start time.
    gettimeofday(&ackStart, NULL);

    while(diff < ACK_TIMEOUT) {
        ssize_t numBytes;
        char *buffer = new char[bufferLen];
        struct sockaddr_in peerAddress;
        socklen_t addrLen = sizeof(peerAddress);

        // Read the bytes from the socket.
        if((numBytes = recvfrom(this->listenSocketFD, buffer, bufferLen, flag, (struct sockaddr *) &peerAddress, &addrLen)) == -1) {
            if(errno != EWOULDBLOCK) {
                perror("Failed to receive a message: recvfrom() failed");
            }
        } else {
            // Determine the type of message and call the appropriate message handler.
            if(numBytes == sizeof(Ack)) {
                this->state = ACK_RECEIVED;

                handleAck(ntoh_ack((Ack *) buffer), peerAddress);
                if(this->state == ACK_VERIFIED) {
                    this->numMsgsSent--;
                }
            } else if(numBytes >= (sizeof(SignedMessage) + sizeof(struct sig))) {
                this->state = MSG_RECEIVED;
                handleMessage(ntoh_sm((SignedMessage *) buffer, numBytes), peerAddress, numBytes);
            }

            if(this->numMsgsSent == 0) {
                this->state = ALL_ACKS_RECEIVED;
            }
        }

        if(buffer) {
            delete[] buffer;
        }

        // Record the current time and calculate the difference from the time we started checking for ACKs.
        struct timeval end;
        gettimeofday(&end, NULL);
        diff = ((end.tv_sec * 1000000 + end.tv_usec) - (ackStart.tv_sec * 1000000 + ackStart.tv_usec));
    }

    if(this->numMsgsSent > 0) {
        this->state = ALL_ACKS_NOT_RECEIVED;
    }
}

// Handles an ACK received.
void Lieutenant::handleAck(Ack *ackData, struct sockaddr_in peerAddress) {
    // Check if it is an expected ACK.
    if(ackData && ackData->type == TYPE_ACK && ackData->round == this->round) {
        uint32_t peerId = this->ipToId[(peerAddress.sin_addr).s_addr];
        this->sendQueue[peerId] = ACKED;
        this->state = ACK_VERIFIED;
    }
}

// Handles a message received.
void Lieutenant::handleMessage(SignedMessage *msgReceived, struct sockaddr_in peerAddress, ssize_t numBytesReceived) {
    sendAck(peerAddress);
    
    // Do some sanity check on the message arrived.
    if(msgReceived && msgReceived->type == TYPE_SEND && (msgReceived->order == RETREAT || msgReceived->order == ATTACK)) {
        uint32_t numSignatures = (numBytesReceived - sizeof(SignedMessage)) / sizeof(struct sig);

        if(numSignatures == msgReceived->total_sigs) {
            // Verifies the signatures in the message.
            verifySignatures(msgReceived->order, numSignatures, msgReceived->sigs);

            // If the signatures are verified and if the value/order is not there in my set of values then include it.
            if(this->state == SIGNATURE_VERIFIED && !isValueInSet(msgReceived->order)) {
                if(msgReceived->total_sigs > this->round) {
                    this->round++; // Catch up if lagging behind.
                }
                this->values.insert(msgReceived->order);
                this->state = VALUE_INCLUDED;
                this->msgsToForward.push_back(constructMessage(msgReceived));
            }
        }
    }
}

// Sends an ACK in response to a message received.
void Lieutenant::sendAck(struct sockaddr_in peerAddress) {
    long int diff = 0;
    
    while(diff < ROUND_TIMEOUT) {
        int socketFD;

        // Prepare a socket to send the ACK.
        if((socketFD = socket(peerAddress.sin_family, SOCK_DGRAM, 0)) == -1) {
            perror("Failed to create a socket: socket() failed.");
            continue;
        }

        int numBytes;
        Ack *ackData = new Ack;
        ackData->type = TYPE_ACK;
        ackData->round = this->round;

        struct sockaddr_in sendtoAddr;
        memset((char *)&sendtoAddr, 0, sizeof(peerAddress));
        string ip = inet_ntoa(peerAddress.sin_addr);
        sendtoAddr.sin_family = AF_INET;
        sendtoAddr.sin_port = htons((unsigned short int) atoi(this->listenPort.c_str()));
        inet_aton(ip.c_str(), &sendtoAddr.sin_addr);

        // Send the ACK prepared above and to the address prepared above.
        if((numBytes = sendto(socketFD, (void *) hton_ack(ackData), sizeof(Ack), 0, (struct sockaddr *) &sendtoAddr, sizeof(sendtoAddr))) == -1) {
            cerr<<"Failed to send ACK to "<<ipToId[(peerAddress.sin_addr).s_addr];
            perror("Failed to send: sendto() failed");

            // Record the current time and calculate the difference from the time we started this round.
            struct timeval end;
            gettimeofday(&end, NULL);
            diff = ((end.tv_sec * 1000000 + end.tv_usec) - ((this->start).tv_sec * 1000000 + (this->start).tv_usec));

            continue;
        }

        close(socketFD);
        if(ackData) {
            delete ackData;
        }
        break;
    }
}

// Verified the digital signature in a message received.
void Lieutenant::verifySignatures(uint32_t order, uint32_t totalSigns, struct sig *signs) {
    if(!this->cryptoOff) {
        for(int i = totalSigns - 1; i >= 0; i--) {
            int dataLen;
            char *data;
            string id = intToString(signs[i].id);

            if(i == 0) {
                data = (char *) &order;
                dataLen = sizeof(order);
            } else {
                data = (char *) signs[i-1].signature;
                dataLen = SIG_SIZE;
            }

            EVP_MD_CTX md_ctx;
            
            // Verify the signature
            EVP_VerifyInit(&md_ctx, EVP_sha1());
            EVP_VerifyUpdate(&md_ctx, data, dataLen);
            int err = EVP_VerifyFinal(&md_ctx, signs[i].signature, SIG_SIZE, this->idToCert[signs[i].id]);

            if(err != 1) {
                ERR_print_errors_fp (stderr);
                return;
            }

            // Update the send status to refelct that this general should not be sent a message.
            this->sendQueue[signs[i].id - 1] = DO_NOT_SEND;
        }
    }
    this->state = SIGNATURE_VERIFIED;
}

// Constructs a message to be sent.
SignedMessage* Lieutenant::constructMessage(SignedMessage *msgReceived) {
    struct sig *sign = signMessage(msgReceived->sigs[this->round - 1].signature, SIG_SIZE);
    SignedMessage *message = (SignedMessage *) malloc(sizeof(SignedMessage) + (sizeof(struct sig) * (this->round + 1)));
    message->type = TYPE_SEND;
    message->total_sigs = this->round + 1;
    message->order = msgReceived->order;
    memcpy(message->sigs, msgReceived->sigs, this->round * sizeof(struct sig)); // Copy the existing signatures.
    memcpy(&(message->sigs[this->round]), sign, sizeof(struct sig));            // Copy the current signature.
    message = hton_sm(message);

    if(sign) {
        delete sign;
    }
    return message;
}

// Forwards messages to the generals.
long int Lieutenant::forwardMessages() throw(string) {
    long int diff = 0;

    // Loop over the mssages to be sent till the round lasts.
    for(vector<SignedMessage*>::iterator iter = this->msgsToForward.begin(); iter != this->msgsToForward.end() && diff < ROUND_TIMEOUT; iter++) {
        // Loop over till all messages are sent to all requried generals or till the round lasts.
        while(this->state != ALL_SENT && diff < ROUND_TIMEOUT) {
            sendOrder(*iter);
            for(int i = 0; i < this->numGenerals; i++) {
                if(this->sendQueue[i] == NOT_SENT) {
                    cerr<<"\nCould not send message to: "<<this->hostNames[i];
                    this->state = ALL_NOT_SENT;
                    break;
                }
            }

            // Record the current time and calculate the difference from the time we started checking for ACKs.
            struct timeval end;
            gettimeofday(&end, NULL);
            diff = ((end.tv_sec * 1000000 + end.tv_usec) - (this->start.tv_sec * 1000000 + this->start.tv_usec));

            if(this->state == ALL_NOT_SENT) {
                continue;
            }

            this->state = ALL_SENT;
        }
    }
    return diff;
}

// Check if a value is in the set values.
bool Lieutenant::isValueInSet(int order) {
	for(set<int>::iterator iter = this->values.begin(); iter != this->values.end(); iter++) {
		if(*iter == order) {
			return true;
		}
	}
	return false;
}

// Takes a decision based on the values in the set.
int Lieutenant::decide() {
	if(this->values.empty() || this->values.size() >= 2) {
		return RETREAT;
	} else {
		set<int>::iterator iter = this->values.begin();
		return *iter;
	}
}
