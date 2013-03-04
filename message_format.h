/*
+----------------------------------------------------------------------+
| This header file contains the definition of the message formats. |
+----------------------------------------------------------------------+
*/

#ifndef MSG_FORMAT_H
#define MSG_FORMAT_H

#include <stdint.h>

struct sig {
    uint32_t id;            // The identifier of the signer.
    uint8_t signature[256]; // Since we are using 2048 bits RSA private key.
};

typedef struct {
    uint32_t type;       // Must be equal to 1.
    uint32_t total_sigs; // Total number of signatures on the message (also indicates the round number).
    uint32_t order;      // The order (retreat = 0 and attack = 1).
    struct sig sigs[];   // Contains total_sigs signatures.
} SignedMessage;

typedef struct {
    uint32_t type;  // Must be equal to 2.
    uint32_t round; // Round number.
} Ack;

#endif
