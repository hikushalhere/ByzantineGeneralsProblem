/*
+----------------------------------------------------------------------+
| This is the child class derived from class General. |
| It contains the defintion of class Commander. |
+----------------------------------------------------------------------+
*/

#ifndef COMMANDER_H
#define COMMANDER_H

#include "General.h"

// Class definition.
class Commander : public General {

    private:
        uint32_t order; // The order to be sent to toher generals.

        void selectValue();             // Selects the value/order to be sent.
        void send() throw(std::string); // Sends the order to all generals.
        void waitForAck();              // Waits for incoming ACKs.

    public:
        Commander(GeneralInfo *, uint32_t) throw(std::string); // Constructor initializes the variables and calls the parameterized constructor of the base class.
        int run() throw(std::string);                          // Implements the pure virtual function of parent class which kicks off the algorithm.
};

#endif
