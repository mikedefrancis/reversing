/*
Copyright (c) 2012, Broadcom Europe Ltd
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Classic Hello World

#include <unistd.h>

#include <stdio.h>

#include <stdlib.h>

#include <signal.h>

#include <dlfcn.h>

#include <signal.h>

 

void signal_callback_handler(int signum)

{

   printf("Caught signal %d. Exiting \n",signum);

   // Cleanup and close up stuff here

 

   // Terminate program

   exit(signum);

}

 

void set_signal_handlers()

{

   // Register signal and signal handler

   signal(SIGFPE, signal_callback_handler); //floating point exception.

   signal(SIGSEGV, signal_callback_handler); //Operating system sends a program this signal when it tries to access memory that does not belong to it;

   signal(SIGBUS, signal_callback_handler);  //Indicates an access to an invalid address

   signal(SIGILL, signal_callback_handler); //legal Instruction (ANSI)  executable file is corrupted or use of data where a pointer to a function was expected;

   signal(SIGSYS, signal_callback_handler); //bad system call

   signal(/*SIGSTKFLT*/16, signal_callback_handler); //stack fault

   return;
}

int main(void)
{
    set_signal_handlers();
    printf("Hello world from MPD @ IAI!\n");
   return 0;
}
