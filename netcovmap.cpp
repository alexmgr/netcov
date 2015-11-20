/*
 * File:   rcovtrace.cpp
 * Author: amoneger
 *
 * Created on September 4, 2015, 1:31 PM
 */

/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2010 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>  // mkfifo
#include <sys/stat.h>   // mkfifo
#include <map>
#include <list>
#include <iostream>
#include <utility>
#include <vector>
#include <fstream>
#include <sstream>

#include "pin.H"


#ifdef _WIN32
#define linesep         "\\"
#else
#define linesep         "/"
#endif

// Force each thread's data to be in its own data cache line so that
// multiple threads do not contend for the same data cache line.
// This avoids the false sharing problem.
// See https://software.intel.com/sites/landingpage/pintool/docs/55942/Pin/html/index.html#InscountTLS
#define PADSIZE 56  // 64 byte line size: 64-8
#define PIPE_NAME "/tmp/netcovmap"

#if defined(__APPLE__)
#define APPLE_OFFSET_SYSCALL(SYSCALL) (SYSCALL + 0x2000000)
#define SYS_ACCEPT APPLE_OFFSET_SYSCALL(SYS_accept)
#define SYS_READ APPLE_OFFSET_SYSCALL(SYS_read)
#define SYS_WRITE APPLE_OFFSET_SYSCALL(SYS_write)
#define SYS_CLOSE APPLE_OFFSET_SYSCALL(SYS_close)
#define SYS_RECVFROM APPLE_OFFSET_SYSCALL(SYS_recvfrom)
#define SYS_SENDTO APPLE_OFFSET_SYSCALL(SYS_sendto)
#else
#define SYS_ACCEPT SYS_accept
#define SYS_READ SYS_read
#define SYS_WRITE SYS_write
#define SYS_CLOSE SYS_close
#define SYS_RECVFROM SYS_recvfrom
#define SYS_SENDTO SYS_sendto
#endif


KNOB<std::string> KnobModuleList(KNOB_MODE_APPEND, "pintool", "m", "", "whitelist of module names, use more than once");


size_t traceCount = 0;
static BOOL whitelistMode = false;
std::map<THREADID, struct TraceInfo> threadInfoMap;
std::map<std::string, std::pair<ADDRINT,ADDRINT> > moduleList;
static TLS_KEY tlsKey;
int pipe_fd = -1;


struct BBLEdge {
    ADDRINT parent;
    ADDRINT child;
};

struct TraceInfo {
    ADDRINT prevAddress;
    std::map<std::pair<ADDRINT,ADDRINT>, unsigned int> *coverageMap;
    size_t hitCount;
};

struct ThreadInfo {
    UINT32 hasHitAccept;
    UINT32 fd;
    UINT8 _pad[PADSIZE];
};


UINT32 Usage() {
    std::cout << "CodeCoverage tool for dumping BBL control flows" << std::endl;
    std::cout << KNOB_BASE::StringKnobSummary() << std::endl;
    return 2;
}


static inline size_t getAddressOffset(IMG img, ADDRINT address) {
    return address - IMG_LowAddress(img);
}


static inline string basename(const string &fullpath) {
    ssize_t index = fullpath.rfind(linesep);
    return std::string(fullpath.substr(index + 1));
}


static std::ostringstream* logCallGraph(const THREADID tid,
                                        const std::map<std::pair<ADDRINT,ADDRINT>, unsigned int> *coverageMap) {
    std::map<std::pair<ADDRINT,ADDRINT>, unsigned int>::const_iterator edge;
    std::ostringstream *traceBuffer = new std::ostringstream();
    for (edge = coverageMap->begin(); edge != coverageMap->end(); edge++) {
        if ((edge->first.first != 0) && (edge->first.second != 0)) {
            PIN_LockClient();
            IMG parentImg = IMG_FindByAddress(edge->first.first);
            IMG childImg = IMG_FindByAddress(edge->first.second);
            PIN_UnlockClient();
            std::string parentImgName = basename(IMG_Name(parentImg));
            std::string childImgName = basename(IMG_Name(childImg));
            size_t parentOfset = getAddressOffset(parentImg, edge->first.first);
            size_t childOffset = getAddressOffset(childImg, edge->first.second);
            *traceBuffer << parentImgName << "+" << parentOfset
                         << "->" << childImgName << "+" << childOffset
                         << ":" << edge->second << ";";
        }
    }
    return traceBuffer;
}


static VOID logBasicBlock(THREADID tid, ADDRINT address) {
    // We have a new thread here. Initialize the per thread call graph
    if (threadInfoMap.count(tid) != 0) {
        TraceInfo *traceInfo = &(threadInfoMap[tid]);
        if (traceInfo->prevAddress != 0) {
            (*(traceInfo->coverageMap))[std::make_pair(traceInfo->prevAddress, address)]++;
            traceInfo->prevAddress = address;
            traceInfo->hitCount++;
        } else {
            traceInfo->prevAddress = address;
        }
    }
}


static inline BOOL requiresInstrumentation(ADDRINT address) {
    // Is the current address in a module we are interested in?
    std::map<std::string, std::pair<ADDRINT,ADDRINT> >::iterator module;
    for (module = moduleList.begin(); module != moduleList.end(); module++) {
        if (module->second.first <= address && address <= module->second.second) {
            return TRUE;
        }
    }
    return FALSE;
}


static VOID traceBasicBlocks(TRACE trace, VOID *v) {
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		INS first_ins = BBL_InsHead(bbl);
        INS last_ins = BBL_InsTail(bbl);
        // Follow only conditional branches (CALL, RET, JNE, JZ, ...). Ignore unconditional JMPs
        if (((INS_IsBranch(last_ins) && INS_HasFallThrough(last_ins)) || INS_IsCall(last_ins) || INS_IsRet(last_ins))
                && requiresInstrumentation(INS_Address(first_ins))) {
            INS_InsertCall(first_ins, IPOINT_BEFORE, AFUNPTR(logBasicBlock), IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
        }
	}
}


static VOID traceImageLoad(IMG img, VOID *v) {
    ADDRINT start = IMG_LowAddress(img);
    ADDRINT end = IMG_HighAddress(img);

    std::map<std::string, std::pair<ADDRINT, ADDRINT> >::iterator module;
    const std::string &fullpath = IMG_Name(img);
    std::string imgName = basename(fullpath);

    if (whitelistMode) {
        for (module = moduleList.begin(); module != moduleList.end(); module++) {
            if (module->first == imgName) {
                module->second = std::make_pair(start, end);
            }
        }
    } else {
        moduleList[imgName] = std::make_pair(start,end);
    }
}


static size_t pipeWrite(std::string data) {
    size_t totalWriteLen = 0;
    int writeLen = 0;
    size_t dataLen = data.length();
    while (totalWriteLen < dataLen) {
        writeLen = write(pipe_fd, data.c_str() + totalWriteLen, dataLen - totalWriteLen);
        if (writeLen < 1) {
            break;
        }
        totalWriteLen += (size_t)writeLen;
    }
    return totalWriteLen;
}


static BOOL pipeWriteMessage(std::string msgType, size_t fd, std::string payload) {
    std::ostringstream msgStream;
    // Format is syscall name=trace\n
    msgStream << msgType << ":" << fd << "=";
    size_t msgLen = msgStream.str().length();
    if ((pipeWrite(msgStream.str().c_str()) != msgLen) || (pipeWrite(payload) != payload.length())
        || pipeWrite(std::string("\n")) != 1) {
        return FALSE;
    }
    return TRUE;
}


VOID traceSyscallEntry(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
    ThreadInfo *threadInfo = static_cast<ThreadInfo*>(PIN_GetThreadData(tlsKey, tid));
    ADDRINT syscallId = PIN_GetSyscallNumber(ctx, std);
    ADDRINT fd = PIN_GetSyscallArgument(ctx, std, 0);
    switch (syscallId) {
        case SYS_ACCEPT:
            threadInfo->hasHitAccept = 1;
            break;
        case SYS_RECVFROM:
        case SYS_READ:
            if (threadInfo->fd == fd && threadInfoMap.count(tid) == 0) {
                std::map<std::pair<ADDRINT,ADDRINT>, unsigned int> *coverageMap =
                        new std::map<std::pair<ADDRINT,ADDRINT>, unsigned int>();
                TraceInfo traceInfo = {0, coverageMap, 0};
                threadInfoMap[tid] = traceInfo;
            }
            break;
        case SYS_SENDTO:
        case SYS_WRITE:
            if (threadInfo->fd == fd && threadInfoMap.count(tid) != 0) {
                TraceInfo *traceInfo = &(threadInfoMap[tid]);
                std::ostringstream *traceBuffer = logCallGraph(tid, traceInfo->coverageMap);
                if (!pipeWriteMessage(string("write"), fd, traceBuffer->str())) {
                    std::cerr << "Failed to write trace to pipe" << std::endl;
                }
                delete traceBuffer;
                delete traceInfo->coverageMap;
                threadInfoMap.erase(tid);
            }
            break;
        case SYS_CLOSE:
            if (threadInfo->fd == fd) {
                if (threadInfoMap.count(tid) != 0) {
                    TraceInfo *traceInfo = &(threadInfoMap[tid]);
                    std::ostringstream *traceBuffer = logCallGraph(tid, traceInfo->coverageMap);
                    if (!pipeWriteMessage(std::string("close"), fd, traceBuffer->str())) {
                        std::cerr << "Failed to write trace to pipe" << std::endl;
                    }
                    threadInfo->fd = 0;
                    delete traceBuffer;
                    delete traceInfo->coverageMap;
                    threadInfoMap.erase(tid);
                } else {
                    if (!pipeWriteMessage(std::string("close"), fd, std::string(""))) {
                        std::cerr << "Failed to write trace to pipe" << std::endl;
                    }
                }
            }
            break;
        default:
            break;
    }
}


VOID traceSyscallExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
    ThreadInfo *threadInfo = static_cast<ThreadInfo*>(PIN_GetThreadData(tlsKey, tid));
    if (threadInfo->hasHitAccept == 1) {
        threadInfo->hasHitAccept = 0;
        threadInfo->fd = PIN_GetSyscallReturn(ctx, std);
    }
}


VOID traceThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
    ThreadInfo *threadInfo = new ThreadInfo;
    threadInfo->hasHitAccept = 0;
    PIN_SetThreadData(tlsKey, threadInfo, tid);
}


VOID traceThreadExit(THREADID tid, const CONTEXT *ctx, INT32 flags, VOID *v)
{
    ThreadInfo *threadInfo = static_cast<ThreadInfo*>(PIN_GetThreadData(tlsKey, tid));
    delete threadInfo;
    PIN_SetThreadData(tlsKey, 0, tid);
}


int main(int argc, char **argv) {
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    for (size_t i = 0; i < KnobModuleList.NumberOfValues(); i++) {
        std::string module = std::string(KnobModuleList.Value(i));
        moduleList[module] = std::make_pair(0,0);
        whitelistMode = true;
    }

    // Ignore SIGPIPEs. Just fail on write
    signal(SIGPIPE, SIG_IGN);
    // Create named pipe if it doesn't exist
    struct stat buf;
    if (stat(PIPE_NAME, &buf) != 0) {
        if (mkfifo(PIPE_NAME, S_IREAD|S_IWRITE|S_IRGRP) != 0) {
            std::cerr << "Failed to create named pipe at " << PIPE_NAME << ": " << strerror(errno) << std::endl;
            exit(1);
        }
    }
    std::cerr << "Opening named pipe " << PIPE_NAME << ". Halting until other end opened for read" << std::endl;
    if ((pipe_fd = open(PIPE_NAME, O_WRONLY)) < 0) {
        std::cerr << "Failed to open named pipe at " << PIPE_NAME << ": " << strerror(errno) << std::endl;
        exit(1);
    }

    tlsKey = PIN_CreateThreadDataKey(NULL);
    PIN_AddThreadStartFunction(traceThreadStart, 0);
    PIN_AddThreadFiniFunction(traceThreadExit, 0);

    PIN_AddSyscallEntryFunction(traceSyscallEntry, 0);
    PIN_AddSyscallExitFunction(traceSyscallExit, 0);

    TRACE_AddInstrumentFunction(traceBasicBlocks, 0);
    IMG_AddInstrumentFunction(traceImageLoad, 0);

    PIN_StartProgram();

    return 0;
}


