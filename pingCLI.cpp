#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <sys/types.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <cmath>
#include <vector>
#include <chrono>
#include <csignal>

using namespace std;
using namespace std::chrono;

string ipAddress = "", hostName = "";               // Stores IP Address and hostname for post-ping analysis
int defaultTTL = 64;                                // Default Time To Live in seconds
int defaultInterval = 1;                            // Default interval between pings in seconds
bool isIPv4;                                        // IP version tracker for post-ping analysis
const int rollingAverageItemCount = 100;            // Length of rollingAverage array calculations
double minRTT = defaultTTL * 1.1, maxRTT = 0.0;     // Stores min and max RTT's for post-ping analysis
double rollingAverage[rollingAverageItemCount];     // Stores rollingAverageItemCount RTT's for post-ping analysis
unsigned long long int sent = 0, lost = 0, id = 0;  // Packet counters

void showUsage() {
    cout << "\n";
    cout << string(88, '=');
    cout << "\n\nPing CLI Usage\n\n";
    cout << "g++ -std=c++2a pingCLI.cpp -o pingCLI\n";
    cout << "sudo ./pingCLI [address] [optional flags]\n\n";
    cout << "Note: [address] supports and automatically detects valid IPv4, IPv6, and DNS addresses\n";
    cout << "Note: flags and address are not positional arguments\n\n";
    cout << "Flags: \n\n";
    cout << "-h, --help\t\tDisplay help menu\n";
    cout << "-t, --ttl\t\t(int 0 - 255) Set IP TTL (Time To Live) in seconds; default = " << defaultTTL << "\n";
    cout << "-i, --interval\t\t(int) Set interval in seconds between pings; default = " << defaultInterval << "\n";
    cout << "-p, --packets\t\t(int) Set number of pings; default = ∞\n";
    cout << "-a, --audible\t\tCreates an audible ping\n" << endl;
    exit(0);
}

void postPingStats(int catchCode) {
    int iterLength = min((int)sent, rollingAverageItemCount), index;  // If less than rollingAverageItemCount items have been sent
    // Calculates sum of last rollingAverageItemCount RTT times to calculate standard deviation
    double sum = 0.0, average = 0.0, standardDeviation = 0.0, packetLoss = 0.0;
    // If any packets were sent
    if (iterLength) {
        for (index = 0; index < iterLength; index++) {
            sum += rollingAverage[index];
        }
        average = sum / iterLength * 1.0;
        for (index = 0; index < iterLength; index++) {
            standardDeviation += (rollingAverage[index] - average) * (rollingAverage[index] - average);  // Faster than std::pow()
        }
        packetLoss = (double)lost / (double)id * 100.0;
    }
    // If 0 packets were sent
    else {
        minRTT = 0.0; // Initialized to larger than max value, needs to be reset when no packets are sent
    }
    // Modifies ping text based on IPv4 vs. IPv6
    string pingText = "ping";
    if (!isIPv4) {
        pingText = "ping6";
    }
    // Prints an extra line if KeyboardInterrupt
    if (catchCode == SIGINT) {
        cout << endl;
    }
    printf("\n--- %s %s statistics ---\n", hostName.c_str(), pingText.c_str());
    printf("%llu packets transmitted, %llu packets received, %.2f%% packet loss\n", id, sent, packetLoss);
    printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n\n", minRTT, average, maxRTT, sqrt(standardDeviation / iterLength));
    exit(catchCode);
}

uint16_t calculateCheckSum(uint16_t *addr, unsigned len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *(addr++);
        len -= 2;
    }
    if (len > 0) {
        sum += *(uint8_t *) addr;
    }
    while (sum >> 16u) {
        sum = (sum & 0xffffu) + (sum >> 16u);
    }
    uint16_t answer = ~sum;
    return answer;
}

int ping(int TTL, unsigned int sleepDuration, int packets, bool audible) {
    // If ping is just a test
    bool pingTest = packets == -2;
    // Used for packet sends
    int sock;
    int byteCount = 64;
    // Used for packet receipts
    int packetLength = 200 - ICMP_MINLEN;
    struct sockaddr_in responseSocket{};
    int responseSocketSize = sizeof(sockaddr_in);
    auto *responsePacket = (u_char *)malloc((u_int)packetLength);
    u_char packetHeader[(65536 - 60 - ICMP_MINLEN)];
    // Used to initialize address
    struct sockaddr_in sockAddr{};
    sockAddr.sin_port = 0;
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(ipAddress.c_str());
    // Assigns values based on IPv4 vs. IPv6
    if (isIPv4) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    else {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP);
        sockAddr.sin_family = AF_INET6;
    }
    // Checks if program was run as sudo
    if (sock < 0) {
        cerr << "Ping CLI tool must be run as sudo, aborting now" << endl;
        postPingStats(0);
    }
    // Won't print during ping test
    if (!pingTest) {
        printf("PING %s (%s): 56 data bytes\n", hostName.c_str(), ipAddress.c_str());
    }
    // Specifies socket options
    setsockopt(sock, IPPROTO_IP, IP_TTL, &TTL, sizeof(TTL));
    // Executes until number of desired number of packets is sent
    while (id != packets) {
        struct icmp *headerStruct;
        headerStruct = (struct icmp*) packetHeader;
        headerStruct->icmp_type = ICMP_ECHO;
        headerStruct->icmp_code = 0;
        headerStruct->icmp_cksum = 0;
        headerStruct->icmp_seq = 1;
        headerStruct->icmp_id = id;
        headerStruct->icmp_cksum = calculateCheckSum((unsigned short *)headerStruct, byteCount);
        auto startTime = system_clock::now();  // Starts timer for RTT
        int sendToVal = sendto(sock, (char *)packetHeader, byteCount, 0, (struct sockaddr*)&sockAddr, (socklen_t)sizeof(struct sockaddr_in));
        // Checks if all written characters were sent
        if (sendToVal != byteCount) {
            if (!pingTest) {
                printf("wrote %s %d chars, ret=%d\n", hostName.c_str(), byteCount, sendToVal);
            }
            if (sendToVal < 0) {
                // Failed ping >> invalid IP address
                if (pingTest) {
                    return -1;
                }
                postPingStats(0);
            }
        }
        int response = recvfrom(sock, (char *)responsePacket, packetLength, 0, (struct sockaddr *)&responseSocket, (socklen_t *)&responseSocketSize);
        auto endTime = system_clock::now();
        // Received response message
        if (response >= 0) {
            int responseLen = sizeof(struct ip);
            headerStruct = (struct icmp *)(responsePacket + responseLen);
            // Successful packet receipt
            if (headerStruct->icmp_type == ICMP_ECHOREPLY) {
                if (pingTest) {
                    return 0;
                }
                rollingAverage[sent % 100] =  duration<double>(endTime - startTime).count() * 1000.0;  // Stores rolling average for 100 most recent
                printf("%d bytes from %s: ICMP Sequence = %llu TTL = %d RTT = %.3f ms\n", byteCount, ipAddress.c_str(), id++, TTL, rollingAverage[sent % rollingAverageItemCount]);
                minRTT = min(minRTT, rollingAverage[sent % rollingAverageItemCount]);
                maxRTT = max(maxRTT, rollingAverage[sent++ % rollingAverageItemCount]);
            }
            // Received packet was too short
            else if (response < (responseLen + ICMP_MINLEN)) {
                if (pingTest) {
                    return -1;
                }
                printf("Packet received from %s (%s) was too short", hostName.c_str(), ipAddress.c_str());
            }
            // Time Limit Exceeded >> Packet Lost
            else {
                if (pingTest) {
                    return -1;
                }
                printf("%d bytes from %s: ICMP Sequence = %llu, %llu Packet(s) Lost >> Time Limit Exceeded\n", byteCount, ipAddress.c_str(), id++, ++lost);
            }
        }
        // No response received
        else {
            if (pingTest) {
                return -1;
            }
            printf("%d bytes from %s: ICMP Sequence = %llu, %llu Packet(s) Lost >> No response received\n", byteCount, ipAddress.c_str(), id++, ++lost);
        }
        // Use system ping noise if audible flag was enabled
        if (audible) {
            cout << '\a';
        }
        usleep(sleepDuration);
    }
    postPingStats(0);  // Display statistics after the run
    return 0;
}

vector<int> parseArguments(int argc, char *argv[]) {
    cout << endl;
    vector<int> args = {defaultTTL, defaultInterval, -1, 0};
    // TTL (int), Interval (double), Packets (int), Audible (bool)
    int pointer = 0;
    while (++pointer != argc) {
        // TTL Flag
        if (!strncmp(argv[pointer], "-t", 2) || !strncmp(argv[pointer], "--ttl", 3)) {
            int ttl = stoi(argv[++pointer]);
            if (ttl < 0 || ttl > 255) {
                throw invalid_argument("Out of bounds");
            }
            args[0] = ttl;
            cout << "TTL set to " << ttl << " seconds" << endl;
        }
        // Interval Flag
        else if (!strncmp(argv[pointer], "-i", 2) || !strncmp(argv[pointer], "--interval", 3)) {
            double interval = stod(argv[++pointer]);
            if (interval < 0.0) {
                throw invalid_argument("Out of bounds");
            }
            cout << "Ping interval set to " << interval << " seconds" << endl;
            args[1] = (unsigned int) (interval * 1000000);
        }
        // Packet Flag
        else if (!strncmp(argv[pointer], "-p", 2) || !strncmp(argv[pointer], "--packets", 3)) {
            int packetCount = stoi(argv[++pointer]);
            if (packetCount <= 0) {
                cout << "Packet Count flag is set to 0, aborting Ping CLI tool";
                exit(0);
            }
            args[2] = packetCount;
            cout << "Packet count set to " << packetCount << endl;
        }
        // Audible Flag
        else if (!strncmp(argv[pointer], "-a", 2) || !strncmp(argv[pointer], "--audible", 3)) {
            cout << "Audible flag enabled" << endl;
            args[3] = 1;
        }
        // IP Address or hostname argument
        else {
            string address = string(argv[pointer]);
            struct sockaddr_in sockAddr{};
            sockAddr.sin_port = 0;
            sockAddr.sin_family = AF_INET;
            inet_pton(AF_INET, address.c_str(), &(sockAddr.sin_addr));
            int colonIndex = address.find(':');
            // If a DNS address was provided
            if ((sockAddr.sin_addr.s_addr == (in_addr_t) (-1) || sockAddr.sin_addr.s_addr == 0) && colonIndex == -1) {
                struct hostent *resolveDNS = gethostbyname(address.c_str());
                // If DNS lookup was successful
                if (resolveDNS) {
                    hostName = address;
                    sockAddr.sin_family = resolveDNS->h_addrtype;
                    bcopy(resolveDNS->h_addr, (caddr_t) &sockAddr.sin_addr, resolveDNS->h_length);
                    char *hostname = const_cast<char *>(address.c_str());
                    char ip[100];
                    struct hostent *he = gethostbyname(hostname);
                    struct in_addr **addr_list;
                    addr_list = (struct in_addr **) he->h_addr_list;
                    strcpy(ip, inet_ntoa(*addr_list[0]));
                    ipAddress = ip;
                    isIPv4 = ipAddress.find(':') == -1;
                }
            }
            // If an IP address was provided
            else if (sockAddr.sin_addr.s_addr > 0 || colonIndex != -1) {
                isIPv4 = colonIndex == -1;
                hostName = address;
                ipAddress = address;
            }
            // Run full ping test to ensure the IP address is valid
            if(!ipAddress.empty()) {
                // If ping is unsuccessful, reset hostName and ipAddress
                if (ping(args[0], args[1], -2, args[3])) {
                    hostName = "", ipAddress = "";
                }
            }
        }
    }
    // Checks if IP address or hostname was provided
    if (ipAddress.empty()) {
        cout << "No valid IP address or hostname was provided, aborting Ping CLI tool" << endl;
        showUsage();
    }
    return args;
}

int main (int argc, char *argv[]) {
    // No arguments were passed
    if (argc == 1 || !strncmp(argv[1], "-h", 2) || !strncmp(argv[1], "--help", 3)) {
        showUsage();
    }
    // Arguments were passed
    else {
        // Address (str), isIPv4 (bool), TTL (int), Interval (double), Packets (int), Audible (bool)
        vector<int> args = parseArguments(argc, argv);
        if (argc == 2) {
            cout << "\nNo flags provided, using default values for TTL and ping interval" << endl;
        }
        cout << endl;
        signal(SIGINT, postPingStats);  // Adds ctrl + c listener to provide post Ping CLI statistics
        ping(args[0], args[1], args[2], args[3]);
    }
    return 0;
}
