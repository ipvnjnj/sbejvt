#include <net/ethernet.h>
#include <netinet/ip.h>
#include <unistd.h>

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "boost/filesystem.hpp"
#include "boost/unordered_set.hpp"

#include "account.hpp"
#include "pcap.hpp"

enum {
    ACCESS_REQUEST = 1,
    ACCESS_ACCEPT = 2,
    ACCESS_REJECT = 3,
    ACCOUNTING_REQUEST = 4,
    ACCOUNTING_RESPONSE = 5,
    ACCESS_CHALLENGE = 11,
    STATUS_SERVER = 12,
    STATUS_CLIENT = 13
};

attributes g_standard_attributes;
boost::unordered_set<attributes> g_vendor_attributes;

#define DELIMITER ','
void __print_attribute(ATTRIBUTE_VALUE_TYPE type, const uint8_t* value, std::size_t length)
{
    switch (type) {
    case ATTRIBUTE_VALUE_TYPE_UNKNOWN:
        std::cout << "unknown";
        break;

    case ATTRIBUTE_VALUE_TYPE_ADDRESS:
        /*
        struct in_addr in;
        in.s_addr = *(uint32_t*)value;
        char ip_string[32];
        inet_ntop(AF_INET, (const void*)(&in), ip_string, sizeof(ip_string));
        std::cout << ip_string; 
        */
        std::cout << *(const uint32_t*)value; 
        break;

    case ATTRIBUTE_VALUE_TYPE_DATE:
    {
        time_t t = ntohl(*(const uint32_t*)value);
        char buffer[128];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&t));
        std::cout << buffer;
        break;
    }

    case ATTRIBUTE_VALUE_TYPE_INTEGER:
        // length should be 4;
        std::cout << ntohl(*(const uint32_t*)value);
        break;

    case ATTRIBUTE_VALUE_TYPE_STRING:
    case ATTRIBUTE_VALUE_TYPE_TEXT:
    {
        std::size_t i;
        for (i = 0; i < length; i++) {
            std::cout << value[i];
        }
        break;
    }

    case ATTRIBUTE_VALUE_TYPE_TIME:
    {
        time_t t = ntohl(*(const uint32_t*)value);
        std::cout << t;
        break;
    }

    case ATTRIBUTE_VALUE_TYPE_VENDOR_SPECIFIC:
        break;

    default:
        break;
    }
}

static void _print_attribute(account& acc, std::string attribute_name)
{
    unsigned int attribute_id = g_standard_attributes.get_id(attribute_name);
    std::pair<const uint8_t*, std::size_t> attribute_value = acc.get_attribute_value(attribute_id);
    const uint8_t* value = attribute_value.first;
    std::size_t length = attribute_value.second;
    ATTRIBUTE_VALUE_TYPE type = g_standard_attributes.get_value_type(attribute_id);
    if (value != NULL) {
        __print_attribute(type, value, length);
    }

    std::cout << DELIMITER;
}

static void _print_attribute(account& acc, std::string vendor_name, std::string attribute_name)
{
    unsigned int attribute_id;
    ATTRIBUTE_VALUE_TYPE type = ATTRIBUTE_VALUE_TYPE_UNKNOWN;
    const uint8_t* value = NULL;
    std::size_t length = 0;

    // iterate vendor attributes to get id 
    boost::unordered_set<attributes>::iterator iter;
    for (iter = g_vendor_attributes.begin(); iter != g_vendor_attributes.end(); ++iter) {
        if (iter->get_vendor_name().compare(vendor_name) == 0)
            break;
    }
    if (iter != g_vendor_attributes.end()) {
        attribute_id = iter->get_id(attribute_name);
        type = iter->get_value_type(attribute_id);

        attribute_id += (iter->get_vendor_id() << 8);
        std::pair<const uint8_t*, std::size_t> attribute_value = acc.get_attribute_value(attribute_id);
        value = attribute_value.first;
        length = attribute_value.second;
        if (value != NULL) {
            __print_attribute(type, value, length);
        }
    }
    else {
        std::cerr << "vendor: " << vendor_name << " not found" << std::endl;
    }

    std::cout << DELIMITER;
}

std::string g_log_file_path = "./log";
time_t g_log_time = 0, g_log_interval = 60;
std::ofstream g_log_file;

static bool _prepare_log_file(time_t now)
{
    // check if now time is greater than log time + log interval
    if (now < (g_log_time + g_log_interval))
    {
        // not need create new log file
        return true;
    }

    g_log_time = now;

    // close the used log file and create a new one
    g_log_file.close();

    // turn time to year/month/day/hour/minute
    struct tm now_broken_down_time;
    if (localtime_r(&now, &now_broken_down_time) == NULL)
        return false;
    int year = now_broken_down_time.tm_year + 1900;
    int month = now_broken_down_time.tm_mon + 1;
    int day = now_broken_down_time.tm_mday;
    int hour = now_broken_down_time.tm_hour;
    int minute = now_broken_down_time.tm_min;
    int second = now_broken_down_time.tm_sec;

    std::ostringstream log_file_name;
    log_file_name << g_log_file_path << '/' << year << '/' << year << '-' << month << '-' << day;
    if (!boost::filesystem::exists(log_file_name.str())) {
        if (!boost::filesystem::create_directories(log_file_name.str())) {
            std::cerr << "cannot create directory " << log_file_name.str() << std::endl;
            return false;
        }
    }

    // create new log file.
    log_file_name << '/' << year << '_' << month << '_' << day << '_' << hour << '_' << minute << '_' << second << ".csv";
   
    // redirect std::cout to log file.
    g_log_file.open(log_file_name.str().c_str());
    if (!g_log_file.good()) {
        std::cerr << "cannot open file " << log_file_name.str() << std::endl;
        return false;
    }
    std::streambuf *log_buffer = g_log_file.rdbuf();
    std::cout.rdbuf(log_buffer);

    return true;
}

static void _radius_process(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes)
{
    if (!_prepare_log_file(h->ts.tv_sec))
        return;

    struct iphdr* ipptr;
    if (((struct ether_header*)bytes)->ether_type != 0x0008) {
        // not standard ethernet head, need skip 18 bytes
        ipptr = (struct iphdr*)(bytes + sizeof(struct ether_header) + 18);
    }
    else {
        ipptr = (struct iphdr*)(bytes + sizeof(struct ether_header));
    }
    struct udphdr* udpptr = (struct udphdr*)((uint8_t*)ipptr + ipptr->ihl * 4);
    unsigned char* data = (unsigned char*)udpptr + 8;

    unsigned int code = data[0];
    //unsigned int identifier = data[1];
    unsigned int length = (data[2] << 8) + data[3];
    uint8_t* authenticator = data + 4;
    /*
    std::cout << "code: " << code << std::endl;
    std::cout << "identifier: " << identifier << std::endl;
    std::cout << "length: " << length << std::endl;
    std::cout << std::endl;
    */

    account acc;

    if ((data + length) > (bytes + h->caplen)) {
        /*
        std::cerr << "data too long" << std::endl;
        std::cerr.fill('0');
        for (std::size_t i = 0; i < length; i++) {
            std::cerr << std::setw(2) << std::hex << (unsigned int)(bytes[i]) << ' ';
            if ((i % 16) == 15) std::cerr << std::endl;
        }
        */
        return;
    }

    switch (code) {
    case ACCESS_REQUEST:
        //std::cout << "Access-Request" << std::endl;
        break;

    case ACCESS_ACCEPT:
        //std::cout << "Access-Reply" << std::endl;
        break;

    case ACCOUNTING_REQUEST:
    {
        // now we only process accounting-request
        //std::cout << "Accouting-Request" << std::endl;

        unsigned char* attributes = data + 20;
        while (attributes < data + length) {
            unsigned int attribute_type = attributes[0];
            unsigned int attribute_length = attributes[1] - 2;
            uint8_t* attribute_value = attributes + 2;

            if ((attribute_value + attribute_length) > (data + length)) {
                std::cerr << "invalid attribute length" << std::endl;
                return;
            }

            // next attribute
            attributes += (attribute_length + 2);

            if (g_standard_attributes.defined(attribute_type)) {
                if (attribute_type == 26/*vendor specific attribute*/) {
                    // extract the real type/value/length
                    // first 4 bytes is vendor id
                    uint32_t vendor_id = ntohl(*(const uint32_t*)attribute_value);
                    attribute_value += sizeof(uint32_t);
                    // then one byte vendor attribute id and one byte attribute length
                    attribute_type = (vendor_id << 8) + *attribute_value++;
                    unsigned int long_length = attribute_length;
                    attribute_length = *attribute_value++ - 2;
                    if ((attribute_length + 6) != long_length) {
                        std::cerr << "NNGX" << std::endl;
                    }
                }

                acc.add_attribute(attribute_type, attribute_value, attribute_length);
            }
            else {
                std::cerr << "attribute " << attribute_type << " not defined" << std::endl;
            }
        }

        // print the following information
        //ProviderID SrcIP DstIP Account UserPassword Acct_Sess_Id Acct_Multi_Sess_Id Acct_Link_Count Acct_Input_Octets Acct_Output_Octets Acct_Input_Packets Acct_Output_Packets Starttime Endtime Request_auth nas_ipaddr radius_ipaddr framed_ip_address calling_tel acct_status_type ignored nas_domainname capturetime nas_port_type nas_delay_time off_cause
#define PROVIDER_ID 13
        std::cout << PROVIDER_ID << DELIMITER;

        std::cout << ntohl(ipptr->saddr) << DELIMITER;
        std::cout << ntohl(ipptr->daddr) << DELIMITER;

        _print_attribute(acc, "Calling-Station-Id");
        _print_attribute(acc, "User-Password");
        _print_attribute(acc, "Acct-Session-Id");
        _print_attribute(acc, "Acct-Multi-Session-Id");
        _print_attribute(acc, "Acct-Link-Count");
        _print_attribute(acc, "Acct-Input-Octets");
        _print_attribute(acc, "Acct-Output-Octets");
        _print_attribute(acc, "Acct-Input-Packets");
        _print_attribute(acc, "Acct-Output-Packets");
        _print_attribute(acc, "Event-Timestamp");
        _print_attribute(acc, "Acct-Session-Time"); 
        /*
        {
            // Here we does'nt use _print_attribute() function and mannuly get the value. Because the value of "acct-session-time" need added to the value of "evnet-timestamp". 
            unsigned int event_timestamp_id = g_standard_attributes.get_id("Event-Timestamp");
            std::pair<uint8_t*, std::size_t> event_timestamp = acc.get_attribute_value(event_timestamp_id);
            time_t t1 = ntohl(*(uint32_t*)(event_timestamp.first));
            char buffer[128];
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&t1));
            std::cout << buffer << DELIMITER;

            unsigned int acct_session_time_id = g_standard_attributes.get_id("Acct-Session-Time");
            std::pair<uint8_t*, std::size_t> acct_session_time = acc.get_attribute_value(acct_session_time_id);
            time_t t2 = ntohl(*(uint32_t*)(acct_session_time.first));
            if (t2 > 0) {
                t1 += t2;
                strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&t1));
                std::cout << buffer;
            }
            std::cout << DELIMITER;
        }
        */

        // the authenticator is 16 bytes long
        std::cout << std::hex << std::setiosflags(std::ios::uppercase);
        for (int i = 0; i < 16; i++) {
            std::cout << (unsigned int)(authenticator[i]);
        }
        std::cout << std::dec << DELIMITER;

        _print_attribute(acc, "NAS-IP-Address");
        // Radius IP Address, use dest IP address
        std::cout << ntohl(ipptr->daddr) << DELIMITER;
        _print_attribute(acc, "Framed-IP-Address");
        _print_attribute(acc, "China-Telecom", "Telephone-Number");
        _print_attribute(acc, "Called-Station-Id");
        _print_attribute(acc, "Acct-Status-Type");

        // ignored?
        std::cout << '0' << DELIMITER;

        // NAS domain?
        std::cout << DELIMITER;

        // captur time
        char buffer[128];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&(h->ts.tv_sec)));
        std::cout << buffer << '.' << h->ts.tv_usec << DELIMITER;

        _print_attribute(acc, "NAS-Port-Type");
        _print_attribute(acc, "Acct-Delay-Time");
        _print_attribute(acc, "Acct-Terminate-Cause");
        _print_attribute(acc, "3GPP2", "3GPP2-MEID");
        _print_attribute(acc, "3GPP2", "3GPP2-BSID");
        _print_attribute(acc, "3GPP2", "3GPP2-PCF-IP-Address");

        std::cout << std::endl;

        acc.clear_attributes();

        break;
    }

    case ACCOUNTING_RESPONSE:
        break;

    default:
        break;
    }
}

static bool _load_dictionary_file(const char* dictionary_file_name)
{
    std::cout << "load dictionary " << dictionary_file_name << std::endl;

    std::ifstream df(dictionary_file_name);
    if (!df.good()) {
        std::cerr << "cannot open file: " << dictionary_file_name << std::endl;
        return false;
    }

    bool vendor_specific = false;
    attributes vsa;
    attributes *attr = &g_standard_attributes;

    while (!df.eof()) {
        char line[256];
        df.getline(line, sizeof(line));
        std::istringstream lines(line);
        std::string keyword;
        lines >> keyword;
        if (keyword[0] == '#') {
            // comment, ignore the line
            continue;
        }

        if (keyword.compare("VENDOR") == 0) {
            // verdor specific attributes file
            vendor_specific = true;
            std::string vendor_name;
            unsigned int vendor_id = 0;
            lines >> vendor_name >> vendor_id;
            vsa.set_vendor(vendor_name, vendor_id);
            attr = &vsa;
            continue;
        }

        if (keyword.compare("ATTRIBUTE") == 0) {
            // ATTRIBUTE <attribute type name> <attribute type value> <attribute value type>
            std::string name, temp;
            unsigned int id;
            ATTRIBUTE_VALUE_TYPE value_type;
            lines >> name >> id >> temp;

            if (temp.compare("date") == 0)
                value_type = ATTRIBUTE_VALUE_TYPE_DATE;
            else if ((temp.compare("integer") == 0) || (temp.compare("signed") == 0))
                value_type = ATTRIBUTE_VALUE_TYPE_INTEGER;
            else if (temp.compare("ipaddr") == 0)
                value_type = ATTRIBUTE_VALUE_TYPE_ADDRESS;
            else if (temp.compare(0, 5, "octet") == 0)
                value_type = ATTRIBUTE_VALUE_TYPE_STRING;
            else if (temp.compare("string") == 0)
                value_type = ATTRIBUTE_VALUE_TYPE_TEXT;
            else if (temp.compare("time") == 0)
                value_type = ATTRIBUTE_VALUE_TYPE_TIME;
            else if (temp.compare("vsa") == 0)
                value_type = ATTRIBUTE_VALUE_TYPE_VENDOR_SPECIFIC;
            else {
                std::cerr << "unkown attribute value type: " << temp << std::endl;
                value_type = ATTRIBUTE_VALUE_TYPE_UNKNOWN;
            }

            //std::cout << "add attribute " << name << ' ' << id << ' ' << value_type << std::endl;
            attr->set_attribute(name, id, value_type);
        }
        else if (keyword.compare("VALUE") == 0) {
            // VALUE <attribute type name> <value_name> <value_value>
        }
        else {
            // ignore?
        }
    }

    if (vendor_specific) {
        g_vendor_attributes.insert(*attr);
    }

    df.close();

    return true;
}

static bool _load_dictionary(const char* dictionary_directory)
{
    boost::filesystem::path dd(dictionary_directory);
    if (!boost::filesystem::exists(dd)) {
        std::cerr << "directory " << dictionary_directory << " not exites" << std::endl;
        return false;
    }

    boost::filesystem::directory_iterator end;
    for (boost::filesystem::directory_iterator di(dd); di != end; ++di) {
        if (boost::filesystem::is_regular_file(di->status())) {
            if (boost::filesystem::basename(di->path()).compare(0, 10, "dictionary") == 0) {
                _load_dictionary_file(di->path().string().c_str());
            }
        }
    }

    return true;
}

void _usage(void)
{
}

int main(int argc, char* argv[])
{
    std::string cap_device_name;
    std::string cap_file_name;    
    std::string dictionary_directory = ".";
    std::streambuf* cout_buffer = std::cout.rdbuf();

    int opt;
    while ((opt = getopt(argc, argv, "d:f:i:r:w:")) != -1)
    {
        switch (opt)
        {
        case '?':
            std::cerr << "unkown option" << std::endl;
            _usage();
            exit(1);

        case 'd':
            // the dictionary directory
            dictionary_directory = optarg;
            break;

        case 'f':
            // the pcap file to read packets
            cap_file_name = optarg;
            break;

        case 'i':
            // the log file interval
            g_log_interval = strtol(optarg, NULL, 0);
            break;

        case 'r':
            // the network interface to capture packets
            cap_device_name = optarg;
            break;

        case 'w':
            // the directory to write log files
            g_log_file_path = optarg;
            break;

        default:
            break; 
        }
    }
    argc -= optind;
    argv += optind;

    // load dictionary
    if (_load_dictionary(dictionary_directory.c_str()) != true) {
        std::cerr << "error load dictionary" << std::endl;
        return -1;
    }

    // initialize capture
    pcap capture;
    if (cap_file_name[0]) {
        capture.open_file(cap_file_name.c_str());
    }
    else if (cap_device_name[0]) {
        capture.open_device(cap_device_name.c_str());
    }
    else {
        return 0;
    }
    capture.set_filter("udp port 1812 or udp port 1813");

    // start capture
    int rt = 1;
    while (rt > 0)
    {
        rt = capture.loop(_radius_process);
    }

    capture.close();

    if (cout_buffer) {
        // restore the std::cout buffer
        std::cout.rdbuf(cout_buffer);
    }

    return 0;
}
