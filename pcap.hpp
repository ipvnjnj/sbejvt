#ifndef _SBEJVT_PCAP_HPP
#define _SBEJVT_PCAP_HPP

#include "pcap.h"

class pcap {
private:
    pcap_t* _pcap;
    struct bpf_program _bpf;

public:
    pcap() {};
    ~pcap() {};

    void open_device(const char* device)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        _pcap = pcap_create(device, errbuf);
        if (_pcap == NULL) {
            std::cerr << errbuf;
            throw std::exception();
        }

        pcap_set_snaplen(_pcap, 65535);
        pcap_set_promisc(_pcap, 1);
        pcap_set_buffer_size(_pcap, 10 * 1024 * 1024);

        if (pcap_activate(_pcap) != 0) {
            pcap_close(_pcap);
            pcap_perror(_pcap, NULL);
            throw std::exception();
        }
    }

    void open_file(const char* filename)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        _pcap = pcap_open_offline(filename, errbuf);
        if (_pcap == NULL) {
            std::cerr << errbuf << std::endl;
            throw std::exception();
        }
    }

    void close(void) {
        pcap_close(_pcap);
    }

    bool set_filter(const char* filter_string)
    {
        if (pcap_compile(_pcap, &_bpf, filter_string, 1, 0) != 0)
            return false;

        return !pcap_setfilter(_pcap, &_bpf);
    }

    int loop(pcap_handler callback, int count = -1, void* user = NULL)
    {
        int rt = pcap_loop(_pcap, count, callback, (u_char*)user);
        if (rt == -1) {
            // an error occurs
            pcap_perror(_pcap, (char*)"read packet error");
        }
        return rt;
    }

    void show_stats(void)
    {
        struct pcap_stat ps;
        if (pcap_stats(_pcap, &ps) == 0)
        {
            std::cout << "packets received: " << ps.ps_recv << std::endl;
            std::cout << "packets dropped: " << ps.ps_drop << std::endl;
            //std::cout << "packets inteface dropped: " << ps.ps_ifdrop << std::endl;
        }
    }
};

#endif

