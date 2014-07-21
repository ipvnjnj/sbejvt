#ifndef SBEJVT_ACCOUNT_HPP
#define SBEJVT_ACCOUNT_HPP

#include <cstring>

#include "boost/array.hpp"
#include "boost/unordered_map.hpp"

#include "attribute.hpp"

#define MAX_VALUE_LENGTH 255

typedef std::pair<uint8_t[MAX_VALUE_LENGTH], std::size_t> VL;

class account {
private:
    // attributes
    // the vendor specific id is vendor_id * 256 + vendor_attribute_id
    boost::unordered_map<unsigned int/*id*/, VL> _attributes;

public:
    account()
    {
    }
    ~account() 
    {
    }

    void add_attribute(unsigned int id, uint8_t* value, unsigned int length)
    {
        VL vl;
        if (length > MAX_VALUE_LENGTH) length = MAX_VALUE_LENGTH;
        memcpy(vl.first, value, length);
        vl.second = length;

        _attributes[id] = vl;
    }

    void clear_attributes(void)
    {
        _attributes.clear();
    }

    std::pair<const uint8_t*, std::size_t> get_attribute_value(unsigned int id)
    {
        if (_attributes.find(id) != _attributes.end())
            return std::make_pair(_attributes[id].first, _attributes[id].second);
        return std::make_pair((const uint8_t*)0, 0);
    }
};

#endif

