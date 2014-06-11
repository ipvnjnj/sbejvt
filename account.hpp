#ifndef SBEJVT_ACCOUNT_HPP
#define SBEJVT_ACCOUNT_HPP

#include "boost/array.hpp"
#include "boost/tuple/tuple.hpp"

#include "attribute.hpp"

#define MAX_VALUE_LENGTH 255

class account {
private:
    // attributes
    boost::array< boost::tuple<uint8_t, uint8_t[MAX_VALUE_LENGTH], std::size_t>, MAX_ATTRIBUTE_ID + 1 > _attributes;

public:
    account()
    {
    }
    ~account() 
    {
    }

    void add_attribute(unsigned int id, uint8_t* value, unsigned int length)
    {
        if (id > MAX_ATTRIBUTE_ID) return;

        _attributes[id].get<0>() = id;
        if (length > MAX_VALUE_LENGTH) length = MAX_VALUE_LENGTH;
        memcpy(_attributes[id].get<1>(), value, length);
        _attributes[id].get<2>() = length;
    }

    void clear_attributes()
    {
        std::size_t i;
        for (i = 0; i < _attributes.size(); i++) {
            _attributes[i].get<0>() = 0;
            _attributes[i].get<1>()[0] = '\0';
            _attributes[i].get<2>() = 0;
        }
    }

    std::pair<uint8_t*, std::size_t> get_attribute_value(unsigned int attribute_id)
    {
        if (attribute_id > MAX_ATTRIBUTE_ID)
            return std::make_pair((uint8_t*)0, 0);
        else 
            return std::make_pair(_attributes[attribute_id].get<1>(), _attributes[attribute_id].get<2>());
    }
};

#endif

