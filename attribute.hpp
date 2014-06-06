#ifndef SBEJVT_ATTRIBUTE_HPP
#define SBEJVT_ATTRIBUTE_HPP

#include "boost/array.hpp"

typedef enum {
    ATTRIBUTE_VALUE_TYPE_UNKNOWN,
    ATTRIBUTE_VALUE_TYPE_ADDRESS,
    ATTRIBUTE_VALUE_TYPE_DATE,
    ATTRIBUTE_VALUE_TYPE_INTEGER,
    ATTRIBUTE_VALUE_TYPE_STRING,
    ATTRIBUTE_VALUE_TYPE_TEXT,
    ATTRIBUTE_VALUE_TYPE_TIME,
    ATTRIBUTE_VALUE_TYPE_VENDOR_SPECIFIC
} ATTRIBUTE_VALUE_TYPE;

#define MAX_ATTRIBUTE_ID 255

class attributes {
private:
    std::string _vendor_name;
    unsigned int _vendor_id; //0 for standard

    boost::array< boost::tuple<std::string, unsigned int, ATTRIBUTE_VALUE_TYPE>, MAX_ATTRIBUTE_ID + 1> _attributes;

public:
    attributes()
    {
        // set all attribute id to 0. 0 means not defined
    }
    ~attributes() {}

    std::string get_vendor_name() const
    {
        return _vendor_name;
    }

    unsigned int get_vendor_id() const
    {
        return _vendor_id;
    }

    bool operator==(const attributes& attr) const
    {
        return (_vendor_id == attr._vendor_id);
    }

    void set_vendor(std::string name, unsigned int id)
    {
        _vendor_name = name;
        _vendor_id = id; 
    }

    bool defined(unsigned int attribute_id)
    {
        return (_attributes[attribute_id].get<1>() != 0);
    }

    unsigned int get_id(std::string attribute_name)
    {
        std::size_t i;
        for (i = 0; i < _attributes.size(); i++) {
            if ((_attributes[i].get<1>() != 0) && 
                (_attributes[i].get<0>().compare(attribute_name) == 0)) {
                break;
            }
        }

        return i;
    }

    ATTRIBUTE_VALUE_TYPE get_value_type(unsigned int attribute_id)
    {
        return _attributes[attribute_id].get<2>();
    }

    void set_attribute(std::string name, unsigned int id, ATTRIBUTE_VALUE_TYPE value_type)
    {
        _attributes[id].get<0>() = name;
        _attributes[id].get<1>() = id;
        _attributes[id].get<2>() = value_type;
    }
};

std::size_t hash_value(const attributes& attr)
{
    return boost::hash_value(attr.get_vendor_id());
}

#endif

