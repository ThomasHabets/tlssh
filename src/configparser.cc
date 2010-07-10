/**
 * @file src/configparser.cc
 * Config file parser
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<string>
#include<vector>
#include<fstream>
#include<iostream>
#include<iterator>

#include"tlssh.h"
#include"util.h"
#include"configparser.h"

/**
 * Parse config line.
 */
void
ConfigParserData::parse_line(const std::string&s)
{
	lineno++;
	line = s;
	rest = "";
	keyword = "";
	parms = tokenize(trim(s));

	if (parms.size()) {
		keyword = parms[0];
		rest = trim(s.substr(keyword.length()));
		parms.erase(parms.begin());
	}

}

/**
 * Output parsed config line quite verbosely.
 */
std::ostream&
operator<<(std::ostream&o, const ConfigParserData&d)
{ 
	o << d.lineno << ": <" << d.line << ">" << std::endl
	  << "  Keyword: <" << d.keyword << ">" << std::endl
	  << "  Rest:    <" << d.rest << ">" << std::endl
	  << "  Parms:   [";
	for (ConfigParserData::parms_t::const_iterator itr = d.parms.begin();
	     itr != d.parms.end();
	     ++itr) {
		o << "<" << *itr << "> ";
	}
	o << "]";
        return o;
}

/**
 * Compare iterators. Two iterators are only the same if either they are
 * the same iterator or they are both EOF.
 */
bool
ConfigParser::operator==(const ConfigParser&rhs) const
{
        if (&rhs == this) {
                return true;
        }
	return rhs.is_end & is_end;
}

/**
 * Opposite of ==
 */
bool
ConfigParser::operator!=(const ConfigParser&rhs) const
{
	return !(*this == rhs);
}

/**
 * Read and parse one line from the input stream.
 */
void
ConfigParser::readnext()
{
	std::string line;
	getline(*stream, line);
	if (stream->eof()) {
		if (line.empty()) {
			is_end = true;
		}
	} else if (!stream->good()) {
		THROW(ErrStream, "configparser stream is not 'good'");
	}
	data.parse_line(line);
}

/**
 * Prefix increment
 */
const ConfigParser&
ConfigParser::operator++()
{
	readnext();
	return *this;
}

/**
 * Postfix increment
 */
ConfigParser
ConfigParser::operator++(int)
{
	ConfigParser tmp(*this);
	readnext();
	return tmp;;
}

/**
 * Dereference
 */
const ConfigParserData&
ConfigParser::operator*() const
{
	return data;
}

/**
 * Dereference and follow
 */
const ConfigParserData*
ConfigParser::operator->() const
{
	return &data;
}


/**
 * Create an iterator generating config entries from the input stream 's'.
 * The generated iterator will turn into an EOF iterator when EOF is reached.
 * @param[in] s Input stream
 */
ConfigParser::ConfigParser(std::istream &s)
	:stream(&s),is_end(false)
{
	readnext();
}

/**
 * Create an EOF iterator. Never read from, only compared against a real
 * iterator to see if we have reached end of file.
 */
ConfigParser::ConfigParser()
	:stream(0),is_end(true)
{
}


#ifdef UNIT_TEST
/**
 *
 */
int
main()
{
	// test parser
	if (1) {
		std::ostream_iterator<ConfigParserData> out(std::cout, "\n");
		std::ifstream inn("../test/test.conf");
		std::copy(ConfigParser(inn),
			  ConfigParser(),
			  out);
	}

	// debug code
	if (0) {
		std::cout << "--------\n";
		std::ostream_iterator<char> out(std::cout);
		std::ifstream inn("../test/test.conf");
		std::copy(std::istreambuf_iterator<char>(inn),
			  std::istreambuf_iterator<char>(),
			  out);
	}
}
#endif

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
