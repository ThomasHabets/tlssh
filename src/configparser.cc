// tlssh/src/configparser.cc
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
 *
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
 *
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
 *
 */
bool
ConfigParser::operator==(const ConfigParser&rhs) const
{
	return rhs.is_end & is_end;
}

/**
 *
 */
bool
ConfigParser::operator!=(const ConfigParser&rhs) const
{
	return !(*this == rhs);
}

/**
 *
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
 *
 */
const ConfigParser&
ConfigParser::operator++()
{
	readnext();
	return *this;
}

/**
 *
 */
ConfigParser
ConfigParser::operator++(int unused)
{
	ConfigParser tmp(*this);
	readnext();
	return tmp;;
}

/**
 *
 */
const ConfigParserData&
ConfigParser::operator*() const
{
	return data;
}

/**
 *
 */
const ConfigParserData*
ConfigParser::operator->() const
{
	return &data;
}


/**
 *
 */
ConfigParser::ConfigParser(std::istream &s)
	:stream(&s),is_end(false)
{
	readnext();
}

/**
 *
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
