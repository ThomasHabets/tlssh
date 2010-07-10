// -*- c++ -*-
/**
 * @file src/configparser.h
 * Config file parser
 */
#include<string>
#include<vector>

#include "errbase.h"

/** Data which the ConfigParser iterator dereferences to
 *
 */
struct ConfigParserData {
	ConfigParserData():lineno(0){}

	void parse_line(const std::string &s);

	unsigned int lineno;
	std::string line;
	std::string keyword;
	std::string rest;
	typedef std::vector<std::string> parms_t;
	parms_t parms;
};

/**
 * Input iterator generating parsed lines from an input stream.
 *
 * Example use:
 @code
  std::ostream_iterator<ConfigParserData> out(std::cout, "\n");
  std::ifstream inn("../test/test.conf");
  std::copy(ConfigParser(inn),
            ConfigParser(),
            out);
 @endcode
 @code
  std::ifstream fi(fn.c_str());
  ConfigParser conf(fi);
  ConfigParser end;
  for (;conf != end; ++conf) {
    std::cout << conf->keyword << std::endl;
  }
 @endcode
 */
class ConfigParser: public std::iterator<std::input_iterator_tag,
					 ConfigParserData,
					 const ConfigParserData*,
					 const ConfigParserData&
					 > {
public:
        /**
         * Exception for read errors
         */
        class ErrStream: Err::ErrBase {
	public:
                ErrStream(Err::ErrData errdata,
                          const std::string &m):Err::ErrBase(errdata,m) {}
                virtual ~ErrStream() throw() {}
	};

	bool operator==(const ConfigParser&rhs) const;
	bool operator!=(const ConfigParser&rhs) const;

	const ConfigParserData&operator*() const;
	const ConfigParserData*operator->() const;

	const ConfigParser& operator++();
	ConfigParser operator++(int);

	ConfigParser(std::istream &s);
	ConfigParser();
private:
	struct ConfigParserData data;
	std::istream *stream;
	bool is_end;
	void readnext();
};

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
