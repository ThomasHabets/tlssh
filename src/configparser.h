// -*- c++ -*-
#include<string>
#include<vector>

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

class ConfigParser: public std::iterator<std::input_iterator_tag,
					 ConfigParserData,
					 const ConfigParserData*,
					 const ConfigParserData&
					 > {
public:
        class ErrStream {
	public:
		ErrStream(const std::string &s) {}
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
