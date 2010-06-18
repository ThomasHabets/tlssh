class FDWrap {
	int fd;
public:
	FDWrap(int fd = -1)
		:fd(fd)
	{
	}
	~FDWrap()
	{
		close();
	}
	void close()
	{
		if (fd > 0) {
			::close(fd);
			forget();
		}
	}

	int get() const
	{
		return fd;
	}

	int set(int n)
	{
		close();
		fd = n;
	}
	void forget()
	{
		fd = -1;
	}

	bool valid()
	{
		return fd != -1;
	}
};
