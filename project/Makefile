CXX=g++
CXXFLAGS=-g -fsanitize=address -I. -Wno-deprecated-declarations
LDFLAGS=-lcrypto
USERID=123456789

HELPER_SRCS=$(wildcard helpers/*.cpp)
DEPS=$(HELPER_SRCS:.cpp=.d)

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $(CXXFLAGS) $<

all: server client

server: server.o security.o $(HELPER_SRCS:.cpp=.o)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

client: client.o security.o $(HELPER_SRCS:.cpp=.o)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

security.o: security.cpp
	$(CXX) -c -o $@ $(CXXFLAGS) $<

clean:
	rm -rf *.o helpers/*.o server client *.tar.gz

dist: tarball

tarball: clean
	tar -cvzf /tmp/$(USERID).tar.gz --exclude=./.vagrant . && mv /tmp/$(USERID).tar.gz .