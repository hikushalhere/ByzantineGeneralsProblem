general: main.cpp General.cpp Commander.cpp Lieutenant.cpp
	g++ -o general main.cpp General.cpp Commander.cpp Lieutenant.cpp -lcrypto
clean:
	rm -rf *.o general
