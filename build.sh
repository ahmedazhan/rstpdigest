
if [ -f bin/digestcrack ] 
then
    rm bin/digestcrack
fi

g++ src/main.cpp src/md5.cpp -o bin/digestcrack