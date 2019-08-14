#include <iostream>
#include "md5.h"

using namespace std;

string genResponse(string password) {
    // HA1 = MD5(username:realm:password)
    // HA2 = MD5(method:digestURI)
    // response = MD5(HA1:nonce:HA2)
    string ha1 = md5("admin:IP Camera(C5426):" + password);
    string ha2 = md5("DESCRIBE:/ch1/main/av_stream");
    string response = md5(ha1 + ":6efad5225d8cbca2a6c0bb8adb4615a3:" + ha2);
    return response;
}


string alphabet="abcdefghijklmnopqrstuvwxyz";
string ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
string s_symbol="!@#$%&";
string number="0123456789";

bool on_alphabet = false;
bool on_ALPHABET = false;
bool on_symbol = false;
bool on_number = false;

const int min_password_length = 8;
const int max_password_length = 16;
int password_length = min_password_length;
int character_length;

int pwd[max_password_length];
string pstr = "";
string password = "";

/**
 *  method prepares the script for bruteforce password generation
 **/
void prepare() {
    if (on_alphabet == true) {
        pstr += alphabet;
    }

    if (on_ALPHABET == true) {
        pstr += ALPHABET;
    }

    if (on_number == true) {
        pstr += number;
    }

    if (on_symbol == true) {
        pstr += s_symbol;
    }

    character_length = pstr.length();

    for (int i=0; i<max_password_length; i++) {
        pwd[i] = 0;
    }
}


/**
 *  Method returns next in line password
 * */
string getNextPassword() {
    pwd[password_length-1]++;
    for (int i=password_length-1; i>0; i--) {
        if (pwd[i] >= character_length) {
            pwd[i] = 0;
            pwd[i-1]++;
        } else {
            break;
        }
    }

    if (pwd[0] >= character_length) {
        return "";
    }

    password = "";
    for (int i=0; i<password_length; i++) {
        password += pstr.at( pwd[i] );
    }

    return password;
}



int main()
{
    cout << "Hello World" << endl;

    string finalresponse = "f2e5deb88d09181be414f2f30e0ae95c";

    on_alphabet = true;
    on_number = true;

    prepare();


    string pass = getNextPassword();
    string passmd5 = "";
    
    double counter = 0;
    int dispcouter = 0;
    while (pass != "") {

        passmd5 = genResponse(pass);

        if (dispcouter == 1000000) {
            cout << counter << "\t: " << finalresponse << "<->" << passmd5 << " : " << pass << endl;
            dispcouter = 0;
        }

        if (passmd5 == finalresponse) {
            cout << "Match! password is \"" << pass << "\".";
            break;
        }

        pass = getNextPassword();
        counter++;
        dispcouter++;
    }

    return 0;
}