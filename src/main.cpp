#include <iostream>
#include "md5.h"
#include <sys/stat.h>
#include <time.h>
#include <fstream>

using namespace std;


const string control_file = "bruteforce.running.pid";
const string state_file = "bruteforce.state.txt";

const string alphabet="abcdefghijklmnopqrstuvwxyz";
const string ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const string s_symbol="!@#$%&";
const string number="0123456789";
const string hexnumber="0123456789abcdef";

const int min_password_length = 8;
const int max_password_length = 16;
int password_length = min_password_length;
int character_length;

bool on_alphabet = false;
bool on_ALPHABET = false;
bool on_symbol = false;
bool on_number = false;
bool on_hex = false;

int pwd[max_password_length];
string pstr = "";
string password = "";
string ha2 = "";

string method = "";
string uri = "";
string nonce = "";
string username = "";
string realm = "";
string finalresponse = "";


/**
 *  method checks if file exists on disk
 **/
inline bool file_exists (const string& name) {
  struct stat buffer;   
  return (stat (name.c_str(), &buffer) == 0); 
}


string genResponse(string password) {
    // HA1 = MD5(username:realm:password)
    // HA2 = MD5(method:digestURI)
    // response = MD5(HA1:nonce:HA2)
    string ha1 = md5(username + ":" + realm + ":" + password);
    // string ha1 = md5("admin:IP Camera(C5426):" + password);
    string response = md5(ha1 + ":" + nonce + ":" + ha2);
    return response;
}


/**
 *  method prepares the script for bruteforce password generation
 **/
void prepare() {

    pstr = "";

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

    if (on_hex == true) {
        pstr += hexnumber;
    }

    character_length = pstr.length();

    for (int i=0; i<max_password_length; i++) {
        pwd[i] = 0;
    }

    string ha2 = md5(method + ":" + uri);
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


/**
 *  method returns the timestamp in formatted string
 **/
string timestamp() {
  
    time_t rawtime;
    struct tm * timeinfo;
    char buffer [80];

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    strftime(buffer,80,"%F %T",timeinfo);

    return string(buffer);
    // puts (buffer);
}


/**
 *  method saves the state of the bruteforce on to file, for later loading purpose...
 **/
void save_state() {
    // create the state file
    ofstream outfile (state_file.c_str());
    outfile << "length:" << password_length << endl;
    outfile << "simple:" << on_alphabet << endl;
    outfile << "capital:" << on_ALPHABET << endl;
    outfile << "numeric:" << on_number << endl;
    outfile << "symbols:" << on_symbol << endl;

    outfile << "pattern:";
    for (int i=0; i<max_password_length; i++) {
        outfile << pwd[i] << ",";
    }
    outfile << endl;

    outfile << "lastpassword:";
    for (int i=0; i<password_length; i++) {
        outfile << pstr.at( pwd[i] );
    }
    outfile << endl;

    outfile.close();
}



/**
 *  Main programm
 **/
int main()
{

    cout << "Azhan's RTSP digest hash crack..." << endl;

    bool prompt = true;

    while (prompt) {

        if (username == "") {
            cout << " -> enter username: ";
            getline(cin, username);
        }

        if (realm == "") {
            cout << " -> enter realm: ";
            getline(cin, realm);
        }

        if (method == "") {
            cout << " -> enter method: ";
            getline(cin, method);
        }

        if (uri == "") {
            cout << " -> enter uri: ";
            getline(cin, uri);
        }

        if (nonce == "") {
            cout << " -> enter nonce: ";
            getline(cin, nonce);
        }


        if (finalresponse == "") {
            cout << " -> enter response: ";
            getline(cin, finalresponse);
        }

        if (username != "" && realm != "" && nonce != "" && method != "" && uri != "" && finalresponse != "") {
            prompt = false;
            cout << "string -> " << username << ":" << realm << ":" << nonce << ":" << method << ":" << uri << ":" << finalresponse << endl;
        }

    }


    cout << endl << timestamp() << " Starting Azhans Bruteforce!" << endl;

    // string finalresponse = "f2e5deb88d09181be414f2f30e0ae95c";

    on_alphabet = false;
    on_number = false;
    on_ALPHABET = false;
    on_symbol = false;
    on_hex = true;

    bool found = false;

    // create the control file
    ofstream outfile (control_file);
    outfile << "starting" << endl;
    outfile.close();

    int dispcouter = 0;
    int countx = 0;


    while (found == false) {
        prepare();

        string pass = getNextPassword();
        string passmd5 = "";
        

        while (pass != "") {
            passmd5 = genResponse(pass);

            if (dispcouter == 5000000) {
                countx++;

                cout << timestamp() << " " << (countx * 5) << "M\t -> " << pass << endl;
                dispcouter = 0;

                if (!file_exists(control_file)) {
                    cout << timestamp() << " pid file removed. exiting..." << endl;
                    save_state();
                    return 0;
                }
            }

            if (passmd5 == finalresponse) {
                cout << timestamp() <<" MATCH! password is \"" << pass << "\".";
                found = true;
                break;
            }

            pass = getNextPassword();
            dispcouter++;
        }

        if (found == false) {
            password_length++;
            cout << timestamp() << " Increasing password length to " << password_length << " characters!" << endl;
        }

        if (password_length > max_password_length) {
            cout << timestamp() << " MAXMIUM REACHED! exiting...";
            return 0;
        }

        if (!file_exists(control_file)) {
            cout << timestamp() << " pid file removed. exiting..." << endl;
            save_state();
            return 0;
        }
    }

    return 0;
}