#include <iostream>
#include "utils.h"
#include "client.h"
#include "server.h"

using namespace std;

int main(){
    cout << "Hello World!" << endl;
    
    Server* server = new Server();
    Client client(server);

    client.run_protocol();
}