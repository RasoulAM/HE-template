#ifndef __CLIENT__H
#define __CLIENT__H

#include "seal/seal.h"
#include "utils.h"
#include "server.h"

#include <vector>

class Client {
public:

    seal::EncryptionParameters* enc_params;

    seal::SEALContext* context;
    seal::KeyGenerator* keygen;
    seal::SecretKey secret_key;
    seal::Evaluator* evaluator;
    seal::Encryptor* encryptor;
    seal::BatchEncoder* batch_encoder;
    
    // Stringstreams
    std::stringstream params_stream;
    std::stringstream data_stream;

    Server* server;
    Metrics* metrics;

    // Preparation steps

    Client(){
        server = new Server();
    }
    
    Client(Server* _server){
        server = _server;
    }

    void set_server(Server* server);
    void setup_crypto(uint64_t log_poly_modulus_degree=14, uint64_t prime_bitlength=20, bool _verbose = true);
    void send_parameters_and_keys(bool debug_mode=false);
    void encrypt_and_send(vector<seal::Plaintext>& plaintexts, bool _verbose);
    bool run_protocol(bool _verbose = true);
    vector<seal::Plaintext> load_and_decrypt(int num_cts, bool _verbose = true);
};

#endif
