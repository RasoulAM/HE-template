#ifndef __SERVER__H
#define __SERVER__H

#include "seal/seal.h"
#include "utils.h"

class Server {
public:
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    seal::EncryptionParameters* enc_params;
    seal::SEALContext* context;

    seal::Evaluator* evaluator;
    seal::RelinKeys* rlk_keys_server;
    seal::GaloisKeys* gal_keys_server;
    seal::PublicKey* public_key;
    seal::Encryptor* encryptor;
    seal::BatchEncoder* batch_encoder;

    // Requires secret key
    // Only available in debug mode
    seal::Decryptor* noise_calculator;
        
    void initialize(uint64_t poly_modulus_degree = 8192);
    void initialize_params_with_input(stringstream& parms_stream);
    void load_parameters_and_keys(stringstream& params_stream, bool debug_mode=false, bool _verbose=true);
    vector<seal::Ciphertext> load_inputs(stringstream& data_stream, int num_input_cts);
    void send_results(vector<seal::Ciphertext>& results, stringstream& data_stream);
    void do_server_computation(stringstream& data_stream, int num_input_cts, Metrics* metrics, bool);

};

#endif
