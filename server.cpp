#include "server.h"

using namespace std;
using namespace seal;

void Server::load_parameters_and_keys(stringstream& params_stream, bool debug_mode, bool _verbose)
{
    this->enc_params = new EncryptionParameters();
    this->enc_params->load(params_stream);

    this->context = new SEALContext(*enc_params);

    this->rlk_keys_server = new RelinKeys();
    this->gal_keys_server = new GaloisKeys();
    this->public_key = new PublicKey();
    this->rlk_keys_server->load(*context, params_stream);
    this->gal_keys_server->load(*context, params_stream);
    this->public_key->load(*context, params_stream);

    this->batch_encoder = new BatchEncoder(*context);
    this->encryptor = new Encryptor(*context, *public_key);
    this->evaluator = new Evaluator(*context);

    if (debug_mode){
        SecretKey secret_key;
        secret_key.load(*context, params_stream);
        this->noise_calculator = new Decryptor(*context, secret_key);
    }
}

vector<Ciphertext> Server::load_inputs(stringstream& data_stream, int num_input_cts){
    vector<Ciphertext> inputs;
    Ciphertext __ct_temp;
    for (int i=0;i<num_input_cts;i++){
        __ct_temp.load(*context, data_stream);
        inputs.push_back(__ct_temp);
    }
    data_stream.str("");
    return inputs;
}

void Server::send_results(vector<Ciphertext>& results, stringstream& data_stream){
    for (int i=0;i<results.size();i++){
        results[i].save(data_stream);
    }
}

void Server::do_server_computation(stringstream& data_stream, int num_input_cts, Metrics* metrics, bool _verbose){
    Timer server_time;
    vector<Ciphertext> inputs = load_inputs(data_stream, num_input_cts);
    
    vector<Ciphertext> results;
    
    server_time.start();

        // Do some stuff here
        // Put the results in 'results'
        // Ciphertext _ct;
        this->evaluator->multiply_inplace(inputs[0], inputs[1]);
        this->evaluator->relinearize_inplace(inputs[0], *rlk_keys_server);
        results.push_back(inputs[0]);

    server_time.end();
    metrics->metrics_["time_server"] = server_time.get_time_in_milliseconds();
    
    send_results(results, data_stream);
}