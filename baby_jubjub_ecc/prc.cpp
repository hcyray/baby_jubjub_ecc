#include "prc.h"
#include <fstream>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include "leader_proof.hpp"
#include "pedersen_commitment.hpp"
#include <iostream>
#include  "identity_proof.hpp"
#include <string.h>
#include "baby_jubjub_ecc.hpp"
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace std;
using namespace libsnark;
using namespace libff;



// prc - private reputation chain zksnark lib




template<typename ppT>
void loadFromFile(std::string path, ppT& objIn) {
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);
    ss << fh.rdbuf();
    fh.close();
    ss.rdbuf()->pubseekpos(0, std::ios_base::in);
    ss >> objIn;
}

template<typename T>
void saveToFile(std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}
/*
void prc_load_shielding_keys() {
    loadFromFile("/keys/shielding.vk", zsl::vkShielding);
    loadFromFile("/keys/shielding.pk", zsl::pkShielding);
}
*/

/*
template<typename ppT>
libff::Fr<ppT> get_field_element_from_bits(pb_variable_array<libff::Fr<ppT>> *x, const protoboard<libff::Fr<ppT>> &pb) {
    typedef libff::Fr<ppT> FieldT;
    FieldT result = FieldT::zero();
    for (size_t i = 0; i < 253; ++i)
    {
        const FieldT v = pb.val((*x)[i]);
        assert(v == FieldT::zero() || v == FieldT::one());
        result += result + v;
    }
    return result;
}
*/
libff::bit_vector setbits(ulong x){
    libff::bit_vector bits(253,0);
    int i = 252;
    while (x > 0) {
        bits[i] = x & 1;
        x = x >> 1;
        i--;
    }
    return bits;
}

void prc_initialize(){
    libff::alt_bn128_pp::init_public_params();
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;

}

bool prc_verify_hpc(void *proof_ptr, char *comm_x, char *comm_y, int id) {
    unsigned char *proof = reinterpret_cast<unsigned char *>(proof_ptr);
    //input proof
    std::vector<unsigned char> proof_v(proof, proof+312);
    std::stringstream proof_data;
    for (int i = 0; i < 312; i++) {
        proof_data << proof_v[i];
    }
    assert(proof_data.str().size() == 312);
    proof_data.rdbuf()->pubseekpos(0, std::ios_base::in);
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof_obj;
    proof_data >> proof_obj;

    // Add commitment value
    r1cs_primary_input<FieldT> witness_map;
    witness_map.insert(witness_map.end(), FieldT(comm_x));
    witness_map.insert(witness_map.end(), FieldT(comm_y));

    r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> verification_key;
    loadFromFile<r1cs_ppzksnark_verification_key<ppT>>(to_string(id) + "_hpc.vk", verification_key);
    return r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(verification_key, witness_map, proof_obj);
}


void prc_prove_hpc(void *output_proof_ptr, ulong m_ulong, ulong r_ulong, char* comm_x, char* comm_y, int id){
    unsigned char *output_proof = reinterpret_cast<unsigned char *>(output_proof_ptr);
    protoboard<FieldT> pb;
    out_pedersen_commitment<FieldT> g(pb,"pedersen commitment");
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(FieldT(comm_x), FieldT(comm_y), FieldT(m_ulong), FieldT(r_ulong));

    assert(pb.is_satisfied());

    r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> proving_key;
    loadFromFile<r1cs_ppzksnark_proving_key<ppT>>(to_string(id) + "_hpc.pk", proving_key);

    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(proving_key, pb.primary_input(), pb.auxiliary_input());
    std::stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();
    assert(proof_str.size() == 312);
    for (int i = 0; i < 312; i++) {
        output_proof[i] = proof_str[i];
    }
}

void prc_paramgen_hpc(int id) {
    protoboard<FieldT> pb;
    out_pedersen_commitment<FieldT> g(pb,"pedersen commitment");
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    auto crs = r1cs_ppzksnark_generator<ppT>(constraint_system);

    saveToFile<r1cs_ppzksnark_proving_key<ppT>>(to_string(id) + "_hpc.pk", crs.pk);
    saveToFile<r1cs_ppzksnark_verification_key<ppT>>(to_string(id) + "_hpc.vk", crs.vk);

}






bool prc_verify_lp(void *proof_ptr, char* sn_comm_x, char* sn_comm_y, char* T,
                   char* rep_comm_x, char* rep_comm_y, char* block_hash, int sl, int id) {
    unsigned char *proof = reinterpret_cast<unsigned char *>(proof_ptr);
    //input proof
    std::vector<unsigned char> proof_v(proof, proof+312);
    std::stringstream proof_data;
    for (int i = 0; i < 312; i++) {
        proof_data << proof_v[i];
    }
    assert(proof_data.str().size() == 312);
    proof_data.rdbuf()->pubseekpos(0, std::ios_base::in);
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof_obj;
    proof_data >> proof_obj;

    // Add witness value
    r1cs_primary_input<FieldT> witness_map;
    witness_map.insert(witness_map.end(), FieldT(block_hash));
    witness_map.insert(witness_map.end(), FieldT(sl));
    witness_map.insert(witness_map.end(), FieldT(T));
    witness_map.insert(witness_map.end(), FieldT(sn_comm_x));
    witness_map.insert(witness_map.end(), FieldT(sn_comm_y));
    witness_map.insert(witness_map.end(), FieldT(rep_comm_x));
    witness_map.insert(witness_map.end(), FieldT(rep_comm_y));

    r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> verification_key;
    loadFromFile<r1cs_ppzksnark_verification_key<ppT>>(to_string(id) + "_lp.vk", verification_key);
    return r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(verification_key, witness_map, proof_obj);
}


void prc_prove_lp(void *output_proof_ptr, ulong sn_m, ulong sn_r, char* sn_comm_x, char* sn_comm_y, char* T,
        ulong rep_m, ulong rep_r, char* rep_comm_x, char* rep_comm_y, char* block_hash, int sl, int id){
    unsigned char *output_proof = reinterpret_cast<unsigned char *>(output_proof_ptr);
    protoboard<FieldT> pb;
    leader_proof<FieldT> g(pb,"pedersen commitment");
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(FieldT(sn_m), FieldT(sn_r), FieldT(sn_comm_x), FieldT(sn_comm_y), FieldT(T),
            FieldT(rep_m), FieldT(rep_r), FieldT(rep_comm_x), FieldT(rep_comm_y),FieldT(block_hash),FieldT(sl));

    assert(pb.is_satisfied());

    r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> proving_key;
    loadFromFile<r1cs_ppzksnark_proving_key<ppT>>(to_string(id) + "_lp.pk", proving_key);

    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(proving_key, pb.primary_input(), pb.auxiliary_input());
    std::stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();
    assert(proof_str.size() == 312);
    for (int i = 0; i < 312; i++) {
        output_proof[i] = proof_str[i];
    }
}

void prc_paramgen_lp(int id) {
    protoboard<FieldT> pb;
    leader_proof<FieldT> g(pb,"pedersen commitment");
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    auto crs = r1cs_ppzksnark_generator<ppT>(constraint_system);

    saveToFile<r1cs_ppzksnark_proving_key<ppT>>(to_string(id) + "_lp.pk", crs.pk);
    saveToFile<r1cs_ppzksnark_verification_key<ppT>>(to_string(id) + "_lp.vk", crs.vk);

}
