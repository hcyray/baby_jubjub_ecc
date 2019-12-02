#include <iostream>
#include "leader_proof.hpp"
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
using namespace std;

int main () {
    typedef libff::Fr<libff::bn128_pp> FieldT;

    libff::bn128_pp::init_public_params();

    protoboard<FieldT> pb;


    std::shared_ptr<leader_proof<FieldT>> leader;

    FieldT sn_m = FieldT("30000000002");
    FieldT sn_r = FieldT("2");
    FieldT rep_m = FieldT("30000000002");
    FieldT rep_r = FieldT("2");
    FieldT block_hash = FieldT("29852648006495581632639394572552351243421167921610457916422658377040103735296");
    FieldT sl = FieldT("1");
    FieldT avg_rep = FieldT("1");

    FieldT sn_x = FieldT("6468125633283523844081138403201428527072905892236409266890308262966770366270");
    FieldT sn_y = FieldT("15599159073676304331609141418095610264573471298139509244854073578575099976066");
    FieldT rep_x = FieldT("6468125633283523844081138403201428527072905892236409266890308262966770366270");
    FieldT rep_y = FieldT("15599159073676304331609141418095610264573471298139509244854073578575099976066");
    FieldT rn_x = FieldT("13647547311933543444637307980047256750971254683623422165118646954184898163653");
    FieldT rn_y = FieldT("11273894275322725312797439907538424583649707310938481045408412348190690865322");
    FieldT total_rep = FieldT("10");
    size_t d = 0;
    size_t n = 10;
    leader.reset(new leader_proof<FieldT>(pb, d, n, "leader_proof"));
    leader -> generate_r1cs_constraints();
    leader -> generate_r1cs_witness(sn_m, sn_r, sn_x, sn_y, total_rep, rep_m, rep_r, rep_x, rep_y, block_hash, sl, rn_x, rn_y, avg_rep);
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<libff::bn128_pp> keypair = r1cs_ppzksnark_generator<libff::bn128_pp>(constraint_system);

    const r1cs_ppzksnark_proof<libff::bn128_pp> proof = r1cs_ppzksnark_prover<libff::bn128_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::bn128_pp>(keypair.vk, pb.primary_input(), proof);


    cout << pb.is_satisfied() << endl;
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Verification status: " << verified << endl;

    std::stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();
    cout << "proof size :" << proof_str.size() << endl;
    cout <<  pb.primary_input() << endl;
    cout <<"Finish" << endl;

    return 0;

}
