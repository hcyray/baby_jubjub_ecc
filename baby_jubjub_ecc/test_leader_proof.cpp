#include <iostream>
#include "leader_proof.hpp"
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
using namespace std;

int main () {
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;

    libff::alt_bn128_pp::init_public_params();

    protoboard<FieldT> pb;


    std::shared_ptr<leader_proof<FieldT>> leader;

    FieldT sn_m = FieldT("2");
    FieldT sn_r = FieldT("2");
    FieldT rep_m = FieldT("2");
    FieldT rep_r = FieldT("2");
    FieldT block_hash = FieldT("1234");
    FieldT sl = FieldT("1");


    FieldT sn_x = FieldT("18517123153863469553573384572371536953407444696640934598826194274645946323334");
    FieldT sn_y = FieldT("16366639365004517936716040800897479058579589069997927276858356063876961184474");
    FieldT rep_x = FieldT("18517123153863469553573384572371536953407444696640934598826194274645946323334");
    FieldT rep_y = FieldT("16366639365004517936716040800897479058579589069997927276858356063876961184474");
    FieldT rn_x = FieldT("17340275048943653547614489228527344381464164653252141404090367775488601412428");
    FieldT rn_y = FieldT("933123352423928023129012374387605308470368372720613198607919169954889220173");
    FieldT total_rep = FieldT("10");
    size_t d = 3;
    size_t n = 10;
    leader.reset(new leader_proof<FieldT>(pb, d, n, "leader_proof"));
    leader -> generate_r1cs_constraints();
    leader -> generate_r1cs_witness(sn_m, sn_r, sn_x, sn_y, total_rep, rep_m, rep_r, rep_x, rep_y, block_hash, sl, rn_x, rn_y);
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = r1cs_ppzksnark_generator<libff::alt_bn128_pp>(constraint_system);

    const r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool verified = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(keypair.vk, pb.primary_input(), proof);


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
