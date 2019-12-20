#include <iostream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include "pow_proof.hpp"

using namespace std;
int main()
{
    typedef libff::Fr<libff::bn128_pp> FieldT;

    libff::bn128_pp::init_public_params();


    protoboard<FieldT> pb;
    FieldT rep_m = FieldT("2");
    FieldT rep_r = FieldT("2");
    FieldT block = FieldT("1234");
    FieldT nonce = FieldT("1");
    FieldT rep_x = FieldT("18517123153863469553573384572371536953407444696640934598826194274645946323334");
    FieldT rep_y = FieldT("16366639365004517936716040800897479058579589069997927276858356063876961184474");

    pb.set_input_sizes(1);
    pow_proof<FieldT> powProof(pb, "mul_cmp");
    powProof.generate_r1cs_constraints();
    powProof.generate_r1cs_witness(rep_m, rep_r, rep_x, rep_y, nonce, block);
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
