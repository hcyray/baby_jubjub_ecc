#include<hpc.h>

#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "baby_jubjub.hpp"
#include "eddsa.hpp"
#include "pedersen_commitment.hpp"
#include <iostream>
#include <depends/libsnark/libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
using namespace std;
using namespace libsnark;
using namespace libff;
typedef libff::Fr<ppT> FieldT;


// test inputs taken from ../test/test_pedersen.py
template<typename ppT>


void hpc_initialize(){
    libff::alt_bn128_pp::init_public_params();
}

void hpc_prove(void *output_proof_ptr){
    protoboard<FieldT> pb;
    std::shared_ptr<pedersen_commitment<FieldT>> jubjub_pedersen_commitment;
    pb_variable<FieldT> base_x;
    pb_variable<FieldT> base_y;

    pb_variable<FieldT> a;
    pb_variable<FieldT> d;
    //public key
    pb_variable<FieldT> h_x;
    pb_variable<FieldT> h_y;

    pb_variable<FieldT> commitment_x;
    pb_variable<FieldT> commitment_y;


    base_x.allocate(pb, "base x");
    base_y.allocate(pb, "base y");

    h_x.allocate(pb, "h_x");
    h_y.allocate(pb, "h_y");


    a.allocate(pb, "a");
    d.allocate(pb, "d");

    commitment_x.allocate(pb, "r_x");
    commitment_y.allocate(pb, "r_y");





    pb.val(base_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(base_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    pb.val(h_x) = FieldT("16540640123574156134436876038791482806971768689494387082833631921987005038935");
    pb.val(h_y) = FieldT("20819045374670962167435360035096875258406992893633759881276124905556507972311");


    pb.val(commitment_x) = FieldT("8010604480252997578874361183087746053332521656016812693508547791817401879458");
    pb.val(commitment_y) = FieldT("15523586168823793714775329447481371860621135473088351041443641753333446779329");


    pb_variable_array<FieldT> m;
    pb_variable_array<FieldT> r;

    m.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));

    r.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));


    m.fill_with_bits(pb,  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1});

    r.fill_with_bits(pb, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1});


    jubjub_pedersen_commitment.reset(new pedersen_commitment<FieldT> (pb,a,d, base_x, base_y, h_x, h_y,commitment_x, commitment_y,m, r));
    jubjub_pedersen_commitment->generate_r1cs_constraints();
    jubjub_pedersen_commitment->generate_r1cs_witness();
}



void test_pedersen() {


    //const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    //const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);
    const r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(constraint_system);

    //const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    const r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    //bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    bool verified = r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, pb.primary_input(), proof);

    cout << pb.is_satisfied() << endl;
    cout << "Number of R1CS constraints: " << pb.num_constraints() << endl;
    //cout << "Primary (public) input: " << pb.primary_input() << endl;
    //cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;
}
