#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "gadget.hpp"
#include "util.hpp"
#include "mul_cmp.hpp"

using namespace libsnark;
using namespace std;
int main()
{
     typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

  // Initialize the curve parameters

    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    vector<int> test_s;
    vector<int> new_s;
    test_s.push_back(1);
    test_s.push_back(2);
    new_s = vector<int>{test_s.begin(), test_s.begin()+1};
    //cout << new_s <<endl;

    pb_variable<FieldT> x;
    pb_variable<FieldT> result;
    x.allocate(pb, "x");
    result.allocate(pb, "final result");
    pb.set_input_sizes(1);
    mul_cmp_gadget<FieldT> mulCmp(pb, x, result, "mul_cmp");
    mulCmp.generate_r1cs_constraints();

    pb.val(x) = FieldT(25);

    mulCmp.generate_r1cs_witness();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    cout << "result:" << endl;
    bool c1 = pb.val(result) == FieldT::one();
    cout << c1 << endl;

    cout << pb.is_satisfied() << endl;
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    //cout << "Primary (public) input: " << pb.primary_input() << endl;
    //cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;
    return 0;
    }
