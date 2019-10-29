//
// Created by hcy_ray on 10/29/19.
//

#ifndef BABY_JUBJUB_ECC_LEADER_PROOF_HPP
#define BABY_JUBJUB_ECC_LEADER_PROOF_HPP

#include <cassert>
#include <memory>
#include <libsnark/gadgetlib1/gadget.hpp>

using namespace libsnark;

template<typename FieldT>
class leader_proof:public gadget<FieldT> {
private:
public:

    leader_proof(protoboard<FieldT> &pb, const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;
        acc += 1; // sn commitment x
        acc += 1; // sn commitment y
        return acc;
    }
};

#include "leader_proof.cpp"
#endif //BABY_JUBJUB_ECC_LEADER_PROOF_HPP
