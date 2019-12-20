//
// Created by hcy_ray on 10/11/19.
//

#ifndef BABY_JUBJUB_POW_PROOF_HPP
#define BABY_JUBJUB_POW_PROOF_HPP


#include <cassert>
#include <memory>
#include "pedersen_hash.hpp"
#include <libsnark/gadgetlib1/gadget.hpp>
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
using namespace libsnark;

template<typename FieldT>
class pow_proof : public gadget<FieldT> {
private:
    /* no internal variables */
    size_t n_cmp;
    pb_variable<FieldT>     rep;
    pb_variable<FieldT>     target;
    pb_variable<FieldT>     nonce;
    pb_variable_array<FieldT> rep_T;
    pb_variable_array<FieldT> diff_T;
    pb_variable_array<FieldT> rep_relation;
    pb_variable_array<FieldT> diff_relation;
    pb_variable_array<FieldT> rep_m;
    pb_variable_array<FieldT> rep_r;
    std::shared_ptr<pedersen_commitment<FieldT>> repCommit;
    std::vector<std::shared_ptr<comparison_gadget<FieldT>>> cmp_rep;
    std::vector<std::shared_ptr<comparison_gadget<FieldT>>> cmp_diff;
    std::shared_ptr<pedersen_hash<FieldT>> target_hash;
public:
    pb_variable<FieldT> rep_x;
    pb_variable<FieldT> rep_y;
    pb_variable<FieldT> block;

    pow_proof(protoboard<FieldT> &pb, const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness(const FieldT &in_rep_m, const FieldT &in_rep_r,
                               const FieldT &rep_commit_x, const FieldT &rep_commit_y,
                               const FieldT &nonce, const FieldT &block);

    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }
    static size_t verifying_input_bit_size() {
        size_t acc = 0;
        acc += 253; // rep x
        acc += 253; // rep y
        acc += 253; // block
        return acc;
    }
};


#include "pow_proof.cpp"

#endif