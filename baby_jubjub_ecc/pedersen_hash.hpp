//
// Created by hcy_ray on 10/23/19.
//
#ifndef PEDSEN_HASH_HPP_
#define PEDSEN_HASH_HPP_
#include <cassert>
#include <memory>
#include "pedersen_commitment.hpp"
#include <libsnark/gadgetlib1/gadget.hpp>




using namespace libsnark;

template<typename FieldT>
class  pedersen_hash : public gadget<FieldT> {

private:
    pb_variable_array<FieldT> m;
    pb_variable_array<FieldT> r;
    pb_variable<FieldT> left_x;
    pb_variable<FieldT> left_y;
    pb_variable<FieldT> right_x;
    pb_variable<FieldT> right_y;
    pb_variable<FieldT> m_var;
    pb_variable<FieldT> r_var;
    pb_variable<FieldT> a;
    pb_variable<FieldT> d;
    std::shared_ptr<pedersen_commitment<FieldT>> commit;
    std::shared_ptr<pointAddition<FieldT>> hash_pointAddition;
    //pb_variable<FieldT> res_x;
    //pb_variable<FieldT> res_y;
public:

    pedersen_hash(protoboard<FieldT> &pb, const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
            const pb_variable<FieldT> &left_x,
            const pb_variable<FieldT> &left_y,
            const pb_variable<FieldT> &right_x,
            const pb_variable<FieldT> &right_y
            );
    pb_variable<FieldT> get_res_x();
    pb_variable<FieldT> get_res_y();

    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += 1; // left x
        acc += 1; // left y
        acc += 1; // right x
        acc += 1; // right y

        return acc;
    }
};





#include "pedersen_hash.cpp"
#endif