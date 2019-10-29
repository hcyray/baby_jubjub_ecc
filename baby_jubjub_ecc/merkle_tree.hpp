#ifndef BABY_JUBJUB_MERKLE_TREE_HPP_
#define BABY_JUBJUB_MERKLE_TREE_HPP_

#include "baby_jubjub_ecc.hpp"
#include "pedersen_hash.hpp"
#include <memory>

/**
* Depending on the address bit, output the correct left/right inputs
* for the merkle path authentication hash
*
* 0 = left
* 1 = right
*
* There are two variables which make up each element of the path,
* the `input` and the `pathvar`, the input is the leaf or the
* output from the last hash, and the path var is part of the merkle
* tree path.
*
* The `is_right` parameter decides if the `input` is on the left or
* right of the hash. These are decided in-circuit using the following
* method:
*
* Left:
*  ((1-is_right) * input) + (is_right * pathvar)
*
* Right:
*  (is_right * input) + ((1 - is_right) * pathvar)
*
* Each component is split into a & b sides, then added together
* so the correct variable ends up in the right or left hand side.
*/
using namespace libsnark;


class merkle_path_selector : public GadgetT
{
public:
    VariableT m_input_x;
    VariableT m_input_y;
    VariableT m_pathvar_x;
    VariableT m_pathvar_y;
    VariableT m_is_right;

    VariableT m_left_a_x;
    VariableT m_left_b_x;
    VariableT m_left_x;

    VariableT m_left_a_y;
    VariableT m_left_b_y;
    VariableT m_left_y;

    VariableT m_right_a_x;
    VariableT m_right_b_x;
    VariableT m_right_x;

    VariableT m_right_a_y;
    VariableT m_right_b_y;
    VariableT m_right_y;

    merkle_path_selector(
        ProtoboardT &in_pb,
        const VariableT& in_input_x,
        const VariableT& in_input_y,
        const VariableT& in_pathvar_x,
        const VariableT& in_pathvar_y,
        const VariableT& in_is_right,
        const std::string &in_annotation_prefix
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness() const;

    const VariableT& left_x() const;
    const VariableT& left_y() const;
    const VariableT& right_x() const;
    const VariableT& right_y() const;
};






class markle_path_compute : public GadgetT
{
private:
    std::vector<merkle_path_selector> m_selectors;
    std::vector<std::shared_ptr <pedersen_hash<FieldT>>> m_hashers;
public:
    size_t m_depth;
    VariableArrayT m_address_bits;
    VariableT m_leaf_x;
    VariableT m_leaf_y;
    VariableArrayT m_path;


    markle_path_compute(
        ProtoboardT &in_pb,
        const size_t &in_depth,
        const std::string &in_annotation_prefix
    );

    VariableT result_x();

    VariableT result_y();

    void generate_r1cs_constraints();

    void generate_r1cs_witness(
            const VariableArrayT& in_address_bits,
            const VariableT& in_leaf_x,
            const VariableT& in_leaf_y,
            const VariableArrayT& in_path
            );
};


/**
* Merkle path authenticator, verifies computed root matches expected result
*/

class merkle_path_authenticator : public markle_path_compute
{
public:
    VariableT m_expected_root_x;
    VariableT m_expected_root_y;
    merkle_path_authenticator(
        ProtoboardT &in_pb,
        const size_t& in_depth,
        const std::string &in_annotation_prefix
    );

    bool is_valid();

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
            const VariableArrayT &in_address_bits,
            const VariableT &in_leaf_x,
            const VariableT &in_leaf_y,
            const VariableT &in_expected_root_x,
            const VariableT &in_expected_root_y,
            const VariableArrayT &in_path
            );
    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;
        acc += 1; // expected root commitment x
        acc += 1; // expected root commitment y
        return acc;
    }
};



#include<merkle_tree.cpp>
#endif
