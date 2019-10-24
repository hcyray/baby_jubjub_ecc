#ifndef ETHSNARKS_MERKLE_TREE_HPP_
#define ETHSNARKS_MERKLE_TREE_HPP_

#include "baby_jubjub_ecc.hpp"


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
class merkle_path_selector : public GadgetT
{
public:
    const VariableT m_input_x;
    const VariableT m_input_y;
    const VariableT m_pathvar_x;
    const VariableT m_pathvar_y;
    const VariableT m_is_right;

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


const VariableArrayT merkle_tree_IVs (ProtoboardT &in_pb);


template<typename HashT>
class markle_path_compute : public GadgetT
{
public:
    const size_t m_depth;
    const VariableArrayT m_address_bits;
    const VariableT m_leaf_x;
    const VariableT m_leaf_y;
    const VariableArrayT m_path;

    std::vector<merkle_path_selector> m_selectors;
    std::vector<HashT> m_hashers;

    markle_path_compute(
        ProtoboardT &in_pb,
        const size_t in_depth,
        const VariableArrayT& in_address_bits,
        const VariableT in_leaf_x,
        const VariableT in_leaf_y,
        const VariableArrayT& in_path,
        const std::string &in_annotation_prefix
    ) :
        GadgetT(in_pb, in_annotation_prefix),
        m_depth(in_depth),
        m_address_bits(in_address_bits),
        m_leaf_x(in_leaf_x),
        m_leaf_y(in_leaf_y),
        m_path(in_path)
    {
        assert( in_depth > 0 );
        assert( in_address_bits.size() == in_depth );
        //assert( in_IVs.size() >= in_depth * 2 );

        for( size_t i = 0; i < m_depth; i++ )
        {
            if( i == 0 )
            {
                m_selectors.push_back(
                    merkle_path_selector(
                        in_pb, in_leaf_x, in_leaf_y, in_path[0], in_path[1], in_address_bits[i],
                        FMT(this->annotation_prefix, ".selector[%zu]", i)));
            }
            else {
                m_selectors.push_back(
                    merkle_path_selector(
                        in_pb, m_hashers[i-1].get_res_x(), m_hashers[i-1].get_res_y(), in_path[i*2], in_path[i*2+1], in_address_bits[i],
                        FMT(this->annotation_prefix, ".selector[%zu]", i)));
            }

            auto t = HashT(
                    in_pb, m_selectors[i].left_x(),m_selectors[i].left_y(), m_selectors[i].right_x(),m_selectors[i].right_y(),
                    FMT(this->annotation_prefix, ".hasher[%zu]", i));
            m_hashers.push_back(t);
        }
    }

    const VariableT result_x() const
    {
        assert( m_hashers.size() > 0 );

        return m_hashers.back().get_res_x();
    }

    const VariableT result_y() const
    {
        assert( m_hashers.size() > 0 );

        return m_hashers.back().get_res_y();
    }


    void generate_r1cs_constraints()
    {
        size_t i;
        for( i = 0; i < m_hashers.size(); i++ )
        {
            m_selectors[i].generate_r1cs_constraints();
            m_hashers[i].generate_r1cs_constraints();
        }
    }

    void generate_r1cs_witness() const
    {
        size_t i;
        for( i = 0; i < m_hashers.size(); i++ )
        {
            m_selectors[i].generate_r1cs_witness();
            m_hashers[i].generate_r1cs_witness();
        }
    }
};


/**
* Merkle path authenticator, verifies computed root matches expected result
*/
template<typename HashT>
class merkle_path_authenticator : public markle_path_compute<HashT>
{
public:
    const VariableT m_expected_root_x;
    const VariableT m_expected_root_y;
    merkle_path_authenticator(
        ProtoboardT &in_pb,
        const size_t in_depth,
        const VariableArrayT in_address_bits,
        const VariableT in_leaf_x,
        const VariableT in_leaf_y,
        const VariableT in_expected_root_x,
        const VariableT in_expected_root_y,
        const VariableArrayT in_path,
        const std::string &in_annotation_prefix
    ) :
        markle_path_compute<HashT>::markle_path_compute(in_pb, in_depth, in_address_bits, in_leaf_x, in_leaf_y, in_path, in_annotation_prefix),
        m_expected_root_x(in_expected_root_x),
        m_expected_root_y(in_expected_root_y)
    { }
    /*
    bool is_valid() const
    {
        return this->pb.val(this->result()) == this->pb.val(m_expected_root);
    }
*/
    void generate_r1cs_constraints()
    {
        markle_path_compute<HashT>::generate_r1cs_constraints();

        // Ensure root matches calculated path hash
        this->pb.add_r1cs_constraint(
            ConstraintT(this->result_x(), 1, m_expected_root_x),
            FMT(this->annotation_prefix, ".expected_root_x authenticator"));
        this->pb.add_r1cs_constraint(
                ConstraintT(this->result_y(), 1, m_expected_root_y),
                FMT(this->annotation_prefix, ".expected_root_y authenticator"));
    }
};




// ETHSNARKS_MERKLE_TREE_HPP_
#endif
#include <merkle_tree.cpp>