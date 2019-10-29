// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "baby_jubjub_ecc.hpp"



merkle_path_selector::merkle_path_selector(
    ProtoboardT &in_pb,
    const VariableT& in_input_x,
    const VariableT& in_input_y,
    const VariableT& in_pathvar_x,
    const VariableT& in_pathvar_y,
    const VariableT& in_is_right,
    const std::string &in_annotation_prefix
) :
    GadgetT(in_pb, in_annotation_prefix),
    m_input_x(in_input_x),
    m_input_y(in_input_y),
    m_pathvar_x(in_pathvar_x),
    m_pathvar_y(in_pathvar_y),
    m_is_right(in_is_right)
{
    m_left_a_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_a_x"));
    m_left_b_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_b_x"));
    m_left_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_x"));

    m_left_a_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_a_y"));
    m_left_b_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_b_y"));
    m_left_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_y"));

    m_right_a_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_a_x"));
    m_right_b_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_b_x"));
    m_right_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_x"));

    m_right_a_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_a_y"));
    m_right_b_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_b_y"));
    m_right_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_y"));
}

void merkle_path_selector::generate_r1cs_constraints()
{
    // left x commitment
    this->pb.add_r1cs_constraint(
        ConstraintT(1 - m_is_right, m_input_x, m_left_a_x),
        FMT(this->annotation_prefix, "1-is_right_x * input_x = left_a_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_pathvar_x, m_left_b_x),
        FMT(this->annotation_prefix, "is_right * pathvar_x = left_b_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_left_a_x + m_left_b_x, 1, m_left_x),
        FMT(this->annotation_prefix, "1 * left_a_x + left_b_x = left_x"));

    // left y commitment
    this->pb.add_r1cs_constraint(
            ConstraintT(1 - m_is_right, m_input_y, m_left_a_y),
            FMT(this->annotation_prefix, "1-is_right_y * input_y = left_a_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_pathvar_y, m_left_b_y),
                                 FMT(this->annotation_prefix, "is_right * pathvar_y = left_b_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_left_a_y + m_left_b_y, 1, m_left_y),
                                 FMT(this->annotation_prefix, "1 * left_a_y + left_b_y = left_y"));

    // right x commitment
    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_input_x, m_right_a_x),
        FMT(this->annotation_prefix, "is_right * input_x = right_a_x"));

    this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_pathvar_x, m_right_b_x),
        FMT(this->annotation_prefix, "1-is_right * pathvar_x = right_b_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_right_a_x + m_right_b_x, 1, m_right_x),
        FMT(this->annotation_prefix, "1 * right_a_x + right_b_x = right_x"));

    // right y commitment
    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_input_y, m_right_a_y),
                                 FMT(this->annotation_prefix, "is_right * input_y = right_a_y"));

    this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_pathvar_y, m_right_b_y),
                                 FMT(this->annotation_prefix, "1-is_right * pathvar_y = right_b_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_right_a_y + m_right_b_y, 1, m_right_y),
                                 FMT(this->annotation_prefix, "1 * right_a_y + right_b_y = right_y"));


}

void merkle_path_selector::generate_r1cs_witness() const
{
    this->pb.val(m_left_a_x) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_input_x);
    this->pb.val(m_left_b_x) = this->pb.val(m_is_right) * this->pb.val(m_pathvar_x);
    this->pb.val(m_left_x) = this->pb.val(m_left_a_x) + this->pb.val(m_left_b_x);

    this->pb.val(m_left_a_y) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_input_y);
    this->pb.val(m_left_b_y) = this->pb.val(m_is_right) * this->pb.val(m_pathvar_y);
    this->pb.val(m_left_y) = this->pb.val(m_left_a_y) + this->pb.val(m_left_b_y);

    this->pb.val(m_right_a_x) = this->pb.val(m_is_right) * this->pb.val(m_input_x);
    this->pb.val(m_right_b_x) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_pathvar_x);
    this->pb.val(m_right_x) = this->pb.val(m_right_a_x) + this->pb.val(m_right_b_x);

    this->pb.val(m_right_a_y) = this->pb.val(m_is_right) * this->pb.val(m_input_y);
    this->pb.val(m_right_b_y) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_pathvar_y);
    this->pb.val(m_right_y) = this->pb.val(m_right_a_y) + this->pb.val(m_right_b_y);
}

const VariableT& merkle_path_selector::left_x() const {
    return m_left_x;
}
const VariableT& merkle_path_selector::left_y() const {
    return m_left_y;
}
const VariableT& merkle_path_selector::right_x() const {
    return m_right_x;
}
const VariableT& merkle_path_selector::right_y() const {
    return m_right_y;
}


markle_path_compute:: markle_path_compute(
            ProtoboardT &in_pb,
            const size_t& in_depth,
            const std::string &in_annotation_prefix
    ) :
            GadgetT(in_pb, in_annotation_prefix),
            m_depth(in_depth)
    {
        assert( in_depth > 0 );
        assert( in_address_bits.size() == in_depth );
        //assert( in_IVs.size() >= in_depth * 2 );
        m_address_bits.allocate(pb, m_depth, FMT(annotation_prefix, "address_bit"));
        m_leaf_x.allocate(pb, FMT(annotation_prefix, "leaf_x"));
        m_leaf_y.allocate(pb, FMT(annotation_prefix, "leaf_x"));
        m_path.allocate(pb, m_depth*2, FMT(annotation_prefix, "path"));
        for( size_t i = 0; i < m_depth; i++ )
        {
            if( i == 0 )
            {
                m_selectors.emplace_back(
                                in_pb, m_leaf_x, m_leaf_y, m_path[0], m_path[1], m_address_bits[i],
                                FMT(this->annotation_prefix, ".selector[%zu]", i));
            }
            else {
                m_selectors.emplace_back(
                                in_pb, m_hashers[i-1]->get_res_x(), m_hashers[i-1]->get_res_y(), m_path[i*2], m_path[i*2+1], m_address_bits[i],
                                FMT(this->annotation_prefix, ".selector[%zu]", i));
            }

            m_hashers.emplace_back(new pedersen_hash<FieldT>(in_pb,  FMT(this->annotation_prefix, ".hasher[%zu]", i)));
        }
    }


VariableT markle_path_compute::result_x(){
        assert( m_hashers.size() > 0 );

        return m_hashers.back()->get_res_x();
    }


VariableT markle_path_compute::result_y() {
    assert( m_hashers.size() > 0 );
    return m_hashers.back()->get_res_y();
}


void markle_path_compute::generate_r1cs_constraints()
{
    size_t i;
    for( i = 0; i < m_hashers.size(); i++ )
    {
        m_selectors[i].generate_r1cs_constraints();
        m_hashers[i]->generate_r1cs_constraints();
    }
}

void markle_path_compute::generate_r1cs_witness(
        const VariableArrayT& in_address_bits,
        const VariableT& in_leaf_x,
        const VariableT& in_leaf_y,
        const VariableArrayT& in_path
        )
{
    m_address_bits.fill_with_field_elements(pb, in_address_bits.get_vals(pb));
    pb.val(m_leaf_x) = pb.val(in_leaf_x);
    pb.val(m_leaf_y) = pb.val(in_leaf_y);
    m_path.fill_with_field_elements(pb, in_path.get_vals(pb));
    size_t i;
    for( i = 0; i < m_hashers.size(); i++ )
    {
        m_selectors[i].generate_r1cs_witness();
        m_hashers[i]->generate_r1cs_witness(m_selectors[i].left_x(),m_selectors[i].left_y(),
                                            m_selectors[i].right_x(),m_selectors[i].right_y());
    }

//    Debug
//    for( i = 0; i < m_hashers.size(); i++ )
//    {
//        std::cout << this->pb.val(m_hashers[i]->get_res_x()) << std::endl;
//        std::cout << this->pb.val(m_hashers[i]->get_res_y()) << std::endl;
//    }
//
//    for( i = 0; i < m_selectors.size(); i++ )
//    {
//        std::cout << "i:" <<i << std::endl;
//        std::cout << this->pb.val(m_selectors[i].left_x()) << std::endl;
//        std::cout << this->pb.val(m_selectors[i].left_y()) << std::endl;
//        std::cout << this->pb.val(m_selectors[i].right_x()) << std::endl;
//        std::cout << this->pb.val(m_selectors[i].right_y()) << std::endl;
//    }
}



/**
* Merkle path authenticator, verifies computed root matches expected result
*/

merkle_path_authenticator::merkle_path_authenticator(
            ProtoboardT &in_pb,
            const size_t& in_depth,
            const std::string &in_annotation_prefix
    ) :
            markle_path_compute::markle_path_compute(in_pb, in_depth, in_annotation_prefix)
    {
        m_expected_root_x.allocate(pb,FMT(in_annotation_prefix, "expected root x"));
        m_expected_root_y.allocate(pb,FMT(in_annotation_prefix, "expected root y"));
    }

bool merkle_path_authenticator::is_valid()
{
    bool flag = true;
    if (this->pb.val(this->result_x()) != this->pb.val(m_expected_root_x) ||
        this->pb.val(this->result_y()) != this->pb.val(m_expected_root_y)){
        flag = false;
    }
    return flag;
}

void merkle_path_authenticator::generate_r1cs_constraints()
{
    markle_path_compute::generate_r1cs_constraints();

    // Ensure root matches calculated path hash
    this->pb.add_r1cs_constraint(
            ConstraintT(this->result_x(), 1, m_expected_root_x),
            FMT(this->annotation_prefix, ".expected_root_x authenticator"));
    this->pb.add_r1cs_constraint(
            ConstraintT(this->result_y(), 1, m_expected_root_y),
            FMT(this->annotation_prefix, ".expected_root_y authenticator"));
}

void merkle_path_authenticator::generate_r1cs_witness(
        const VariableArrayT &in_address_bits, const VariableT &in_leaf_x, const VariableT &in_leaf_y,
        const VariableT &in_expected_root_x, const VariableT &in_expected_root_y, const VariableArrayT &in_path)
{
    markle_path_compute::generate_r1cs_witness(in_address_bits, in_leaf_x, in_leaf_y, in_path);
    pb.val(m_expected_root_x) = pb.val(in_expected_root_x);
    pb.val(m_expected_root_y) = pb.val(in_expected_root_y);
}

