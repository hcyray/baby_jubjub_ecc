#ifndef ETHSNARKS_HPP_
#define ETHSNARKS_HPP_

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>




typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef libsnark::r1cs_constraint<FieldT> ConstraintT;
typedef libsnark::protoboard<FieldT> ProtoboardT;
typedef libsnark::pb_variable<libff::Fr<ppT>> VariableT;
typedef libsnark::pb_variable_array<FieldT> VariableArrayT;
typedef libsnark::gadget<libff::Fr<ppT>> GadgetT;





#endif
