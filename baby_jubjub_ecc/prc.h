#ifndef _HPC_H_
#define _HPC_H_

#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void prc_initialize();

// pedersen commitment
void prc_prove_hpc(
        void *output_proof_ptr,
        ulong m_ulong,
        ulong r_ulong,
        char *comm_x,
        char *comm_y,
        int id
);
bool prc_verify_hpc(
        void *proof_ptr,
        char *comm_x,
        char *comm_y,
        int id
);
void prc_paramgen_hpc(int id);


//leader proof
void prc_prove_lp(
        void *output_proof_ptr,
        ulong sn_m,
        ulong sn_r,
        char* sn_comm_x,
        char* sn_comm_y,
        char* T,
        ulong rep_m,
        ulong rep_r,
        char* rep_comm_x,
        char* rep_comm_y,
        char* block_hash,
        int sl,
        int id
);
bool prc_verify_lp(
        void *output_proof_ptr,
        char* sn_comm_x,
        char* sn_comm_y,
        char* T,
        char* rep_comm_x,
        char* rep_comm_y,
        char* block_hash,
        int sl,
        int id
);
void prc_paramgen_lp(int id);


//merkle proof
void prc_prove_iup(
        void *output_proof_ptr, int depth,
        bool in_id_address_bits[], char* id_leaft_x, char* id_leaf_y,
        char* id_root_x, char* id_root_y, char* in_id_path[],
        bool in_rep_address_bits[], char* rep_leaf_x, char * rep_leaf_y,
        char* rep_root_x, char* root_rep_y, char* in_rep_path[],
        ulong id_m, ulong id_r, char* id_x, char* id_y,
        ulong rep_m, ulong rep_r, char* rep_x, char* rep_y,
        int id
);
bool prc_verify_iup(
        void *proof_ptr,
        char* old_id_root_x, char* old_id_root_y,
        char* old_rep_root_x, char* old_rep_root_y,
        char* new_id_x, char* new_id_y,
        char* new_rep_x, char* new_rep_y,
        int id
);
void prc_paramgen_iup(int id, int depth);


#ifdef __cplusplus
}
#endif

#endif