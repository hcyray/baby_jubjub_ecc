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


#ifdef __cplusplus
}
#endif

#endif