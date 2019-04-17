

#ifndef __STRINGSEARCH_H_
#define __STRINGSEARCH_H_


#define MAX_STRINGS 100
#define MAX_CALLERS 128
#define MAX_STRLEN  1024


// the type for the ppp callback fn that can be passed to string search to be called
// whenever a string match is observed
typedef void (*on_ssm_t)(CPUState *env, target_ulong pc, target_ulong addr,
                         uint8_t *matched_string,
                         uint32_t matched_string_length, bool is_write,
                         bool in_memory);

typedef void (*on_string_tainted_t)(CPUState *env, target_ulong pc, target_ulong addr, 
                                  uint8_t *buf, uint32_t matched_string_length, 
                                  uint64_t curr_instr);
#endif
