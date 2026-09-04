#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void zunia_string_free(char *ptr);
char *zunia_kernel_version(void);
char *zunia_generate_mnemonic(uint32_t words);
char *zunia_seal_keyring(const char *phrase, const char *password, const char *metadata_json);
char *zunia_open_keyring(const char *envelope_json, const char *password);
char *zunia_derive_address(const char *phrase, const char *passphrase, const char *chain_json, uint32_t account_index);
char *zunia_sign_cosmos(const char *phrase, const char *passphrase, const char *chain_json, uint32_t account_index, const char *sign_bytes_hex);
char *zunia_decode_direct_tx(const char *sign_doc_hex);
char *zunia_build_bank_send_direct(
  const char *chain_id, const char *from, const char *to, const char *amount, const char *denom,
  const char *memo, uint64_t account_number, uint64_t sequence, const char *fee_amount,
  const char *fee_denom, uint64_t gas_limit, const char *public_key_hex, uint8_t eth_key_type
);

#ifdef __cplusplus
}
#endif
