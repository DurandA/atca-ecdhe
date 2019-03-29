#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "cryptoauthlib.h"
#include "basic/atca_basic_aes_gcm.h"

int main()
{
  uint32_t revision;
  uint32_t serial[(ATCA_SERIAL_NUM_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
  bool config_is_locked, data_is_locked;
  ATCA_STATUS status;

  ATCAIfaceCfg cfg = cfg_ateccx08a_i2c_default;
  cfg.atcai2c.bus = 1;
  cfg.atcai2c.baud = 400000;
  cfg.devtype = ATECC608A;

  status = atcab_init(&cfg);
  if (status != ATCA_SUCCESS) {
    printf("ATCA: Library init failed\n");
    goto out;
  }

  status = atcab_info((uint8_t *) &revision);
  if (status != ATCA_SUCCESS) {
    printf("ATCA: Failed to get chip info\n");
    goto out;
  }

  status = atcab_read_serial_number((uint8_t *) serial);
  if (status != ATCA_SUCCESS) {
    printf("ATCA: Failed to get chip serial number\n");
    goto out;
  }

  status = atcab_is_locked(LOCK_ZONE_CONFIG, &config_is_locked);
  status = atcab_is_locked(LOCK_ZONE_DATA, &data_is_locked);
  if (status != ATCA_SUCCESS) {
    printf("ATCA: Failed to get chip zone lock status\n");
    goto out;
  }

  printf("ATECCx08 @ 0x%02x: rev 0x%04x S/N 0x%04x%04x%02x, zone "
     "lock status: %s, %s\n",
     cfg.atcai2c.slave_address >> 1, htonl(revision), htonl(serial[0]), htonl(serial[1]),
     *((uint8_t *) &serial[2]), (config_is_locked ? "yes" : "no"),
     (data_is_locked ? "yes" : "no"));


  uint8_t U[64] = { 0 };
  uint8_t V[64] = { 0 };

  status = atcab_genkey(0, U);
  printf("%02x", status);
  status = atcab_genkey(1, V);
  printf("%02x", status);

  uint8_t E_U[64] = { 0 };
  uint8_t E_V[64] = { 0 };

  status = atcab_genkey(2, E_U);
  printf("%02x", status);
  status = atcab_genkey(3, E_V);
  printf("%02x", status);

  const uint8_t message_V[128];
  memcpy(message_V, E_U, 64 * sizeof(uint8_t));
  memcpy(message_V+64, E_V, 64 * sizeof(uint8_t));
  uint8_t digest_V[32];
  status = atcab_sha(10, message_V, digest_V);
  printf("%02x", status);

  uint8_t signature_V[64];
  status = atcab_sign(1, digest_V, signature_V); // The message to be signed will be loaded into the Message Digest Buffer to the ATECC608A device or TempKey for other devices.
  printf("%02x", status);
  atcab_ecdh_base(ECDH_MODE_COPY_TEMP_KEY, 3, E_U, NULL, NULL);
  printf("%02x", status);

  uint8_t out_kdf_hkdf[32];
  uint8_t data_input_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

  status = atcab_kdf(
      KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_TEMPKEY,
      0x0000, // K_2 stored in slot 4
              // Source key slot is the LSB and target key slot is the MSB.
      KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)sizeof(data_input_16) << 24), /* Actual size
                                      of message is 16 bytes for AES algorithm or is encoded
                                      in the MSB of the details parameter for other
                                      algorithms.*/
      data_input_16,
      out_kdf_hkdf,
      NULL);
  printf("atcab_kdf: %02x\n", status);

  uint8_t iv[12];
  atca_aes_gcm_ctx_t aes_gcm_ctx;
  status = atcab_aes_gcm_init_rand(&aes_gcm_ctx, ATCA_TEMPKEY_KEYID, 0, 12, NULL, 0, iv); /* AES enable bit should be 1 in ATCA_ZONE_CONFIG
                                                                                           https://github.com/MicrochipTech/cryptoauthlib/blob/6919b6d67be78ed998217221a923ea842bbace1a/test/atca_tests_aes.c#L75*/
  const uint8_t *plaintext = "helloworldhellow";
  uint8_t ciphertext[16] = { 0 };
  const uint8_t *aad = "authenticated";
  status = atcab_aes_gcm_aad_update(&aes_gcm_ctx, aad, 13);
  status = atcab_aes_gcm_encrypt_update(&aes_gcm_ctx, plaintext, 16, ciphertext);
  uint8_t tag[12];
  status = atcab_aes_gcm_encrypt_finish(&aes_gcm_ctx, tag, 12);
  printf("atcab_aes_gcm_encrypt_finish: %02x\n", status);

  return 1;

out:
  /*
   * We do not free atca_cfg in case of an error even if it was allocated
   * because it is referenced by ATCA basic object.
   */
  if (status != ATCA_SUCCESS) {
    printf("ATCA: Chip is not available");
    /* In most cases the device can still work, so we continue anyway. */
  }
  return 0;
}
