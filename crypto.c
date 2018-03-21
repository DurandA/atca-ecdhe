#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "cryptoauthlib.h"

int main()
{
  uint32_t revision;
  uint32_t serial[(ATCA_SERIAL_NUM_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
  bool config_is_locked, data_is_locked;
  ATCA_STATUS status;

  ATCAIfaceCfg cfg = cfg_ateccx08a_i2c_default;
  cfg.atcai2c.bus = 1;
  cfg.atcai2c.baud = 400000;

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

  uint8_t random_number[32] = {0};
  status = atcab_random(random_number);  // get a random number from the chip
  printf("Random number: ");
  for (int i=0; i<32; i++)
    printf("%02x", random_number[i]);
  printf("\n");

  uint8_t const *message = "helloworld";
  uint8_t digest[32] = {0};
  status = atcab_sha(10, message, digest);
  printf("Digest of %s is: ", message);
  for (int i=0; i<32; i++)
    printf("%02x", digest[i]);
  printf("\n");

  uint8_t public_key[64] = { 0 };
  status = atcab_genkey(0, public_key);
  printf("Generated public key is: {X:");
  for (int i=0; i<32; i++)
    printf("%02x", public_key[i]);
  printf(", Y:");
  for (int i=0; i<32; i++)
    printf("%02x", public_key[32+i]);
  printf("}\n");

  uint8_t signature[64] = { 0 };
  status = atcab_sign(0, digest, signature);
  printf("Signature of digest is: {R:");
  for (int i=0; i<32; i++)
    printf("%02x", signature[i]);
  printf(", S:");
  for (int i=0; i<32; i++)
    printf("%02x", signature[32+i]);
  printf("}\n");

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
