#include <cstddef>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "warnings.h"
#include "misc_log_ex.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto-tests.h"

using namespace std;
using namespace crypto;
typedef crypto::hash chash;

bool operator !=(const ec_scalar &a, const ec_scalar &b) {
  return 0 != memcmp(&a, &b, sizeof(ec_scalar));
}

bool operator !=(const ec_point &a, const ec_point &b) {
  return 0 != memcmp(&a, &b, sizeof(ec_point));
}

bool operator !=(const key_derivation &a, const key_derivation &b) {
  return 0 != memcmp(&a, &b, sizeof(key_derivation));
}

DISABLE_GCC_WARNING(maybe-uninitialized)

int main(int argc, char *argv[]) {
  TRY_ENTRY();
  size_t output_index;
  bool error = false;
  setup_random();

  // Alice Keypairs
  public_key A1, B1;
  secret_key a1, b1;
  generate_keys(A1, a1);
  generate_keys(B1, b1);

  // Bob Keypairs
  public_key A2, B2;
  secret_key a2, b2;
  generate_keys(A2, a2);
  generate_keys(B2, b2);

  // Regulator Keypairs
  public_key A3, B3;
  secret_key a3, b3;
  generate_keys(A3, a3);
  generate_keys(B3, b3);

  // `Alice`选择随机数`r`, R = r * G
  secret_key r1, r2;
  public_key R;
  char data[sizeof(secret_key) + sizeof(key_derivation)];
  key_derivation a1A2, r2A3;

  // r1
  random_scalar(r1);

  // r2
  generate_key_derivation(A2, a1, a1A2);
  memcpy(data, &r1, sizeof(secret_key));
  memcpy(data + sizeof(secret_key), &a1A2, sizeof(key_derivation));
  crypto::hash_to_scalar(data, sizeof(data), r2);

  // R
  secret_key_to_public_key(r2, R);

  // `Alice`计算`Bob`一次性公钥
  // pk = r3 * G + R + B2
  public_key expected;
  generate_key_derivation(A3, r2, r2A3);
  derive_public_key2(r2A3, output_index, R, B2, expected);

  // `Bob`计算`Bob`一次性公钥
  public_key actual1;
  secret_key sk_1time;
  key_derivation a2A1;

  // r2'
  generate_key_derivation(A1, a2, a2A1);
  memcpy(data, &r1, sizeof(secret_key));
  memcpy(data + sizeof(secret_key), &a2A1, sizeof(key_derivation));
  crypto::hash_to_scalar(data, sizeof(data), r2);

  // r3 = r2 * A3
  generate_key_derivation(A3, r2, r2A3);
  derive_secret_key2(r2A3, output_index, r2, b2, sk_1time);

  // pk1time = (r3 + r2' + b2) * G
  secret_key_to_public_key(sk_1time, actual1);

  // `Regulator`计算`Bob`长期公钥
  public_key actual2;
  key_derivation a3R;

  // r3 = a3 * R
  generate_key_derivation(R, a3, a3R);
  derive_subaddress_public_key2(expected, a3R, R, output_index, actual2);

  if (expected != actual1) {
    cerr << "Wrong PK onetime result: " << endl;
    cerr << "               expected: " << expected << endl;
    cerr << "                 actual: " << actual1 << endl;
    error = true;
  }

  if (B2 != actual2) {
    cerr << "Wrong Subaddress result: " << endl;
    cerr << "               expected: " << B2 << endl;
    cerr << "                 actual: " << actual2 << endl;
    error = true;
  }

  return error ? 1 : 0;
  CATCH_ENTRY_L0("crypto-3p", 1);
}
