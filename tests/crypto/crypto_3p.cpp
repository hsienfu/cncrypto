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
  public_key alice_pk_A, alice_pk_B;
  secret_key alice_sk_A, alice_sk_B;
  generate_keys(alice_pk_A, alice_sk_A);
  generate_keys(alice_pk_B, alice_sk_B);

  // Bob Keypairs
  public_key bob_pk_A, bob_pk_B;
  secret_key bob_sk_A, bob_sk_B;
  generate_keys(bob_pk_A, bob_sk_A);
  generate_keys(bob_pk_B, bob_sk_B);

  // `Alice`选择随机数`r`, R = r * G
  secret_key r;
  public_key R;
  random_scalar(r);
  secret_key_to_public_key(r, R);

  // `Alice`计算`Bob`一次性公钥
  public_key P1;
  key_derivation d1;
  generate_key_derivation(bob_pk_A, r, d1);
  derive_public_key(d1, output_index, bob_pk_B, P1); 

  cout << "P1 = " << P1 << endl;

  // `Bob`计算自己的一次性公钥
  public_key P2;
  secret_key S2;
  key_derivation d2;
  generate_key_derivation(R, bob_sk_A, d2);
  derive_secret_key(d2, output_index, bob_sk_B, S2); 
  secret_key_to_public_key(S2, P2);
  cout << "S2 = " << S2 << endl;
  cout << "P2 = " << P2 << endl;

  return error ? 1 : 0;
  CATCH_ENTRY_L0("crypto-3p", 1);
}
