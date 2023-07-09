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
  if (argc != 2) {
    cerr << "invalid arguments" << endl;
    return 1;
  }
  size_t n = atoi(argv[1]);
  size_t i = 0;

  TRY_ENTRY();
  double t0, t1, t2;
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

  // 计时开始
  t0 = get_time();

  secret_key r;
  public_key R;
  public_key expected;
  key_derivation d1;

  for (; i < n; i++) {
    // `Alice`选择随机数`r`, R = r * G
    random_scalar(r);
    secret_key_to_public_key(r, R);

    // `Alice`计算`Bob`一次性公钥
    generate_key_derivation(A2, r, d1);
    derive_public_key(d1, output_index, B2, expected); 
  }

  // 计时结束
  t1 = get_time();
  cout << "Alice derive PKonetime elapsed: " << (t1 - t0) << endl;

  // `Bob`计算`Bob`一次性公钥
  public_key actual;
  secret_key sk_1time;
  key_derivation d2;

  for (i = 0; i < n; i++) {
    generate_key_derivation(R, a2, d2);
    derive_secret_key(d2, output_index, b2, sk_1time); 
    secret_key_to_public_key(sk_1time, actual);
  }

  // 计时结束
  t2 = get_time();
  cout << "  Bob derive PKonetime elapsed: " << (t2 - t1) << endl;

  if (expected != actual) {
    cerr << "Wrong result: " << endl;
    cerr << "    expected: " << expected << endl;
    cerr << "      actual: " << actual << endl;
    error = true;
  }

  return error ? 1 : 0;
  CATCH_ENTRY_L0("crypto-2p", 1);
}
