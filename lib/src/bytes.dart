import 'dart:math';
import 'dart:typed_data';

final Random _random = Random.secure();

/// Octets aléatoires issus du générateur cryptographique du système.
Uint8List randomBytes(int length) {
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = _random.nextInt(256);
  }
  return out;
}

/// Compare deux suites d'octets en temps constant (pour une longueur donnée),
/// afin de ne pas révéler par la durée à quel octet elles diffèrent.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
