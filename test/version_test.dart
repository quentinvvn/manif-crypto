import 'package:manif_crypto/manif_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('le format cryptographique démarre en version 1', () {
    expect(formatVersion, 1);
  });
}
