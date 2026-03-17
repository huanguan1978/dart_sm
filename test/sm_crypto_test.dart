import 'dart:io';
import 'package:dart_sm/src/sm2.dart';
import 'package:dart_sm/src/sm3.dart';
import 'package:dart_sm/src/sm4.dart';
import 'package:test/test.dart';

void main() async {
  // ignore: unused_local_variable
  var data = "await readJsonFile('test/data.json')";
  group('SM2', () {
    const data = '12345';
    final keypair = SM2.generateKeyPair();
    String privateKey = keypair.privateKey; // private key
    String publicKey = keypair.publicKey; // public key

    test('encryption and decryption', () {
      String encryptData = SM2.encrypt(data, publicKey);
      String decryptData = SM2.decrypt(encryptData, privateKey);
      expect(decryptData, data);
    });

    test('public key compression', () {
      String compressedPublicKey = SM2.compressPublicKey(publicKey);
      expect(compressedPublicKey.length, 66);
      bool isEqual = SM2.comparePublicKey(compressedPublicKey, publicKey);
      expect(isEqual, true);
      bool isValid = SM2.verifyPublicKey(compressedPublicKey);
      expect(isValid, true);
    });

    test('signature', () {
      String sigValue = SM2.signature(data, privateKey);
      bool verifyValue = SM2.verifySignature(data, sigValue, publicKey);
      expect(verifyValue, true);
    });

    test('signature (without public key derivation)', () {
      String sigValue = SM2.signature(data, privateKey, publicKey: publicKey);
      bool verifyValue = SM2.verifySignature(data, sigValue, publicKey);
      expect(verifyValue, true);
    });

    test('signature with SM3 hash', () {
      String sigValue = SM2.signature(data, privateKey,
          publicKey: publicKey, hash: true, userId: 'userId');
      bool verifyValue =
          SM2.verifySignature(data, sigValue, publicKey, hash: true);
      // not adding userId will cause verification failure
      expect(verifyValue, false);
    });

    test('sign', () {
      // add userId
      String sigValue = SM2.signature(data, privateKey,
          publicKey: publicKey, hash: true, userId: 'userId');
      bool verifyValue = SM2.verifySignature(data, sigValue, publicKey,
          hash: true, userId: 'userId');
      expect(verifyValue, true);
    });

    test('sign', () {
      // ASN1 der encoding/decoding
      String sigValue =
          SM2.signature(data, privateKey, publicKey: publicKey, der: true);
      bool verifyValue =
          SM2.verifySignature(data, sigValue, publicKey, der: true);
      expect(verifyValue, true);
    });
  });

  group('SM3', () {
    const data = '12345';
    test('hash', () {
      String hash = SM3.hash(data);
      expect(hash,
          '91a7adde5b0919d53ffb7dc7253f9f345c3c902a759fe5a2493c70abb7e25095');
    });

    test('hmac', () {
      String hash = SM3.hash(data, key: '95cb90ad5ba0c7c0e2a556f0072626b3');
      expect(hash,
          '9bcfb49d6da4291d7cba18cb445f32f505b23363a150174b1b9ca7192fb7327a');
    });
  });

  group('SM4 Encryption and Decryption', () {
    const data = '12345';
    SM4.setKey('0123456789abcdeffedcba9876543210');

    test('ecb', () {
      String encryptData = SM4.encrypt(data);
      String decryptData = SM4.decrypt(encryptData);
      expect(decryptData, data);
    });

    test('cbc', () {
      String encryptData = SM4.encrypt(data,
          mode: SM4CryptoMode.CBC, iv: 'fedcba98765432100123456789abcdef');
      String decryptData = SM4.decrypt(encryptData,
          mode: SM4CryptoMode.CBC, iv: 'fedcba98765432100123456789abcdef');
      expect(decryptData, data);
    });
  });
}

Future<String> readJsonFile(String filePath) async {
  try {
    final file = File(filePath);
    final fileContents = await file.readAsString();
    return fileContents;
  } catch (e) {
    print('Error reading JSON file: $e');
    return '';
  }
}
