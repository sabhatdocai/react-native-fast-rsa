import { NativeModules } from "react-native";

const { RNFastRsa } = NativeModules;

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export type RSAHash  = 'md5' | 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512' 
export type RSABits  = 512 | 1024 | 2048 | 4096

export default class RSA {
  static decryptOAEP(
    message: string,
    label: string,
    hashName: RSAHash,
    pkcs12: string,
  ): Promise<string> {
    return RNFastRsa.decryptOAEP(message, label,hashName,pkcs12);
  }
  static decryptPKCS1v15(
    message: string,
    pkcs12: string,
  ): Promise<string> {
    return RNFastRsa.decryptPKCS1v15(message, pkcs12);
  }
  static encryptOAEP(message: string,label: string, hashName: RSAHash, publicKey: string): Promise<string> {
    return RNFastRsa.encryptOAEP(message,label,hashName, publicKey);
  }
  static encryptPKCS1v15(message: string, pkcs12: string): Promise<string> {
    return RNFastRsa.encryptPKCS1v15(message, pkcs12);
  }
  static signPSS(
    message: string,
    hashName: RSAHash,
    pkcs12: string,
  ): Promise<string> {
    return RNFastRsa.signPSS(message, hashName, pkcs12);
  }
  static signPKCS1v15(
    message: string,
    hashName: RSAHash,
    pkcs12: string,
  ): Promise<string> {
    return RNFastRsa.signPKCS1v15(message, hashName, pkcs12);
  }
  static verifyPSS(
    signature: string,
    message: string,
    hashName: RSAHash,
    pkcs12: string,
  ): Promise<boolean> {
    return RNFastRsa.verifyPSS(signature, message, hashName, pkcs12);
  }
  static verifyPKCS1v15(
    signature: string,
    message: string,
    hashName: RSAHash,
    pkcs12: string,
  ): Promise<boolean> {
    return RNFastRsa.verifyPKCS1v15(signature, message, hashName, pkcs12);
  }

  static hash(
    message: string,
    name: RSAHash
  ): Promise<string> {
    return RNFastRsa.hash(message, name);
  }

  static base64(
    message: string
  ): Promise<string> {
    return RNFastRsa.base64(message);
  }

  static generate(bits: RSABits): Promise<KeyPair> {
    return RNFastRsa.generate(bits);
  }
}
