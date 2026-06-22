//go:build !(goexperiment.simd && amd64)

// simd_stub.go — the pure-Go fallback for every build without the SIMD batch
// path (the default: GOEXPERIMENT=simd off, or any non-amd64 target). It keeps
// Cipher.EncryptBlocks compiling and correct everywhere: the bulk path handles
// no blocks, so EncryptBlocks falls through entirely to per-block Encrypt.
package kuznyechik

func simdBulkEncrypt(c *Cipher, dst, src []byte) int { return 0 }
