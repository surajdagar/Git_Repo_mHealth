#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <inttypes.h>

#define MBED_DOMAIN "3b01e485-d6f1-4625-9700-5e454ba81dd9"
#define MBED_ENDPOINT_NAME "a857e549-04e4-401c-ae6e-1f250d349d93"

const uint8_t SERVER_CERT[] = "-----BEGIN CERTIFICATE-----\r\n"
"MIIBmDCCAT6gAwIBAgIEVUCA0jAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJGSTEN\r\n"
"MAsGA1UEBwwET3VsdTEMMAoGA1UECgwDQVJNMQwwCgYDVQQLDANJb1QxETAPBgNV\r\n"
"BAMMCEFSTSBtYmVkMB4XDTE1MDQyOTA2NTc0OFoXDTE4MDQyOTA2NTc0OFowSzEL\r\n"
"MAkGA1UEBhMCRkkxDTALBgNVBAcMBE91bHUxDDAKBgNVBAoMA0FSTTEMMAoGA1UE\r\n"
"CwwDSW9UMREwDwYDVQQDDAhBUk0gbWJlZDBZMBMGByqGSM49AgEGCCqGSM49AwEH\r\n"
"A0IABLuAyLSk0mA3awgFR5mw2RHth47tRUO44q/RdzFZnLsAsd18Esxd5LCpcT9w\r\n"
"0tvNfBv4xJxGw0wcYrPDDb8/rjujEDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0E\r\n"
"AwIDSAAwRQIhAPAonEAkwixlJiyYRQQWpXtkMZax+VlEiS201BG0PpAzAiBh2RsD\r\n"
"NxLKWwf4O7D6JasGBYf9+ZLwl0iaRjTjytO+Kw==\r\n"
"-----END CERTIFICATE-----\r\n";

const uint8_t CERT[] = "-----BEGIN CERTIFICATE-----\r\n"
"MIIBzjCCAXOgAwIBAgIEWI6NKzAMBggqhkjOPQQDAgUAMDkxCzAJBgNVBAYTAkZ\r\n"
"JMQwwCgYDVQQKDANBUk0xHDAaBgNVBAMME21iZWQtY29ubmVjdG9yLTIwMTgwHh\r\n"
"cNMTcwMzI4MTkxMDI0WhcNMTgxMjMxMDYwMDAwWjCBoTFSMFAGA1UEAxNJM2IwM\r\n"
"WU0ODUtZDZmMS00NjI1LTk3MDAtNWU0NTRiYTgxZGQ5L2E4NTdlNTQ5LTA0ZTQt\r\n"
"NDAxYy1hZTZlLTFmMjUwZDM0OWQ5MzEMMAoGA1UECxMDQVJNMRIwEAYDVQQKEwl\r\n"
"tYmVkIHVzZXIxDTALBgNVBAcTBE91bHUxDTALBgNVBAgTBE91bHUxCzAJBgNVBA\r\n"
"YTAkZJMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE02FXIw0W/d8P91BFQDmqj\r\n"
"bBs1UxNzcUBFwMERgIoyZelp6oxxPGm8ye2vUMGKB7iXrR/FsWbGLrqDRb5i9jC\r\n"
"ijAMBggqhkjOPQQDAgUAA0cAMEQCIFXPsxotnXPaJTqvkkueA9HEm1tTpyzIXdW\r\n"
"Sm+pBMedrAiBOd8g2MkA/QT4PTrrRkWZdCF6UWvBb9yeRj3Pq+0hWAA==\r\n"
"-----END CERTIFICATE-----\r\n";

const uint8_t KEY[] = "-----BEGIN PRIVATE KEY-----\r\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghgmUk9r9USstLFg9\r\n"
"YDzH1M8nfHoe8ao2PjCemCDZsvGhRANCAATTYVcjDRb93w/3UEVAOaqNsGzVTE3N\r\n"
"xQEXAwRGAijJl6WnqjHE8abzJ7a9QwYoHuJetH8WxZsYuuoNFvmL2MKK\r\n"
"-----END PRIVATE KEY-----\r\n";

#endif //__SECURITY_H__