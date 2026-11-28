// Public test fixtures generated for fixture.example.com. The second key belongs to a different pair.
pub(super) const TLS_CERTIFICATE_DER: &str = concat!(
    "MIIBsjCCAVmgAwIBAgIUTJD2F7C8t8BA5VYR1U9z+swgqxAwCgYIKoZIzj0EAwIw\n",
    "HjEcMBoGA1UEAwwTZml4dHVyZS5leGFtcGxlLmNvbTAgFw0yNjExMjEyMzA1NTFa\n",
    "GA8yMTI2MTAyODIzMDU1MVowHjEcMBoGA1UEAwwTZml4dHVyZS5leGFtcGxlLmNv\n",
    "bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD08KAugNhNse/JFC9PS0VfW1T7J\n",
    "7kScLV5hs483qj/sBSeSTQaKZGaoS4vry2wH8Vr+s4YkHazRT8jfPJ2aCBOjczBx\n",
    "MB0GA1UdDgQWBBSKOUk+b8bNZe1cdu+FDylvFuLzXjAfBgNVHSMEGDAWgBSKOUk+\n",
    "b8bNZe1cdu+FDylvFuLzXjAPBgNVHRMBAf8EBTADAQH/MB4GA1UdEQQXMBWCE2Zp\n",
    "eHR1cmUuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDRwAwRAIgB7AuFkTtKxYS1E5T\n",
    "SpucDbTAKSYh5GfoYKwIpSjk8rcCIBaDD/11xFHbGCjCLXw/FheA7ZsM2M5cYoEi\n",
    "JFkKlCQk\n",
);
pub(super) const TLS_KEY_DER: &str = concat!(
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqyy87AfCmCa+KxoD\n",
    "wxuKMb3YzQ1ueR1JlTY9jni4pTahRANCAAQ9PCgLoDYTbHvyRQvT0tFX1tU+ye5E\n",
    "nC1eYbOPN6o/7AUnkk0GimRmqEuL68tsB/Fa/rOGJB2s0U/I3zydmggT\n",
);
pub(super) fn pem(label: &str, encoded_der: &str) -> String {
    format!("-----BEGIN {label}-----\n{encoded_der}-----END {label}-----")
}
