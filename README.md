# cert-checker
Have a large number of certificates you need to check? This script will help you do the analysis. 

# Usage
1. Put all of the certificates you need to check in a single folder. It is often useful to seperate different types of certificates into seperate folders.
2. Ensure you have openssl installed
3. Run as follows:
```./cert-checker.sh /path/to/certificate/folder```

The output will be a CSV file with the following column headings:
* FileName
* Issuer
* Subject
* Valid From
* Valid To
* Key Usage
* Signature Algorithm
* Signature Secure?
* Key Strength
* SHA-256 Fingerprint
* SHA-1 Fingerprint
* SANs
* Revocation Info
* CRL Present
* OCSP URL
* Certificate Policies
* Basic Constraints
* Is CA?
* SCTs Present
* Key Pair Match
