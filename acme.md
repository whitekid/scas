# ACME: Automated Certificated Management Environment

## Procedure

- Create account
  - generate asymetric key pair
  - request a new account with contact informations
  - agreeing to term of service
  - associating the account with an existing account
  - request is signed with generated private key  
- submit an order for certficiate to be issued
- prove control of any identifiers requested in the certificate
- finalize the order by sumitting a CSR
- await issuance and download the issued certificate

## misc

- charset encoding: utf-8
- jws(json web signature)

## References

- <https://www.rfc-editor.org/rfc/rfc8555>
