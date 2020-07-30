# pam-keycloak
PAM module for authenticating against Keycloak

# Installation
1. Install libpam-python
1. Fetch source
1. Create virtualenv
1. Install requirements
1. Add to pam.d

# Keycloak configuration
Create new OpenID Connect client. Add client ID and secret to config file.

## With OTP enabled
First need new authentication flow to allow OTP to be bypassed
Clone the direct flow grant as 'direct flow no OTP' and disable OTP

Secondly create new client of type OpenID Connect with access type confidential
In authentication flow overrides, set direct grant flow to the new direct grant flow
created earlier

# Test
use pamtester
