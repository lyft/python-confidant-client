## 2.1.0

* Added a new timeout option, for being able to configure request timeouts.

## 2.0.0

* Added support for certificate endpoints.
* Added support for getting and listing CAs from the CA endpoints.
* Updated the revert support to use the new revert endpoints in the backend. This support no longer requires fetching and passing in the full objects, but instead passes in the object ID, and the revision to revert to, making it possible to limit ACLs to the client to be able to revert without needing to access the decrypted secrets.

## 1.7.0

* Add a configuration option for being able to disable ssl cert validation.

## 1.6.0

* Require newer boto3 and remove pyopenssl workaround
* Only depend on pyopenssl, ndg-httpsclient, pyasn1 in python2.7

## 1.5.5

* add credential pair to credential id mapping

## 1.5.4

* export metadata in 'combined' output format

## 1.5.3

* update metadata response format handling

## 1.5.2

* fixup for release tag

## 1.5.1

* support custom environment variable prefixes

## 1.5.0

* add credential revert functionality

## 1.4.0

* python3 compat
* changed dependency of kmsauth to >=0.3.0
