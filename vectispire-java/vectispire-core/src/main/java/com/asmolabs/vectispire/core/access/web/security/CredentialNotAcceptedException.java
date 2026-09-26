package com.asmolabs.vectispire.core.access.web.security;

/** A credential presented on a route that does not accept it, or without the scope it needs. */
public class CredentialNotAcceptedException extends RuntimeException {

    public CredentialNotAcceptedException(String message) {
        super(message);
    }
}
