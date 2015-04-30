The JAASmine product is based in Java and implements functionality of Java Authentication and Authorization Services (JAAS), and applies JAAS to common scenarios.

We created the JAASmine product with three initial goals in mind:

  1. Create a login module that will a collect a principal and password from a user, authenticate that user against Kerberos, and save the Subject (with Kerberos Ticket) for later use.
  1. Create a client module that will extract a Kerberos Ticket from the Subject (perhaps provided by the above login module), use that ticket to generate an opaque credential in the form of a GSS-API SPNego Token, and ultimately negotiate authentication with a GSS-API compatible server module.
  1. Create a server module that will require GSS-API negotiated authentication and validate SPNego Tokens from incoming requests.

As a result, some other utilities, helper classes, and variations of the above were developed to help smooth the rough edges, facilitate quick integration, and provide reference implementations.  The combination of all these things produce a solid framework for authenticating web applications and web services using industry standard tools and techniques.

In the near future, we'd like to extend this library to accept delegated credentials, perhaps from a workstation authentication to Kerberos.