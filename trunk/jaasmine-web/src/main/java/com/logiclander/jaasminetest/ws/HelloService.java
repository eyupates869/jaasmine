/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.logiclander.jaasminetest.ws;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

/**
 */
@Path("/{var}/helloworld")
public class HelloService {

    private static final String MESSAGE = "hello world";

    private String currentMessage;

    private EntityTag eTag;

    public HelloService() {
        System.out.println("Instantiating");
        try {

            currentMessage = MESSAGE;
            eTag = EntityTagGenerator.generate(currentMessage);

        } catch (NoSuchAlgorithmException ex) {

            throw new RuntimeException(ex);

        } catch (UnsupportedEncodingException ex) {

            throw new RuntimeException(ex);
        }
    }

    @GET
    @Produces("text/plain")
    public Response getMessage(@HeaderParam("If-None-Match") String ifNoneMatch)
        throws NoSuchAlgorithmException, UnsupportedEncodingException {

        ResponseBuilder rb = null;
        if (ifNoneMatch == null || !ifNoneMatch.equals("\"" + eTag.getValue() + "\"")) {

            rb = Response.ok()
                .tag(eTag)
                .entity(new GenericEntity<String>(currentMessage) {});

        } else {

            rb = Response.notModified(eTag);

        }

        return rb.build();
    }


    @PUT
    public Response updateMessage(@Context Request request,
        @FormParam("m") String newMessage)
        throws UnsupportedEncodingException, NoSuchAlgorithmException {

        ResponseBuilder rb = request.evaluatePreconditions(eTag);

        if (rb == null) {

            currentMessage = newMessage;
            eTag = EntityTagGenerator.generate(currentMessage);
            rb = Response.noContent().tag(eTag);

        }

        return rb.build();

    }
}
